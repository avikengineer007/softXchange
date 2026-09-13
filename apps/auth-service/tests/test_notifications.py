import sys
import uuid
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Ensure apps/auth-service is on sys.path
SERVICE_ROOT = Path(__file__).resolve().parent.parent
if str(SERVICE_ROOT) in sys.path:
    sys.path.remove(str(SERVICE_ROOT))
sys.path.insert(0, str(SERVICE_ROOT))
if "src" in sys.modules and not getattr(sys.modules["src"], "__file__", "").startswith(str(SERVICE_ROOT)):
    sys.modules.pop("src", None)
    for k in list(sys.modules.keys()):
        if k.startswith("src."):
            sys.modules.pop(k, None)

from src.main import app
from src.config import settings
from src.database import Base, get_db
from src.models.user import User, utc_now
from src.models.notification import (
    Notification,
    NotificationType,
    ALL_NOTIFICATION_TYPES,
)
from src.security import create_access_token, hash_password
from src.kyc.service import update_seller_kyc_status

# In-memory SQLite for test isolation
TEST_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_database():
    app.dependency_overrides[get_db] = override_get_db
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)
    app.dependency_overrides.pop(get_db, None)


def _create_test_user(email: str = "test@example.com", roles=None) -> User:
    db = TestingSessionLocal()
    user = User(
        id=str(uuid.uuid4()),
        email=email,
        password_hash=hash_password("Password123!"),
        roles=roles or ["customer"],
        email_verified=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    db.close()
    return user


def _auth_headers(user: User) -> dict:
    token = create_access_token(user_id=user.id, roles=user.roles)
    return {"Authorization": f"Bearer {token}"}


def test_emit_notification_access_control():
    user = _create_test_user()

    # 1. Reject without header
    res = client.post(
        "/notifications/emit",
        json={"user_id": user.id, "type": "scan_passed", "payload": {}},
    )
    assert res.status_code == 401

    # 2. Reject with wrong secret
    res = client.post(
        "/notifications/emit",
        headers={"X-Internal-Secret": "wrong-secret"},
        json={"user_id": user.id, "type": "scan_passed", "payload": {}},
    )
    assert res.status_code == 401

    # 3. Reject non-existent user
    res = client.post(
        "/notifications/emit",
        headers={"X-Internal-Secret": settings.INTERNAL_SERVICE_SECRET},
        json={"user_id": "non-existent-user-id", "type": "scan_passed", "payload": {}},
    )
    assert res.status_code == 404

    # 4. Reject invalid notification type
    res = client.post(
        "/notifications/emit",
        headers={"X-Internal-Secret": settings.INTERNAL_SERVICE_SECRET},
        json={"user_id": user.id, "type": "unknown_future_event", "payload": {}},
    )
    assert res.status_code == 422


def test_all_notification_types_emit_properly():
    """
    Explicitly tests that all notification types emit properly,
    including kyc_rejected, kyc_verified, scan_passed, scan_failed,
    order_paid, question_asked, question_answered, listing_review_received,
    github_connected, and github_disconnected.
    """
    user = _create_test_user()
    secret_headers = {"X-Internal-Secret": settings.INTERNAL_SERVICE_SECRET}

    all_expected_types = [
        "scan_passed",
        "scan_failed",
        "order_paid",
        "question_asked",
        "question_answered",
        "kyc_verified",
        "kyc_rejected",
        "listing_review_received",
        "github_connected",
        "github_disconnected",
    ]

    # Verify that the model enum covers all expected types
    assert set(all_expected_types) == ALL_NOTIFICATION_TYPES

    for notif_type in all_expected_types:
        payload = {"sample_key": f"value_for_{notif_type}"}
        res = client.post(
            "/notifications/emit",
            headers=secret_headers,
            json={"user_id": user.id, "type": notif_type, "payload": payload},
        )
        assert res.status_code == 201, f"Failed to emit notification type: {notif_type}"
        data = res.json()
        assert data["type"] == notif_type
        assert data["user_id"] == user.id
        assert data["payload"]["sample_key"] == f"value_for_{notif_type}"
        assert data["read_at"] is None

    # Check that unread count is exactly total emitted
    res = client.get("/notifications/unread-count", headers=_auth_headers(user))
    assert res.status_code == 200
    assert res.json()["unread_count"] == len(all_expected_types)


def test_get_notifications_pagination_and_unread_filter():
    user = _create_test_user()
    secret_headers = {"X-Internal-Secret": settings.INTERNAL_SERVICE_SECRET}

    # Emit 5 notifications
    for i in range(5):
        client.post(
            "/notifications/emit",
            headers=secret_headers,
            json={"user_id": user.id, "type": "scan_passed", "payload": {"index": i}},
        )

    auth = _auth_headers(user)

    # 1. Limit 2
    res = client.get("/notifications?limit=2&offset=0", headers=auth)
    assert res.status_code == 200
    data = res.json()
    assert len(data["notifications"]) == 2
    assert data["total"] == 5
    assert data["unread_count"] == 5

    # 2. Mark one as read
    first_id = data["notifications"][0]["id"]
    client.post(f"/notifications/{first_id}/read", headers=auth)

    # 3. unread_only=true
    res_unread = client.get("/notifications?unread_only=true", headers=auth)
    assert res_unread.status_code == 200
    unread_data = res_unread.json()
    assert unread_data["total"] == 4
    assert unread_data["unread_count"] == 4
    assert all(n["read_at"] is None for n in unread_data["notifications"])


def test_mark_single_and_all_read():
    user1 = _create_test_user(email="u1@example.com")
    user2 = _create_test_user(email="u2@example.com")
    secret_headers = {"X-Internal-Secret": settings.INTERNAL_SERVICE_SECRET}

    # Emit for user1 and user2
    r1 = client.post(
        "/notifications/emit",
        headers=secret_headers,
        json={"user_id": user1.id, "type": "scan_passed", "payload": {}},
    )
    n1_id = r1.json()["id"]

    r2 = client.post(
        "/notifications/emit",
        headers=secret_headers,
        json={"user_id": user2.id, "type": "order_paid", "payload": {}},
    )
    n2_id = r2.json()["id"]

    # user2 cannot read user1's notification (404)
    res = client.post(f"/notifications/{n1_id}/read", headers=_auth_headers(user2))
    assert res.status_code == 404

    # user1 reads own notification
    res = client.post(f"/notifications/{n1_id}/read", headers=_auth_headers(user1))
    assert res.status_code == 200
    assert res.json()["read_at"] is not None

    # Emit 2 more for user2
    client.post(
        "/notifications/emit",
        headers=secret_headers,
        json={"user_id": user2.id, "type": "question_asked", "payload": {}},
    )
    client.post(
        "/notifications/emit",
        headers=secret_headers,
        json={"user_id": user2.id, "type": "kyc_rejected", "payload": {}},
    )

    count_res = client.get("/notifications/unread-count", headers=_auth_headers(user2))
    assert count_res.json()["unread_count"] == 3

    # read-all for user2
    read_all_res = client.post("/notifications/read-all", headers=_auth_headers(user2))
    assert read_all_res.status_code == 200
    assert read_all_res.json()["updated"] == 3

    count_res2 = client.get("/notifications/unread-count", headers=_auth_headers(user2))
    assert count_res2.json()["unread_count"] == 0


def test_kyc_status_transition_emits_notifications():
    """
    Confirms that update_seller_kyc_status automatically records:
    - kyc_verified when status is verified
    - kyc_rejected when status is rejected
    """
    seller = _create_test_user(email="seller@example.com", roles=["seller"])
    db = TestingSessionLocal()

    # 1. Transition to verified
    update_seller_kyc_status(user_id=seller.id, target_status="verified", db=db)

    # Check notification exists for seller
    notif_verified = (
        db.query(Notification)
        .filter(Notification.user_id == seller.id, Notification.type == NotificationType.KYC_VERIFIED.value)
        .first()
    )
    assert notif_verified is not None
    assert notif_verified.payload["status"] == "verified"

    # 2. Transition to rejected
    update_seller_kyc_status(user_id=seller.id, target_status="rejected", db=db)

    notif_rejected = (
        db.query(Notification)
        .filter(Notification.user_id == seller.id, Notification.type == NotificationType.KYC_REJECTED.value)
        .first()
    )
    assert notif_rejected is not None
    assert notif_rejected.payload["status"] == "rejected"

    db.close()
