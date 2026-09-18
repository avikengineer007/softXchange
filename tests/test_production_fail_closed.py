"""
tests/test_production_fail_closed.py

Rigorous automated test suite exercising every fail-closed production gate
under real production configuration (ENVIRONMENT=production).

Verifies:
1. auth-service refuses to boot with ephemeral RS256 keys when ENVIRONMENT=production.
2. auth-service refuses to boot when ADMIN_PROVISIONING_CODE matches the known dev default
   or lacks cryptographic entropy.
3. payments-service test-confirm endpoint is genuinely unregistered (returns 404) in production,
   and lifespan fails closed with RuntimeError if registered.
4. Razorpay webhook signature verification fails closed with 400 Bad Request on invalid signatures.
"""

import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parent.parent

# Service root paths
AUTH_ROOT = REPO_ROOT / "apps" / "auth-service"
PAYMENTS_ROOT = REPO_ROOT / "apps" / "payments-service"


def _clean_src_modules():
    for mod in list(sys.modules.keys()):
        if mod == "src" or mod.startswith("src."):
            del sys.modules[mod]


def test_auth_service_refuses_ephemeral_rs256_in_production(monkeypatch):
    """auth-service must raise RuntimeError during key init when ENVIRONMENT=production and no PEM keys exist."""
    _clean_src_modules()
    sys.path = [p for p in sys.path if "apps" not in p]
    sys.path.insert(0, str(AUTH_ROOT))

    import src.config as cfg
    monkeypatch.setattr(cfg.settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(cfg.settings, "JWT_ALGORITHM", "RS256")
    monkeypatch.setattr(cfg.settings, "JWT_PRIVATE_KEY", None)
    monkeypatch.setattr(cfg.settings, "JWT_PUBLIC_KEY", None)
    monkeypatch.setattr(cfg.settings, "JWT_PRIVATE_KEY_PATH", None)
    monkeypatch.setattr(cfg.settings, "JWT_PUBLIC_KEY_PATH", None)

    # Importing security triggers _init_rsa_keys() on load; must fail closed immediately
    with pytest.raises(RuntimeError, match="FATAL: JWT_ALGORITHM is RS256 and ENVIRONMENT is 'production'"):
        import src.security as sec


from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Pre-generate valid test RSA keypair for production lifespan tests
_TEST_RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_TEST_RSA_PRIV_PEM = _TEST_RSA_KEY.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
).decode("utf-8")
_TEST_RSA_PUB_PEM = _TEST_RSA_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode("utf-8")


def _provide_valid_rsa_keys(monkeypatch, settings):
    monkeypatch.setattr(settings, "JWT_ALGORITHM", "RS256")
    monkeypatch.setattr(settings, "JWT_PRIVATE_KEY", _TEST_RSA_PRIV_PEM)
    monkeypatch.setattr(settings, "JWT_PUBLIC_KEY", _TEST_RSA_PUB_PEM)
    monkeypatch.setattr(settings, "JWT_PRIVATE_KEY_PATH", None)
    monkeypatch.setattr(settings, "JWT_PUBLIC_KEY_PATH", None)


def test_auth_service_refuses_dev_default_admin_code_in_production(monkeypatch):
    """auth-service lifespan must raise RuntimeError when ADMIN_PROVISIONING_CODE is the known dev default."""
    _clean_src_modules()
    sys.path = [p for p in sys.path if "apps" not in p]
    sys.path.insert(0, str(AUTH_ROOT))

    from src.config import settings
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    _provide_valid_rsa_keys(monkeypatch, settings)
    monkeypatch.setattr(settings, "ADMIN_PROVISIONING_CODE", "sx_admin_sec_9f7a28e4c19d4b8e8f2a1b3c4d5e6f7a")

    from src.main import app

    with pytest.raises(RuntimeError, match="ADMIN_PROVISIONING_CODE is set to the known dev default string"):
        with TestClient(app):
            pass


def test_auth_service_refuses_unrotated_dev_token_in_production(monkeypatch):
    """auth-service lifespan must raise RuntimeError if an unrotated token containing 'dev' is provided."""
    _clean_src_modules()
    sys.path = [p for p in sys.path if "apps" not in p]
    sys.path.insert(0, str(AUTH_ROOT))

    from src.config import settings
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    _provide_valid_rsa_keys(monkeypatch, settings)
    monkeypatch.setattr(settings, "ADMIN_PROVISIONING_CODE", "sx_admin_dev_token_long_enough_32_characters_long")
    monkeypatch.setattr(settings, "ADMIN_CODE_EXPLICITLY_ROTATED", False)

    from src.main import app

    with pytest.raises(RuntimeError, match="appears to be a dev token and has not been explicitly rotated"):
        with TestClient(app):
            pass


def test_auth_service_refuses_low_entropy_admin_code_in_production(monkeypatch):
    """auth-service lifespan must raise RuntimeError when ADMIN_PROVISIONING_CODE is too short."""
    _clean_src_modules()
    sys.path = [p for p in sys.path if "apps" not in p]
    sys.path.insert(0, str(AUTH_ROOT))

    from src.config import settings
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    _provide_valid_rsa_keys(monkeypatch, settings)
    monkeypatch.setattr(settings, "ADMIN_PROVISIONING_CODE", "short_secret")

    from src.main import app

    with pytest.raises(RuntimeError, match="must be set and have at least 32 characters in production"):
        with TestClient(app):
            pass


def _provide_valid_razorpay_creds(monkeypatch, settings):
    monkeypatch.setattr(settings, "RAZORPAY_KEY_ID", "rzp_live_realprod123456")
    monkeypatch.setattr(settings, "RAZORPAY_KEY_SECRET", "sec_live_realproductionsecret123456")
    monkeypatch.setattr(settings, "RAZORPAY_WEBHOOK_SECRET", "whsec_live_realproductionsecret12345")


def test_payments_service_test_confirm_is_unreachable_in_production(monkeypatch):
    """In production, /orders/{id}/test-confirm is NOT registered in routes and returns 404."""
    _clean_src_modules()
    sys.path = [p for p in sys.path if "apps" not in p]
    sys.path.insert(0, str(PAYMENTS_ROOT))

    from src.config import settings
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    _provide_valid_razorpay_creds(monkeypatch, settings)

    from src.main import app

    with TestClient(app) as client:
        # Route is not present -> 404
        resp = client.post("/orders/ord-fake-123/test-confirm")
        assert resp.status_code == 404, f"Expected 404 for test-confirm in production, got {resp.status_code}"


def test_payments_service_lifespan_fails_closed_if_test_confirm_registered(monkeypatch):
    """Lifespan actively scans app.routes and fails closed if test-confirm is ever registered in production."""
    _clean_src_modules()
    sys.path = [p for p in sys.path if "apps" not in p]
    sys.path.insert(0, str(PAYMENTS_ROOT))

    from src.config import settings
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    _provide_valid_razorpay_creds(monkeypatch, settings)

    from src.main import app

    # Deliberately inject a route with test-confirm in its path
    @app.post("/test-confirm-adversarial")
    def adversarial_route():
        return {"status": "bad"}

    try:
        with pytest.raises(RuntimeError, match="SECURITY FATAL: Test-confirm endpoint is registered in production"):
            with TestClient(app):
                pass
    finally:
        # Clean up test route from router
        app.router.routes = [r for r in app.router.routes if getattr(r, "path", None) != "/test-confirm-adversarial"]


def test_payments_service_refuses_mock_razorpay_credentials_in_production(monkeypatch):
    """payments-service lifespan must raise RuntimeError if mock Razorpay credentials are used in production."""
    _clean_src_modules()
    sys.path = [p for p in sys.path if "apps" not in p]
    sys.path.insert(0, str(PAYMENTS_ROOT))

    from src.config import settings
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(settings, "RAZORPAY_KEY_ID", "rzp_test_softxchange_mock_key")
    monkeypatch.setattr(settings, "RAZORPAY_KEY_SECRET", "rzp_test_softxchange_mock_secret")
    monkeypatch.setattr(settings, "RAZORPAY_WEBHOOK_SECRET", "whsec_softxchange_mock_webhook_secret")

    from src.main import app

    with pytest.raises(RuntimeError, match="Mock or dev-default Razorpay credentials detected in production"):
        with TestClient(app):
            pass


def test_razorpay_webhook_rejects_missing_or_invalid_signature(monkeypatch):
    """Razorpay webhook endpoint requires authentic X-Razorpay-Signature and valid webhook secret."""
    _clean_src_modules()
    sys.path = [p for p in sys.path if "apps" not in p]
    sys.path.insert(0, str(PAYMENTS_ROOT))

    from src.config import settings
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    _provide_valid_razorpay_creds(monkeypatch, settings)

    from src.main import app

    with TestClient(app) as client:
        # 1. Missing header
        resp_no_header = client.post(
            "/payments/webhooks/razorpay",
            json={"event": "order.paid"},
        )
        assert resp_no_header.status_code == 400
        assert "Missing X-Razorpay-Signature" in resp_no_header.json()["detail"]

        # 2. Forged header / invalid signature
        resp_bad_sig = client.post(
            "/payments/webhooks/razorpay",
            json={"event": "order.paid"},
            headers={"X-Razorpay-Signature": "forged_signature_hex"},
        )
        assert resp_bad_sig.status_code == 400
        assert "signature verification failed" in resp_bad_sig.json()["detail"].lower()


def test_production_boot_without_migrations_fails_closed(monkeypatch, tmp_path):
    """
    In production (ENVIRONMENT=production), init_db() strictly prohibits auto-creating tables.
    If booted against an unmigrated database, tables are absent and requests fail closed.
    Tables exist only after an explicit migration step.
    """
    _clean_src_modules()
    sys.path = [p for p in sys.path if "apps" not in p]
    sys.path.insert(0, str(AUTH_ROOT))

    db_path = tmp_path / "prod_unmigrated.db"
    db_url = f"sqlite:///{db_path}"

    from src.config import settings
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(settings, "DATABASE_URL", db_url)
    _provide_valid_rsa_keys(monkeypatch, settings)
    monkeypatch.setattr(settings, "ADMIN_PROVISIONING_CODE", "sx_prod_sec_0123456789abcdef0123456789abcdef")
    monkeypatch.setattr(settings, "ADMIN_CODE_EXPLICITLY_ROTATED", True)

    import src.database as db_mod
    monkeypatch.setattr(db_mod.settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(db_mod.settings, "DATABASE_URL", db_url)

    from sqlalchemy import create_engine, inspect
    from sqlalchemy.orm import sessionmaker
    test_engine = create_engine(db_url)
    monkeypatch.setattr(db_mod, "engine", test_engine)
    monkeypatch.setattr(db_mod, "SessionLocal", sessionmaker(bind=test_engine))

    from src.main import app

    # 1. Boot service in production mode without running migrations
    with TestClient(app) as client:
        inspector = inspect(test_engine)
        assert len(inspector.get_table_names()) == 0, "Security violation: init_db() auto-created tables in production!"

        # Query fails closed with 500 (table does not exist)
        resp = client.post("/auth/login", json={"email": "nobody@example.com", "password": "Password123!"})
        assert resp.status_code == 500

    # 2. Explicitly apply migrations (migrate-then-boot)
    monkeypatch.setenv("DATABASE_URL", db_url)
    from alembic import command
    from alembic.config import Config
    cfg = Config(str(AUTH_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(AUTH_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    command.upgrade(cfg, "head")

    inspector_after = inspect(test_engine)
    assert "users" in inspector_after.get_table_names()
    assert "notifications" in inspector_after.get_table_names()
    assert "seller_github_connections" in inspector_after.get_table_names()

    # 3. Boot service after migration: now queries execute properly (401 for unknown user)
    with TestClient(app) as client:
        resp = client.post("/auth/login", json={"email": "nobody@example.com", "password": "Password123!"})
        assert resp.status_code == 401


def test_seed_marketplace_fails_closed_in_production(monkeypatch):
    """seed_marketplace.py must refuse to inject synthetic unscanned listings in production."""
    _clean_src_modules()
    sys.path = [p for p in sys.path if "apps" not in p]
    sys.path.insert(0, str(REPO_ROOT / "apps" / "listings-service"))
    monkeypatch.setenv("ENVIRONMENT", "production")
    if "seed_marketplace" in sys.modules:
        del sys.modules["seed_marketplace"]
    import seed_marketplace

    with pytest.raises(RuntimeError, match="SECURITY FATAL: seed_marketplace.py injects synthetic mock listings"):
        seed_marketplace.seed()


