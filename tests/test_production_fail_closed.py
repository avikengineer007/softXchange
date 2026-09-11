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
4. Stripe webhook signature verification fails closed with 400 Bad Request on invalid signatures.
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


def test_auth_service_refuses_dev_default_admin_code_in_production(monkeypatch):
    """auth-service lifespan must raise RuntimeError when ADMIN_PROVISIONING_CODE is the known dev default."""
    _clean_src_modules()
    sys.path = [p for p in sys.path if "apps" not in p]
    sys.path.insert(0, str(AUTH_ROOT))

    from src.config import settings
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
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
    monkeypatch.setattr(settings, "ADMIN_PROVISIONING_CODE", "short_secret")

    from src.main import app

    with pytest.raises(RuntimeError, match="must be set and have at least 32 characters in production"):
        with TestClient(app):
            pass


def test_payments_service_test_confirm_is_unreachable_in_production(monkeypatch):
    """In production, /orders/{id}/test-confirm is NOT registered in routes and returns 404."""
    _clean_src_modules()
    sys.path = [p for p in sys.path if "apps" not in p]
    sys.path.insert(0, str(PAYMENTS_ROOT))

    from src.config import settings
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")

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


def test_stripe_webhook_rejects_missing_or_invalid_signature(monkeypatch):
    """Stripe webhook endpoint requires authentic Stripe-Signature and valid webhook secret."""
    _clean_src_modules()
    sys.path = [p for p in sys.path if "apps" not in p]
    sys.path.insert(0, str(PAYMENTS_ROOT))

    from src.config import settings
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(settings, "STRIPE_WEBHOOK_SECRET", "whsec_live_real_secret_1234567890")

    from src.main import app

    with TestClient(app) as client:
        # 1. Missing header
        resp_no_header = client.post(
            "/payments/webhooks/stripe",
            json={"type": "payment_intent.succeeded"},
        )
        assert resp_no_header.status_code == 400
        assert "Missing Stripe-Signature" in resp_no_header.json()["detail"]

        # 2. Forged header / invalid signature
        resp_bad_sig = client.post(
            "/payments/webhooks/stripe",
            json={"type": "payment_intent.succeeded"},
            headers={"Stripe-Signature": "t=12345678,v1=forged_signature_hex"},
        )
        assert resp_bad_sig.status_code == 400
        assert "signature verification failed" in resp_bad_sig.json()["detail"].lower()
