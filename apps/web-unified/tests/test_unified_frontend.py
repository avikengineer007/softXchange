"""
test_unified_frontend.py — Unified Frontend Page Serving Test Suite

Validates that apps/web-unified properly serves:
- /healthz
- All 14 marketplace HTML pages at root URLs (/page.html)
- All 14 marketplace HTML pages at /static/ URLs (/static/page.html)
- Root landing page (/)
- Core CSS and JS static assets

Run: pytest apps/web-unified/tests/test_unified_frontend.py -v
"""
import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

# Ensure apps/web-unified is on sys.path
WEB_UNIFIED_DIR = Path(__file__).resolve().parent.parent
if str(WEB_UNIFIED_DIR) not in sys.path:
    sys.path.insert(0, str(WEB_UNIFIED_DIR))

from run import app, PAGES


@pytest.fixture
def client():
    return TestClient(app)


def test_healthz_endpoint(client):
    """Verify /healthz returns status ok."""
    resp = client.get("/healthz")
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("status") == "ok"
    assert data.get("app") == "web-unified"
    assert data.get("port") == 8000


def test_root_serves_landing_page(client):
    """Verify root GET / serves index.html with HTTP 200."""
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers.get("content-type", "")
    assert "<title>" in resp.text


@pytest.mark.parametrize("page", PAGES)
def test_direct_page_routes_served(client, page):
    """Verify each page is served at /{page} with HTTP 200."""
    resp = client.get(f"/{page}")
    assert resp.status_code == 200, f"GET /{page} failed with status {resp.status_code}"
    assert "text/html" in resp.headers.get("content-type", "")


@pytest.mark.parametrize("page", PAGES)
def test_static_page_routes_served(client, page):
    """Verify each page is served at /static/{page} with HTTP 200 (backward-compat)."""
    resp = client.get(f"/static/{page}")
    assert resp.status_code == 200, f"GET /static/{page} failed with status {resp.status_code}"
    assert "text/html" in resp.headers.get("content-type", "")


def test_static_css_and_js_assets_served(client):
    """Verify core design system CSS and JS modules are served."""
    assets = [
        "/static/css/tokens.css",
        "/static/css/style.css",
        "/static/js/auth.js",
        "/static/js/ambient-layer.js",
        "/static/js/verification-motif.js",
        "/static/js/api-client.js",
    ]
    for asset in assets:
        resp = client.get(asset)
        assert resp.status_code == 200, f"Asset {asset} returned {resp.status_code}"
        assert len(resp.text) > 0
