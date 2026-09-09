import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

SERVICE_ROOT = Path(__file__).resolve().parent.parent
if str(SERVICE_ROOT) in sys.path:
    sys.path.remove(str(SERVICE_ROOT))
sys.path.insert(0, str(SERVICE_ROOT))
sys.modules.pop("src", None)
for k in list(sys.modules.keys()):
    if k.startswith("src."):
        sys.modules.pop(k, None)

from src.main import app

@pytest.fixture
def client():
    return TestClient(app)

def test_healthz(client):
    res = client.get("/healthz")
    assert res.status_code == 200
    assert res.json()["service"] == "scan-service"

def test_intake_and_status(client):
    # Submit package via json
    res = client.post("/intake", json={
        "listing_id": "test-list-1",
        "version": "1.0.0",
        "source_type": "upload",
        "package_content": "print('hello softXchange')"
    })
    assert res.status_code == 202
    data = res.json()
    job_id = data["scan_job_id"]
    assert job_id is not None

    # Query status by listing and version
    status_res = client.get("/status/test-list-1/1.0.0")
    assert status_res.status_code == 200
    assert status_res.json()["listing_id"] == "test-list-1"

    # Query status by job_id alias
    job_res = client.get(f"/status/job/{job_id}")
    assert job_res.status_code == 200
    assert job_res.json()["listing_id"] == "test-list-1"
