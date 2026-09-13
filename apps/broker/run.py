import sys
from pathlib import Path

SERVICE_ROOT = Path(__file__).resolve().parent
if str(SERVICE_ROOT) not in sys.path:
    sys.path.insert(0, str(SERVICE_ROOT))

_listings_dir = SERVICE_ROOT.parent / "listings-service"
if _listings_dir.exists() and str(_listings_dir) not in sys.path:
    sys.path.insert(0, str(_listings_dir))

_ml_shared_dir = SERVICE_ROOT.parent.parent / "packages" / "ml-shared" / "src"
if _ml_shared_dir.exists() and str(_ml_shared_dir) not in sys.path:
    sys.path.insert(0, str(_ml_shared_dir))

import uvicorn
from broker.config import settings

if __name__ == "__main__":
    uvicorn.run("broker.main:app", host="0.0.0.0", port=settings.PORT, reload=True)
