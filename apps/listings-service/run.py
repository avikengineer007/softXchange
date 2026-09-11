import sys
from pathlib import Path
import uvicorn

SERVICE_ROOT = Path(__file__).resolve().parent
if str(SERVICE_ROOT) not in sys.path:
    sys.path.insert(0, str(SERVICE_ROOT))

if __name__ == "__main__":
    uvicorn.run("src.main:app", host="0.0.0.0", port=8003, reload=True, app_dir=str(SERVICE_ROOT))
