import sys
from pathlib import Path

SERVICE_ROOT = Path(__file__).resolve().parent.parent
if str(SERVICE_ROOT) in sys.path:
    sys.path.remove(str(SERVICE_ROOT))
sys.path.insert(0, str(SERVICE_ROOT))

# Purge any foreign src modules
if "src" in sys.modules and not getattr(sys.modules["src"], "__file__", "").startswith(str(SERVICE_ROOT)):
    sys.modules.pop("src", None)
    for k in list(sys.modules.keys()):
        if k.startswith("src."):
            sys.modules.pop(k, None)
