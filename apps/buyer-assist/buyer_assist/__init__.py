"""apps/buyer-assist/buyer_assist/__init__.py"""

import sys
from pathlib import Path

# Ensure listings-service and ml-shared are in sys.path when running locally outside Docker
_listings_dir = Path(__file__).resolve().parent.parent.parent / "listings-service"
if _listings_dir.exists() and str(_listings_dir) not in sys.path:
    sys.path.insert(0, str(_listings_dir))

_ml_shared_dir = Path(__file__).resolve().parent.parent.parent.parent / "packages" / "ml-shared" / "src"
if _ml_shared_dir.exists() and str(_ml_shared_dir) not in sys.path:
    sys.path.insert(0, str(_ml_shared_dir))

from buyer_assist.search import search_listings, SearchResultItem, SearchQueryRequest, SearchQueryResponse

__all__ = [
    "search_listings",
    "SearchResultItem",
    "SearchQueryRequest",
    "SearchQueryResponse",
]
