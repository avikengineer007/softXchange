"""
ml_shared.client

Integration client and loader helpers to build a canonical ListingContextBundle
by querying listings-service and scan-service over HTTP or via direct service clients.
"""

from __future__ import annotations
import logging
from typing import Optional, List, Dict, Any
import httpx

from ml_shared.context import ListingContextBundle, SellerDocument

logger = logging.getLogger("ml_shared.client")


class ContextBundleClient:
    """
    HTTP client that aggregates data from listings-service and scan-service
    to construct a validated ListingContextBundle without re-deriving findings.
    """

    def __init__(
        self,
        listings_service_url: str = "http://localhost:8003",
        scan_service_url: str = "http://localhost:8002",
        timeout: float = 10.0,
    ):
        self.listings_service_url = listings_service_url.rstrip("/")
        self.scan_service_url = scan_service_url.rstrip("/")
        self.timeout = timeout

    def fetch_bundle(
        self,
        listing_id: str,
        seller_docs: Optional[List[SellerDocument]] = None,
        auth_header: Optional[str] = None,
    ) -> ListingContextBundle:
        """
        Fetches listing details from listings-service and scan status from scan-service,
        combining them into a canonical ListingContextBundle.
        """
        headers = {}
        if auth_header:
            headers["Authorization"] = auth_header

        with httpx.Client(timeout=self.timeout) as client:
            # 1. Fetch listing details
            listing_url = f"{self.listings_service_url}/listings/{listing_id}"
            listing_resp = client.get(listing_url, headers=headers)
            listing_resp.raise_for_status()
            listing_data = listing_resp.json()

            # 2. Fetch scan status if version is present
            scan_data = None
            current_ver = listing_data.get("current_version") or {}
            version_label = current_ver.get("version_label") or listing_data.get("current_version_label") or "1.0.0"

            if version_label:
                scan_url = f"{self.scan_service_url}/status/{listing_id}/{version_label}"
                try:
                    scan_resp = client.get(scan_url)
                    if scan_resp.status_code == 200:
                        scan_data = scan_resp.json()
                except Exception as exc:
                    logger.warning(f"Could not reach scan-service at {scan_url}: {exc}")

        return ListingContextBundle.from_listing_and_scan(
            listing_data=listing_data,
            scan_data=scan_data,
            seller_docs=seller_docs or [],
        )


def build_context_bundle(
    listing_data: Dict[str, Any],
    scan_data: Optional[Dict[str, Any]] = None,
    seller_docs: Optional[List[SellerDocument]] = None,
) -> ListingContextBundle:
    """Convenience functional builder for existing in-memory / test client data dictionaries."""
    return ListingContextBundle.from_listing_and_scan(
        listing_data=listing_data,
        scan_data=scan_data,
        seller_docs=seller_docs or [],
    )
