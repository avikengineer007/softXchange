from typing import Optional, Dict, Any
import logging
import httpx

from src.config import settings

logger = logging.getLogger("listings-service.scanner_client")


class ScannerClient:
    """
    Strict HTTP client communicating with apps/scan-service over the network.
    Preserves microservice isolation without in-process shortcut bypasses.
    """
    def __init__(self, base_url: Optional[str] = None, timeout: float = 10.0):
        self.base_url = (base_url or settings.SCAN_SERVICE_URL).rstrip("/")
        self.timeout = timeout

    def submit_version(
        self,
        listing_id: str,
        version: str,
        source_type: str = "upload",
        git_url: Optional[str] = None,
        package_content: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Calls POST /intake on scan-service.
        Returns job metadata including scan_job_id.
        """
        url = f"{self.base_url}/intake"
        payload = {
            "listing_id": listing_id,
            "version": version,
            "source_type": source_type,
            "git_url": git_url,
            "package_content": package_content,
        }

        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(url, json=payload)
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPError as exc:
            logger.error(f"Failed to submit package to scan-service ({url}): {exc}", exc_info=True)
            raise RuntimeError(f"Scan service intake error: {exc}")

    def query_status(self, listing_id: str, version: str) -> Dict[str, Any]:
        """
        Calls GET /status/{listing_id}/{version} on scan-service.
        Returns collapsed scan status, severity counts, and redacted findings.
        """
        url = f"{self.base_url}/status/{listing_id}/{version}"

        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.get(url)
                if resp.status_code == 404:
                    return {
                        "listing_id": listing_id,
                        "version": version,
                        "scan_status": "pending_scan",
                        "severity_counts": {},
                        "findings": [],
                    }
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPError as exc:
            logger.error(f"Failed to query scan-service status ({url}): {exc}", exc_info=True)
            raise RuntimeError(f"Scan service status query error: {exc}")


# Global default client
scanner_client = ScannerClient()
