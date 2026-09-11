"""OSV.dev API client for batch dependency vulnerability querying.

Implements batched vulnerability lookups via the OSV.dev querybatch endpoint:
POST https://api.osv.dev/v1/querybatch

Provides:
  - Batching of multiple dependencies in single HTTP requests.
  - Ecosystem mapping between scanner manifests and OSV ecosystems (npm, PyPI, Go, crates.io).
  - Strict, distinct network failure exception hierarchy (never conflating errors with clean scans).
  - Configurable timeout and retry logic with exponential backoff.
  - Flexible authentication support (optional API key / Bearer token).
"""

import json
import socket
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple, Union

from static_analysis.manifests import DeclaredDependency

# =============================================================================
# Exception Hierarchy
# =============================================================================

class OSVClientError(Exception):
    """Base exception for all OSV API client failures."""
    pass


class OSVTimeoutError(OSVClientError):
    """Raised when an OSV API request times out."""

    def __init__(self, message: str = "OSV API request timed out", timeout: float = 10.0):
        super().__init__(message)
        self.timeout = timeout


class OSVConnectionError(OSVClientError):
    """Raised when a network or socket connection to the OSV API fails."""

    def __init__(self, message: str = "Failed to connect to OSV API", original_error: Optional[Exception] = None):
        super().__init__(message)
        self.original_error = original_error


class OSVHTTPError(OSVClientError):
    """Raised when OSV API returns a non-200 HTTP status code."""

    def __init__(self, status_code: int, response_body: str, message: Optional[str] = None):
        self.status_code = status_code
        self.response_body = response_body
        msg = message or f"OSV API returned HTTP {status_code}: {response_body[:200]}"
        super().__init__(msg)


class OSVResponseError(OSVClientError):
    """Raised when OSV API returns malformed JSON or an unexpected schema."""

    def __init__(self, message: str = "Invalid response format from OSV API"):
        super().__init__(message)


# =============================================================================
# Ecosystem Mapping & Query Serialization
# =============================================================================

# Maps manifest ecosystem identifiers to authoritative OSV.dev ecosystem names
ECOSYSTEM_MAPPING: Dict[str, str] = {
    "npm": "npm",
    "pypi": "PyPI",
    "pip": "PyPI",
    "python": "PyPI",
    "crates": "crates.io",
    "crates.io": "crates.io",
    "rust": "crates.io",
    "golang": "Go",
    "go": "Go",
}


def map_ecosystem_to_osv(ecosystem: str) -> str:
    """Maps internal manifest ecosystem identifier to official OSV ecosystem name."""
    eco_key = ecosystem.strip().lower()
    return ECOSYSTEM_MAPPING.get(eco_key, ecosystem)


def normalize_version_for_osv(version_spec: Optional[str]) -> Optional[str]:
    """Cleans dependency version specifier into a concrete version string for OSV.
    
    Strips comparison operators (==, =, ^, ~) while preserving the core version digits.
    """
    if not version_spec:
        return None
    v = version_spec.strip()
    if v.startswith("=="):
        v = v[2:].strip()
    elif v.startswith("="):
        v = v[1:].strip()
    elif v.startswith(("^", "~")):
        v = v[1:].strip()
    return v if v else None


def dependency_to_osv_query(dep: DeclaredDependency) -> Dict[str, Any]:
    """Converts a DeclaredDependency into an OSV query item dictionary."""
    osv_ecosystem = map_ecosystem_to_osv(dep.ecosystem)
    query: Dict[str, Any] = {
        "package": {
            "name": dep.name,
            "ecosystem": osv_ecosystem,
        }
    }
    clean_v = normalize_version_for_osv(dep.version_spec)
    if clean_v:
        query["version"] = clean_v
    return query


# =============================================================================
# OSV Client Implementation
# =============================================================================

class OSVClient:
    """HTTP client for OSV.dev vulnerability queries using the batch endpoint."""

    DEFAULT_BASE_URL = "https://api.osv.dev/v1"
    DEFAULT_TIMEOUT_SECONDS = 10.0
    DEFAULT_MAX_RETRIES = 2
    DEFAULT_BACKOFF_FACTOR = 0.3
    MAX_BATCH_CHUNK_SIZE = 1000

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_retries: int = DEFAULT_MAX_RETRIES,
        backoff_factor: float = DEFAULT_BACKOFF_FACTOR,
        auth_header: Optional[str] = None,
        api_key: Optional[str] = None,
        user_agent: str = "SecretScannerEngine-CVECheck/1.0",
    ):
        """Initializes the OSV client.
        
        Args:
            base_url: Base URL for OSV API (defaults to https://api.osv.dev/v1).
            timeout: Timeout in seconds for HTTP requests.
            max_retries: Number of retry attempts on transient network or 5xx failures.
            backoff_factor: Multiplier for exponential backoff between retries.
            auth_header: Optional raw Authorization header value (e.g. 'Bearer ...').
            api_key: Optional API key. If provided and auth_header is not, generates 'Bearer <key>'.
            user_agent: Custom User-Agent header string.
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = float(timeout)
        self.max_retries = max(0, int(max_retries))
        self.backoff_factor = float(backoff_factor)
        self.user_agent = user_agent

        if auth_header:
            self.auth_header: Optional[str] = auth_header
        elif api_key:
            self.auth_header = f"Bearer {api_key}"
        else:
            self.auth_header = None

    def _build_headers(self) -> Dict[str, str]:
        """Constructs headers for OSV API HTTP requests."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": self.user_agent,
        }
        if self.auth_header:
            headers["Authorization"] = self.auth_header
        return headers

    def _execute_http_post(self, url: str, payload_bytes: bytes) -> Dict[str, Any]:
        """Executes HTTP POST request with retry backoff and distinct exception handling."""
        headers = self._build_headers()
        last_exception: Optional[Exception] = None

        for attempt in range(self.max_retries + 1):
            req = urllib.request.Request(
                url=url,
                data=payload_bytes,
                headers=headers,
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    status_code = resp.status if hasattr(resp, "status") else resp.getcode()
                    body_bytes = resp.read()
                    body_str = body_bytes.decode("utf-8", errors="replace")

                    if status_code != 200:
                        # Check if transient server error (500, 502, 503, 504)
                        if status_code in (500, 502, 503, 504) and attempt < self.max_retries:
                            time.sleep(self.backoff_factor * (2 ** attempt))
                            continue
                        raise OSVHTTPError(status_code=status_code, response_body=body_str)

                    try:
                        return json.loads(body_str)
                    except json.JSONDecodeError as err:
                        raise OSVResponseError(f"Malformed JSON returned by OSV API: {err}")

            except urllib.error.HTTPError as err:
                status_code = err.code
                err_body = err.read().decode("utf-8", errors="replace")
                # Transient 5xx can be retried
                if status_code in (500, 502, 503, 504) and attempt < self.max_retries:
                    last_exception = OSVHTTPError(status_code=status_code, response_body=err_body)
                    time.sleep(self.backoff_factor * (2 ** attempt))
                    continue
                raise OSVHTTPError(status_code=status_code, response_body=err_body)

            except (socket.timeout, TimeoutError) as err:
                last_exception = OSVTimeoutError(
                    message=f"OSV API request timed out after {self.timeout}s: {err}",
                    timeout=self.timeout,
                )
                if attempt < self.max_retries:
                    time.sleep(self.backoff_factor * (2 ** attempt))
                    continue
                raise last_exception

            except urllib.error.URLError as err:
                # Differentiate between timeout wrapped in URLError and network connection failure
                is_timeout = isinstance(err.reason, socket.timeout) or "timed out" in str(err.reason).lower()
                if is_timeout:
                    last_exception = OSVTimeoutError(
                        message=f"OSV API request timed out after {self.timeout}s: {err.reason}",
                        timeout=self.timeout,
                    )
                else:
                    last_exception = OSVConnectionError(
                        message=f"Failed to connect to OSV API: {err.reason}",
                        original_error=err,
                    )

                if attempt < self.max_retries:
                    time.sleep(self.backoff_factor * (2 ** attempt))
                    continue
                raise last_exception

            except OSVClientError:
                raise

            except Exception as err:
                # Any other unexpected network/socket error
                last_exception = OSVConnectionError(
                    message=f"Unexpected error communicating with OSV API: {err}",
                    original_error=err,
                )
                if attempt < self.max_retries:
                    time.sleep(self.backoff_factor * (2 ** attempt))
                    continue
                raise last_exception

        if last_exception:
            raise last_exception
        raise OSVClientError("Request to OSV API failed after all retry attempts")

    def query_batch(self, queries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Queries OSV.dev for a batch of package queries.
        
        Args:
            queries: List of query dictionaries, each specifying 'package' and optional 'version'.
            
        Returns:
            List of result dictionaries, ordered in 1-to-1 correspondence with queries.
            Each entry typically contains a 'vulns' list, or is empty if no vulnerabilities found.
            
        Raises:
            OSVTimeoutError: If request times out.
            OSVConnectionError: If network connection fails.
            OSVHTTPError: If server returns non-200 response.
            OSVResponseError: If server response cannot be parsed as JSON.
        """
        if not queries:
            return []

        all_results: List[Dict[str, Any]] = []
        batch_url = f"{self.base_url}/querybatch"

        # Chunk queries into chunks of MAX_BATCH_CHUNK_SIZE if large
        for i in range(0, len(queries), self.MAX_BATCH_CHUNK_SIZE):
            chunk = queries[i:i + self.MAX_BATCH_CHUNK_SIZE]
            payload = json.dumps({"queries": chunk}).encode("utf-8")
            data = self._execute_http_post(batch_url, payload)

            if not isinstance(data, dict) or "results" not in data or not isinstance(data["results"], list):
                raise OSVResponseError("OSV API response missing expected 'results' array")

            all_results.extend(data["results"])

        return all_results

    def query_dependencies(
        self,
        dependencies: List[DeclaredDependency],
    ) -> List[Tuple[DeclaredDependency, List[Dict[str, Any]]]]:
        """Checks declared dependencies against OSV.dev via a single batch request.
        
        Args:
            dependencies: List of DeclaredDependency objects.
            
        Returns:
            List of (DeclaredDependency, vulnerabilities_list) pairs.
        """
        if not dependencies:
            return []

        queries = [dependency_to_osv_query(dep) for dep in dependencies]
        batch_results = self.query_batch(queries)

        paired: List[Tuple[DeclaredDependency, List[Dict[str, Any]]]] = []
        for dep, res in zip(dependencies, batch_results):
            vulns = res.get("vulns", []) if isinstance(res, dict) else []
            paired.append((dep, vulns if isinstance(vulns, list) else []))

        return paired
