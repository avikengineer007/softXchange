"""Result-level caching for OSV.dev dependency vulnerability queries.

Caches query responses by (ecosystem, package_name, version) for a configurable TTL
(default: 1 hour / 3600s) to avoid repeated remote API requests for identical packages.
"""

import threading
import time
from typing import Any, Dict, List, Optional, Tuple


class OSVCache:
    """Thread-safe in-memory cache for OSV query responses with TTL expiration."""

    DEFAULT_TTL_SECONDS = 3600.0  # 1 hour

    def __init__(self, default_ttl_seconds: float = DEFAULT_TTL_SECONDS):
        self.default_ttl = float(default_ttl_seconds)
        self._cache: Dict[Tuple[str, str, str], Tuple[float, float, List[Dict[str, Any]]]] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _normalize_key(ecosystem: str, name: str, version: Optional[str]) -> Tuple[str, str, str]:
        eco = (ecosystem or "").strip().lower()
        pkg = (name or "").strip().lower()
        ver = (version or "").strip()
        return (eco, pkg, ver)

    def get(self, ecosystem: str, name: str, version: Optional[str]) -> Optional[List[Dict[str, Any]]]:
        """Retrieves cached vulnerability list if present and unexpired."""
        key = self._normalize_key(ecosystem, name, version)
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            stored_at, ttl, vulns = entry
            if (time.time() - stored_at) >= ttl:
                # Expired entry
                del self._cache[key]
                return None
            # Return deep-copied list of dicts to protect internal cache state
            return [dict(v) for v in vulns]

    def set(
        self,
        ecosystem: str,
        name: str,
        version: Optional[str],
        vulns: List[Dict[str, Any]],
        ttl: Optional[float] = None,
    ) -> None:
        """Caches vulnerability list under (ecosystem, name, version) with TTL."""
        key = self._normalize_key(ecosystem, name, version)
        effective_ttl = self.default_ttl if ttl is None else float(ttl)
        with self._lock:
            copied = [dict(v) for v in vulns]
            self._cache[key] = (time.time(), effective_ttl, copied)

    def clear(self) -> None:
        """Purges all cached entries."""
        with self._lock:
            self._cache.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._cache)

    def contains(self, ecosystem: str, name: str, version: Optional[str]) -> bool:
        """Checks if a valid, unexpired entry exists for the given key."""
        return self.get(ecosystem, name, version) is not None


# Shared default in-memory cache instance
DEFAULT_OSV_CACHE = OSVCache()
