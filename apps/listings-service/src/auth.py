from dataclasses import dataclass
from datetime import datetime, timezone
import base64
import logging
import time
from typing import Optional, List, Dict, Any

import httpx
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from src.config import settings

logger = logging.getLogger("listings-service.auth")

security_scheme = HTTPBearer(auto_error=False)


@dataclass
class AuthContext:
    user_id: str
    roles: List[str]
    claims: Dict[str, Any]

    def has_role(self, role: str) -> bool:
        return role in self.roles or "admin" in self.roles


class JWKSKeyManager:
    """
    Autonomous JWKS cache manager.
    Fetches and caches public keys from auth-service with a configurable TTL (e.g. 1 hour).
    Automatically force-refreshes keys on verification failure or unrecognized kid
    to gracefully handle upstream key rotation.
    """
    def __init__(self, jwks_url: str, ttl_seconds: int = 3600):
        self.jwks_url = jwks_url
        self.ttl_seconds = ttl_seconds
        self._keys: Dict[str, Any] = {}
        self._last_fetched: float = 0.0

    def _base64url_to_int(self, val: str) -> int:
        padding = "=" * ((4 - len(val) % 4) % 4)
        data = base64.urlsafe_b64decode(val + padding)
        return int.from_bytes(data, byteorder="big")

    def _load_key_from_jwk(self, jwk: Dict[str, Any]) -> Any:
        if jwk.get("kty") != "RSA":
            raise ValueError(f"Unsupported key type: {jwk.get('kty')}")
        n = self._base64url_to_int(jwk["n"])
        e = self._base64url_to_int(jwk["e"])
        public_numbers = rsa.RSAPublicNumbers(e=e, n=n)
        return public_numbers.public_key(backend=default_backend())

    def refresh_keys(self) -> None:
        """Fetch fresh keys from auth-service."""
        try:
            logger.info(f"Fetching JWKS from {self.jwks_url}")
            with httpx.Client(timeout=5.0) as client:
                resp = client.get(self.jwks_url)
                resp.raise_for_status()
                data = resp.json()

            new_keys = {}
            for jwk in data.get("keys", []):
                kid = jwk.get("kid", "default")
                pub_key = self._load_key_from_jwk(jwk)
                new_keys[kid] = pub_key

            self._keys = new_keys
            self._last_fetched = time.time()
            logger.info(f"Successfully cached {len(self._keys)} public key(s) from JWKS")
        except Exception as exc:
            logger.error(f"Failed to fetch JWKS from {self.jwks_url}: {exc}")
            # Keep existing keys if network error occurs

    def get_public_key(self, kid: Optional[str] = None) -> Any:
        now = time.time()
        # Refresh if cache expired or empty
        if not self._keys or (now - self._last_fetched) > self.ttl_seconds:
            self.refresh_keys()

        if kid and kid in self._keys:
            return self._keys[kid]

        # If kid is specified but not found, force a refresh once in case of key rotation
        if kid and kid not in self._keys:
            logger.warning(f"Key id '{kid}' not in cache. Force-refreshing JWKS.")
            self.refresh_keys()
            if kid in self._keys:
                return self._keys[kid]

        # If still not found but we have any key, use the first key (or fail)
        if not kid and self._keys:
            return next(iter(self._keys.values()))

        raise ValueError(f"No suitable public key found in JWKS cache for kid '{kid}'")

    def set_key_for_testing(self, kid: str, public_key: Any) -> None:
        """Testing hook to inject mock keys without network calls."""
        self._keys[kid] = public_key
        self._last_fetched = time.time()


# Global JWKS manager instance
jwks_manager = JWKSKeyManager(
    jwks_url=f"{settings.AUTH_SERVICE_URL}/auth/.well-known/jwks.json",
    ttl_seconds=settings.JWKS_CACHE_TTL_SECONDS,
)


def decode_access_token(token: str) -> dict:
    """
    Locally verifies access token signature and expiry using cached public key.
    Never calls auth-service synchronously per request.
    """
    try:
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        alg = unverified_header.get("alg", "RS256")
        
        if alg not in ["RS256", "HS256"]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Unsupported token algorithm: {alg}",
                headers={"WWW-Authenticate": "Bearer"},
            )

        public_key = jwks_manager.get_public_key(kid)

        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
        )

        if payload.get("type") != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return payload

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except (jwt.InvalidTokenError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def require_auth(
    auth: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
) -> AuthContext:
    """Dependency verifying caller authentication locally."""
    if not auth or not auth.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(auth.credentials)
    user_id = payload.get("sub")
    roles = payload.get("roles", [])

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token claims: sub missing",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return AuthContext(user_id=str(user_id), roles=list(roles), claims=payload)


def require_seller(auth_ctx: AuthContext = Depends(require_auth)) -> AuthContext:
    """Ensure authenticated caller has the 'seller' or 'admin' role."""
    if not auth_ctx.has_role("seller"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Seller role required for this action",
        )
    return auth_ctx


def get_optional_auth(
    auth: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
) -> Optional[AuthContext]:
    """Optional authentication for endpoints that provide public views with owner enhancements."""
    if not auth or not auth.credentials:
        return None
    try:
        payload = decode_access_token(auth.credentials)
        user_id = payload.get("sub")
        roles = payload.get("roles", [])
        if user_id:
            return AuthContext(user_id=str(user_id), roles=list(roles), claims=payload)
    except Exception:
        pass
    return None
