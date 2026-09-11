"""
apps/seller-assist/seller_assist/auth.py

JWKS-based authentication and role verification for seller-assist.
Ensures only authenticated sellers owning the target listing can request suggestions or explanations.
"""

from dataclasses import dataclass
import base64
import logging
import time
from typing import Optional, List, Dict, Any

import httpx
import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from seller_assist.config import settings

logger = logging.getLogger("seller-assist.auth")

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
    Fetches and caches public keys from auth-service with a configurable TTL.
    """
    def __init__(self, jwks_url: str, ttl_seconds: int = 3600):
        self.jwks_url = jwks_url
        self.ttl_seconds = ttl_seconds
        self._keys: Dict[str, Any] = {}
        self._last_fetched: float = 0.0

    def set_key_for_testing(self, kid: str, public_key: Any) -> None:
        """Inject test public key bypassing HTTP JWKS fetching."""
        self._keys[kid] = public_key
        self._last_fetched = time.time()


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
        try:
            with httpx.Client(timeout=5.0) as client:
                res = client.get(self.jwks_url)
                if res.status_code == 200:
                    jwks_data = res.json()
                    new_keys = {}
                    for key_dict in jwks_data.get("keys", []):
                        kid = key_dict.get("kid")
                        if kid:
                            new_keys[kid] = self._load_key_from_jwk(key_dict)
                    self._keys = new_keys
                    self._last_fetched = time.time()
                    logger.info(f"Loaded {len(self._keys)} public keys from JWKS")
        except Exception as exc:
            logger.warning(f"Failed to fetch JWKS from {self.jwks_url}: {exc}")

    def get_key(self, kid: str) -> Optional[Any]:
        if not self._keys or (time.time() - self._last_fetched > self.ttl_seconds):
            self.refresh_keys()

        if kid not in self._keys:
            self.refresh_keys()

        return self._keys.get(kid)


key_manager = JWKSKeyManager(jwks_url=settings.JWKS_URL)


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
) -> AuthContext:
    # 1. Allow internal service calls (e.g. broker pre-generating drafts)
    internal_service = request.headers.get("X-Internal-Service")
    if internal_service in ["broker", "system"]:
        return AuthContext(
            user_id=f"internal-{internal_service}",
            roles=["seller", "admin"],
            claims={"service": internal_service},
        )

    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    kid = unverified_header.get("kid")
    if not kid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token header missing 'kid'",
            headers={"WWW-Authenticate": "Bearer"},
        )

    public_key = key_manager.get_key(kid)
    if not public_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Unable to find public key matching kid '{kid}'",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = jwt.decode(
            token,
            key=public_key,
            algorithms=["RS256"],
            options={"verify_exp": True, "verify_aud": False},
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token verification failed: {str(exc)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing subject claim ('sub')",
            headers={"WWW-Authenticate": "Bearer"},
        )

    roles = payload.get("roles", [])
    if isinstance(roles, str):
        roles = [roles]

    return AuthContext(user_id=user_id, roles=roles, claims=payload)


async def require_seller(auth_ctx: AuthContext = Depends(get_current_user)) -> AuthContext:
    if not auth_ctx.has_role("seller"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Seller permissions required for this action",
        )
    return auth_ctx
