from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging
import os
import secrets
from typing import Optional, List, Dict, Any

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from src.config import settings

logger = logging.getLogger("auth-service.security")

security_scheme = HTTPBearer(auto_error=False)

# Fixed dummy hash for constant-time comparison when a user does not exist.
# This defends against timing-based user enumeration attacks during login.
DUMMY_BCRYPT_HASH = "$2b$12$e8k8zK8oW.eU2m7x.c6z8e8UoZfE2EwZ7G7h7w8j9k0l1m2n3o4p."

# Global key storage
_PRIVATE_KEY_PEM: Optional[str] = None
_PUBLIC_KEY_PEM: Optional[str] = None
_RSA_KEY_OBJECT = None


def _init_rsa_keys():
    """
    Initialize RSA keys based on environment and configuration.
    
    FAIL-CLOSED PRODUCTION GUARDRAIL:
    In production (ENVIRONMENT=production), if RS256 is configured and valid PEM
    keys are not provided via environment or file paths, auth-service will REFUSE
    TO START rather than generating ephemeral keys. Ephemeral keys in production
    cause multiple service instances to have mismatched signing keys and break
    downstream verification for listings-service and payments-service.
    """
    global _PRIVATE_KEY_PEM, _PUBLIC_KEY_PEM, _RSA_KEY_OBJECT

    if settings.JWT_ALGORITHM != "RS256":
        # HS256 is active
        logger.warning(
            "JWT_ALGORITHM is configured to HS256. Note: HS256 is strictly for local "
            "development/single-service fallback. When downstream services (listings-service, "
            "payments-service) exist, RS256 must be used so downstream services verify with "
            "the public key and never hold the signing secret."
        )
        return

    private_pem = settings.JWT_PRIVATE_KEY
    public_pem = settings.JWT_PUBLIC_KEY

    # Check file paths if inline PEM is not provided
    if not private_pem and settings.JWT_PRIVATE_KEY_PATH and os.path.exists(settings.JWT_PRIVATE_KEY_PATH):
        with open(settings.JWT_PRIVATE_KEY_PATH, "r", encoding="utf-8") as f:
            private_pem = f.read()

    if not public_pem and settings.JWT_PUBLIC_KEY_PATH and os.path.exists(settings.JWT_PUBLIC_KEY_PATH):
        with open(settings.JWT_PUBLIC_KEY_PATH, "r", encoding="utf-8") as f:
            public_pem = f.read()

    is_production = settings.ENVIRONMENT.lower() == "production"

    if private_pem and public_pem:
        _PRIVATE_KEY_PEM = private_pem.strip()
        _PUBLIC_KEY_PEM = public_pem.strip()
        logger.info("Loaded configured RSA keypair for RS256 signing.")
        return

    if is_production:
        raise RuntimeError(
            "FATAL: JWT_ALGORITHM is RS256 and ENVIRONMENT is 'production', but no RSA "
            "private/public keys are configured! Refusing to start with ephemeral keys in "
            "production. Configure JWT_PRIVATE_KEY/JWT_PUBLIC_KEY or file paths."
        )

    # In development/test mode: auto-generate an ephemeral RSA keypair
    logger.warning(
        "No RSA keypair configured in dev/test environment. Generating ephemeral 2048-bit "
        "RSA keypair for RS256 signing."
    )
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    _RSA_KEY_OBJECT = private_key

    _PRIVATE_KEY_PEM = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

    public_key = private_key.public_key()
    _PUBLIC_KEY_PEM = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")


# Run key initialization
_init_rsa_keys()


def get_public_key_pem() -> str:
    """Return the PEM encoded public key for RS256 token verification."""
    if _PUBLIC_KEY_PEM:
        return _PUBLIC_KEY_PEM
    raise RuntimeError("Public key is not configured or algorithm is not RS256.")


def get_jwks() -> Dict[str, Any]:
    """
    Return JWKS (JSON Web Key Set) representation of the public key.
    Downstream services (listings-service, payments-service) can fetch this from
    GET /auth/.well-known/jwks.json to verify access tokens.
    """
    if not _PUBLIC_KEY_PEM:
        return {"keys": []}

    public_key = serialization.load_pem_public_key(
        _PUBLIC_KEY_PEM.encode("utf-8"),
        backend=default_backend()
    )
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Configured public key is not an RSA key")

    public_numbers = public_key.public_numbers()
    
    import base64
    def int_to_base64url(val: int) -> str:
        byte_len = (val.bit_length() + 7) // 8
        val_bytes = val.to_bytes(byte_len, byteorder="big")
        return base64.urlsafe_b64encode(val_bytes).decode("utf-8").rstrip("=")

    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": "softxchange-auth-key-1",
                "n": int_to_base64url(public_numbers.n),
                "e": int_to_base64url(public_numbers.e),
            }
        ]
    }


# ============================================================================
# Password Hashing and Timing Attack Defense
# ============================================================================

def hash_password(password: str) -> str:
    """Hash password using bcrypt."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Constant-time verification of password against stored hash."""
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False


def verify_dummy_password(plain_password: str) -> bool:
    """
    Execute password check against fixed dummy hash to normalize timing
    when a requested user email does not exist in the database.
    """
    try:
        bcrypt.checkpw(plain_password.encode("utf-8"), DUMMY_BCRYPT_HASH.encode("utf-8"))
    except Exception:
        pass
    return False


# ============================================================================
# High-Entropy Token Generation and Hashing (Refresh & Verification Tokens)
# ============================================================================

def generate_secure_token() -> str:
    """Generate high-entropy random URL-safe token."""
    return secrets.token_urlsafe(32)


def hash_token(raw_token: str) -> str:
    """Hash high-entropy random token using SHA-256 for secure database storage."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


# ============================================================================
# JWT Access Token Issuance and Verification
# ============================================================================

def create_access_token(
    user_id: str,
    roles: List[str],
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Create a short-lived access token signed with RS256 (or HS256 in dev).
    Contains user_id and roles as claims.
    """
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    
    payload = {
        "sub": user_id,
        "roles": roles,
        "type": "access",
        "exp": expire,
        "iat": now,
    }

    if settings.JWT_ALGORITHM == "RS256":
        if not _PRIVATE_KEY_PEM:
            raise RuntimeError("RS256 signing requested but RSA private key is not initialized.")
        return jwt.encode(payload, _PRIVATE_KEY_PEM, algorithm="RS256", headers={"kid": "softxchange-auth-key-1"})
    else:
        return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm="HS256")


def decode_access_token(token: str) -> dict:
    """
    Stateless verification of access token signature and expiration.
    Uses the public key for RS256, requiring no database round-trip.
    """
    try:
        if settings.JWT_ALGORITHM == "RS256":
            if not _PUBLIC_KEY_PEM:
                raise RuntimeError("RSA public key is not initialized.")
            payload = jwt.decode(
                token,
                _PUBLIC_KEY_PEM,
                algorithms=["RS256"],
            )
        else:
            payload = jwt.decode(
                token,
                settings.JWT_SECRET_KEY,
                algorithms=["HS256"],
            )

        if payload.get("type") != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type for authorization",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return payload

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ============================================================================
# Exportable Auth Middleware / Dependency for Downstream Services
# ============================================================================

@dataclass
class AuthContext:
    """
    Authenticated user context attached to request context.
    Exported so listings-service and payments-service can verify identity
    without calling back to auth-service.
    """
    user_id: str
    roles: List[str]
    claims: Dict[str, Any]

    def has_role(self, role: str) -> bool:
        return role in self.roles or "admin" in self.roles


def require_auth(
    auth: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
) -> AuthContext:
    """
    FastAPI dependency for stateless request authentication.
    Verifies the access token's signature and expiry, attaching user_id + roles.
    Rejects (401) on any invalid, expired, or malformed token.
    """
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


def require_seller(auth_context: AuthContext = Depends(require_auth)) -> AuthContext:
    """Ensure authenticated context possesses seller or admin role."""
    if not auth_context.has_role("seller"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Seller role required for this action",
        )
    return auth_context


def require_customer(auth_context: AuthContext = Depends(require_auth)) -> AuthContext:
    """Ensure authenticated context possesses customer or admin role."""
    if not auth_context.has_role("customer"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Customer role required for this action",
        )
    return auth_context
