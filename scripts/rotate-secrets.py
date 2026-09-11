#!/usr/bin/env python3
"""
scripts/rotate-secrets.py

Automated cryptographic rotation utility for softXchange production secrets.
Generates:
1. Fresh 2048-bit RSA keypair (jwt_private.pem and jwt_public.pem) for RS256 token signing.
2. High-entropy single-use ADMIN_PROVISIONING_CODE (64-hex-char token).
3. Cryptographically random INTERNAL_SERVICE_SECRET for inter-service HMAC verification.
4. Cryptographically random PostgreSQL database password.
"""

import os
import secrets
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

OUTPUT_DIR = Path(__file__).resolve().parent.parent / "secrets_generated"


def generate_rsa_keypair(output_dir: Path):
    """Generates 2048-bit RSA keypair in PEM format."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    priv_path = output_dir / "jwt_private.pem"
    pub_path = output_dir / "jwt_public.pem"

    with open(priv_path, "wb") as f:
        f.write(private_pem)
    with open(pub_path, "wb") as f:
        f.write(public_pem)

    # Restrict permissions on private key
    try:
        os.chmod(priv_path, 0o600)
    except Exception:
        pass

    return priv_path, pub_path


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    print("=========================================================")
    print("  softXchange Production Secret Generation & Rotation")
    print("=========================================================\n")

    # 1. RSA Keypair
    priv_path, pub_path = generate_rsa_keypair(OUTPUT_DIR)
    print(f"[OK] RSA 2048-bit Keypair Generated:")
    print(f"    Private Key: {priv_path}")
    print(f"    Public Key:  {pub_path}\n")

    # 2. Admin Provisioning Code
    # Format: sx_admin_ + 64 hex characters (32 bytes of cryptographic entropy)
    admin_code = f"sx_admin_{secrets.token_hex(32)}"
    print(f"[OK] Fresh High-Entropy ADMIN_PROVISIONING_CODE:")
    print(f"    {admin_code}\n")

    # 3. Inter-service HMAC Secret
    hmac_secret = secrets.token_hex(32)
    print(f"[OK] Fresh INTERNAL_SERVICE_SECRET (HMAC-SHA256):")
    print(f"    {hmac_secret}\n")

    # 4. Database Password
    db_password = secrets.token_urlsafe(32)
    print(f"[OK] Strong Database Password:")
    print(f"    {db_password}\n")

    # Save summary manifest
    manifest_path = OUTPUT_DIR / "rotated_secrets.env"
    with open(manifest_path, "w", encoding="utf-8") as f:
        f.write(f"# softXchange Rotated Production Secrets\n")
        f.write(f"ADMIN_PROVISIONING_CODE={admin_code}\n")
        f.write(f"ADMIN_CODE_EXPLICITLY_ROTATED=true\n")
        f.write(f"INTERNAL_SERVICE_SECRET={hmac_secret}\n")
        f.write(f"POSTGRES_PASSWORD={db_password}\n")
        f.write(f"JWT_PRIVATE_KEY_PATH={priv_path}\n")
        f.write(f"JWT_PUBLIC_KEY_PATH={pub_path}\n")

    print("=========================================================")
    print(f"  Summary saved to {manifest_path}")
    print("  NEVER commit generated secrets to version control!")
    print("=========================================================")


if __name__ == "__main__":
    main()
