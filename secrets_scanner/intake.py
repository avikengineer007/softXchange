"""Scan-service upload intake layer supporting file uploads and GitHub repository URLs.

Provides:
- IntakeSource and ListingStatus domain models with fail-closed status transitions.
- Scoped GitHub App installation credential storage with KMS-backed envelope encryption.
- Zero-leak token security: write-only credentials, process-table safe GIT_ASKPASS cloning,
  and error message / log sanitization.
- Immediate ref resolution and immutable commit SHA pinning.
- Scratch directory lifecycle guarantees with identical scan pipeline handoff.
- Explicit seller-triggered re-scan versioning.
"""

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from enum import Enum
import hashlib
import hmac
import logging
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

from .contract import ContractStatus, PackageScanResult
from .extractor import safe_extract_archive, ArchiveSecurityError
from .orchestrator import scan_package
from .redactor import redact_secret

logger = logging.getLogger("scan_service.intake")


# -----------------------------------------------------------------------------
# Domain Enums & Models
# -----------------------------------------------------------------------------

class IntakeSource(str, Enum):
    """Supported package intake source types."""
    FILE_UPLOAD = "file_upload"
    GITHUB_URL = "github_url"


class ListingStatus(str, Enum):
    """Listing / Upload verification statuses in scan-service."""
    PENDING_SCAN = "pending_scan"
    SCANNING = "scanning"
    PASSED = "passed"
    FAILED = "failed"
    SCAN_FAILED = "scan_failed"
    ERROR = "error"


# -----------------------------------------------------------------------------
# Zero-Leak Sanitization Utilities
# -----------------------------------------------------------------------------

# Regex matching sensitive tokens and HTTP auth headers
_TOKEN_PATTERN = re.compile(r"(?:gh[spro]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{22,}|Bearer\s+[A-Za-z0-9_\-\.]+)", re.IGNORECASE)
_URL_CRED_PATTERN = re.compile(r"(https?://)(?:[^:@\s]+(?::[^@\s]*)?@)", re.IGNORECASE)


def sanitize_text(text: str, sensitive_values: Optional[List[str]] = None) -> str:
    """Sanitizes sensitive tokens, auth headers, and URL credentials from text.
    
    Guarantees no raw tokens ever surface in log lines, error messages, or exception representations.
    """
    if not text:
        return ""
        
    sanitized = _URL_CRED_PATTERN.sub(r"\1***@", text)
    sanitized = _TOKEN_PATTERN.sub("[REDACTED_TOKEN]", sanitized)
    
    if sensitive_values:
        for val in sensitive_values:
            if val and len(val) >= 4:
                sanitized = sanitized.replace(val, "[REDACTED_CREDENTIAL]")
                
    return sanitized


class IntakeError(Exception):
    """Base intake domain error with guaranteed sanitized string representation."""
    def __init__(self, message: str, sensitive_values: Optional[List[str]] = None):
        self.raw_message = message
        self.sanitized_message = sanitize_text(message, sensitive_values)
        super().__init__(self.sanitized_message)

    def __str__(self) -> str:
        return self.sanitized_message

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.sanitized_message!r})"


class CloneError(IntakeError):
    """Raised when repository cloning fails."""
    pass


class CredentialError(IntakeError):
    """Raised when credential retrieval or authorization fails."""
    pass


# -----------------------------------------------------------------------------
# Cryptographic Key Derivation & KMS-Backed Envelope Encryption
# -----------------------------------------------------------------------------

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 HKDF-Extract using HMAC-SHA256."""
    if not salt:
        salt = b"\x00" * 32
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-Expand using HMAC-SHA256."""
    hash_len = 32
    n = (length + hash_len - 1) // hash_len
    if n > 255:
        raise ValueError("Cannot expand beyond 255 blocks")
        
    okm = bytearray()
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm.extend(t)
    return bytes(okm[:length])


class KMSProvider(ABC):
    """Abstract Key Management Service interface for Data Encryption Key (DEK) protection."""

    @abstractmethod
    def encrypt_dek(self, plaintext_dek: bytes, key_id: str) -> bytes:
        """Encrypts a 256-bit DEK using the specified Key Encryption Key (KEK)."""
        pass

    @abstractmethod
    def decrypt_dek(self, encrypted_dek: bytes, key_id: str) -> bytes:
        """Decrypts an encrypted DEK using the specified Key Encryption Key (KEK)."""
        pass


class LocalRootKeyKMSProvider(KMSProvider):
    """Local KMS provider utilizing HKDF-SHA256 from a root secret.
    
    Supports key rotation via versioned key IDs (e.g. 'root-key-v1').
    """

    def __init__(self, root_secrets: Optional[Dict[str, bytes]] = None):
        if root_secrets is None:
            default_secret = os.environ.get("SCAN_SERVICE_ROOT_KEY", "default-dev-root-secret-32-bytes!!").encode("utf-8")
            self.root_secrets = {"root-key-v1": hashlib.sha256(default_secret).digest()}
        else:
            self.root_secrets = root_secrets

    def encrypt_dek(self, plaintext_dek: bytes, key_id: str) -> bytes:
        if key_id not in self.root_secrets:
            raise CredentialError(f"KMS key ID not found: {key_id}")
        kek = hkdf_expand(self.root_secrets[key_id], b"kms-kek", 32)
        iv = secrets.token_bytes(16)
        # Encrypt DEK with authenticated stream cipher derived from KEK
        stream_key = hkdf_expand(kek, b"dek-enc", 32)
        mac_key = hkdf_expand(kek, b"dek-mac", 32)
        keystream = hmac.new(stream_key, iv, hashlib.sha256).digest()
        ciphertext = bytes(a ^ b for a, b in zip(plaintext_dek, keystream))
        tag = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
        return iv + ciphertext + tag

    def decrypt_dek(self, encrypted_dek: bytes, key_id: str) -> bytes:
        if key_id not in self.root_secrets:
            raise CredentialError(f"KMS key ID not found: {key_id}")
        if len(encrypted_dek) < 48:
            raise CredentialError("Malformed encrypted DEK payload")
            
        iv = encrypted_dek[:16]
        ciphertext = encrypted_dek[16:48]
        tag = encrypted_dek[48:]
        
        kek = hkdf_expand(self.root_secrets[key_id], b"kms-kek", 32)
        mac_key = hkdf_expand(kek, b"dek-mac", 32)
        expected_tag = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected_tag):
            raise CredentialError("KMS DEK integrity verification failed")
            
        stream_key = hkdf_expand(kek, b"dek-enc", 32)
        keystream = hmac.new(stream_key, iv, hashlib.sha256).digest()
        return bytes(a ^ b for a, b in zip(ciphertext, keystream))


@dataclass(frozen=True)
class EncryptedEnvelope:
    """Encrypted data envelope storing ciphertext and encrypted DEK."""
    key_id: str
    encrypted_dek_hex: str
    iv_hex: str
    ciphertext_hex: str
    tag_hex: str

    def __repr__(self) -> str:
        return f"<EncryptedEnvelope key_id={self.key_id!r} cipher_len={len(self.ciphertext_hex) // 2}>"


class EnvelopeCipher:
    """Authenticated encryption engine using KMS-backed Data Encryption Keys.
    
    Uses 256-bit DEKs per secret, HKDF-SHA256 key separation, and Encrypt-then-MAC with
    timing-attack resistant verification.
    """

    def __init__(self, kms_provider: Optional[KMSProvider] = None, default_key_id: str = "root-key-v1"):
        self.kms = kms_provider or LocalRootKeyKMSProvider()
        self.default_key_id = default_key_id

    def encrypt(self, plaintext: str, key_id: Optional[str] = None) -> EncryptedEnvelope:
        kid = key_id or self.default_key_id
        plaintext_bytes = plaintext.encode("utf-8")
        
        # 1. Generate unique 256-bit random DEK
        dek = secrets.token_bytes(32)
        
        # 2. Derive distinct encryption and authentication keys from DEK
        prk = hkdf_extract(salt=b"", ikm=dek)
        enc_key = hkdf_expand(prk, b"payload-enc", 32)
        mac_key = hkdf_expand(prk, b"payload-mac", 32)
        
        # 3. Generate 16-byte random IV
        iv = secrets.token_bytes(16)
        
        # 4. Generate keystream using counter mode with HMAC-SHA256
        num_blocks = (len(plaintext_bytes) + 31) // 32
        keystream = bytearray()
        for i in range(num_blocks):
            block = hmac.new(enc_key, iv + i.to_bytes(4, "big"), hashlib.sha256).digest()
            keystream.extend(block)
            
        ciphertext = bytes(p ^ k for p, k in zip(plaintext_bytes, keystream[:len(plaintext_bytes)]))
        tag = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
        
        # 5. Encrypt DEK with KMS
        encrypted_dek = self.kms.encrypt_dek(dek, kid)
        
        return EncryptedEnvelope(
            key_id=kid,
            encrypted_dek_hex=encrypted_dek.hex(),
            iv_hex=iv.hex(),
            ciphertext_hex=ciphertext.hex(),
            tag_hex=tag.hex(),
        )

    def decrypt(self, envelope: EncryptedEnvelope) -> str:
        try:
            encrypted_dek = bytes.fromhex(envelope.encrypted_dek_hex)
            iv = bytes.fromhex(envelope.iv_hex)
            ciphertext = bytes.fromhex(envelope.ciphertext_hex)
            tag = bytes.fromhex(envelope.tag_hex)
        except ValueError as e:
            raise CredentialError(f"Malformed hex encoding in encrypted envelope: {e}")
            
        # 1. Decrypt DEK via KMS
        dek = self.kms.decrypt_dek(encrypted_dek, envelope.key_id)
        
        # 2. Derive encryption and MAC keys
        prk = hkdf_extract(salt=b"", ikm=dek)
        enc_key = hkdf_expand(prk, b"payload-enc", 32)
        mac_key = hkdf_expand(prk, b"payload-mac", 32)
        
        # 3. Verify MAC in constant time
        expected_tag = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected_tag):
            raise CredentialError("Ciphertext integrity verification failed")
            
        # 4. Decrypt ciphertext
        num_blocks = (len(ciphertext) + 31) // 32
        keystream = bytearray()
        for i in range(num_blocks):
            block = hmac.new(enc_key, iv + i.to_bytes(4, "big"), hashlib.sha256).digest()
            keystream.extend(block)
            
        plaintext_bytes = bytes(c ^ k for c, k in zip(ciphertext, keystream[:len(ciphertext)]))
        return plaintext_bytes.decode("utf-8")


# -----------------------------------------------------------------------------
# Scoped GitHub App Credential Storage
# -----------------------------------------------------------------------------

def normalize_repo_url(url: str) -> str:
    """Normalizes a GitHub repository URL to 'https://github.com/owner/repo'.
    
    Rejects malformed URLs and strips authentication or trailing slashes.
    """
    parsed = urlparse(url.strip())
    if parsed.scheme not in ("https", "http"):
        raise ValueError(f"Invalid URL scheme: {parsed.scheme}")
        
    netloc = parsed.netloc.lower()
    if "@" in netloc:
        # Strip userinfo if present
        netloc = netloc.split("@", 1)[1]
        
    path = parsed.path.rstrip("/")
    if path.endswith(".git"):
        path = path[:-4]
        
    parts = [p for p in path.split("/") if p]
    if len(parts) < 2:
        raise ValueError(f"Invalid repository path in URL: {url}")
        
    owner, repo = parts[0], parts[1]
    return f"https://github.com/{owner}/{repo}"


@dataclass(frozen=True)
class GitHubAppGrant:
    """Scoped repository access grant issued via GitHub App installation authorization.
    
    Zero-leak guarantee: __repr__ and __str__ never expose tokens or keys.
    """
    grant_id: str
    seller_id: str
    normalized_repo_url: str
    envelope: EncryptedEnvelope
    expires_at: Optional[float] = None
    created_at: float = field(default_factory=time.time)

    def __repr__(self) -> str:
        return (
            f"<GitHubAppGrant grant_id={self.grant_id!r} "
            f"seller_id={self.seller_id!r} repo={self.normalized_repo_url!r} encrypted=True>"
        )

    def __str__(self) -> str:
        return self.__repr__()

    def to_dict(self) -> Dict[str, Any]:
        """Safe dictionary representation with zero credential leakage."""
        return {
            "grant_id": self.grant_id,
            "seller_id": self.seller_id,
            "repo_url": self.normalized_repo_url,
            "has_token": True,
            "expires_at": self.expires_at,
            "created_at": self.created_at,
        }


class GitHubAppCredentialStore:
    """Encrypted credential store scoped strictly to 1 seller + 1 repository per grant.
    
    Enforces write-only token discipline. Decrypted tokens are only returned in memory
    for immediate clone execution and never written to disk or logs.
    """

    def __init__(self, cipher: Optional[EnvelopeCipher] = None):
        self.cipher = cipher or EnvelopeCipher()
        # Storage keyed strictly by composite tuple: (seller_id, normalized_repo_url)
        self._grants: Dict[Tuple[str, str], GitHubAppGrant] = {}

    def store_grant(
        self,
        seller_id: str,
        repo_url: str,
        installation_token: str,
        expires_at: Optional[float] = None,
    ) -> GitHubAppGrant:
        """Stores a new GitHub App installation token encrypted at rest.
        
        Guarantees strict 1 seller + 1 repo grant scoping.
        """
        if not seller_id or not seller_id.strip():
            raise CredentialError("seller_id is required")
        if not installation_token or not installation_token.strip():
            raise CredentialError("installation_token cannot be empty")
            
        norm_url = normalize_repo_url(repo_url)
        grant_id = f"grant_{secrets.token_hex(8)}"
        
        envelope = self.cipher.encrypt(installation_token.strip())
        grant = GitHubAppGrant(
            grant_id=grant_id,
            seller_id=seller_id,
            normalized_repo_url=norm_url,
            envelope=envelope,
            expires_at=expires_at,
        )
        
        self._grants[(seller_id, norm_url)] = grant
        logger.info("Stored encrypted GitHub App grant %s for seller %s on %s", grant_id, seller_id, norm_url)
        return grant

    def retrieve_decrypted_token(self, seller_id: str, repo_url: str) -> str:
        """Retrieves and decrypts the installation token for the given seller and repo.
        
        Raises CredentialError on missing, mismatched, or expired grant.
        """
        norm_url = normalize_repo_url(repo_url)
        key = (seller_id, norm_url)
        
        if key not in self._grants:
            raise CredentialError(f"No authorized GitHub App grant found for repository: {norm_url}")
            
        grant = self._grants[key]
        if grant.expires_at is not None and time.time() > grant.expires_at:
            raise CredentialError("GitHub App installation token has expired")
            
        return self.cipher.decrypt(grant.envelope)

    def revoke_grant(self, seller_id: str, repo_url: str) -> bool:
        """Revokes a stored repository grant."""
        norm_url = normalize_repo_url(repo_url)
        return self._grants.pop((seller_id, norm_url), None) is not None

    def has_grant(self, seller_id: str, repo_url: str) -> bool:
        norm_url = normalize_repo_url(repo_url)
        return (seller_id, norm_url) in self._grants


# -----------------------------------------------------------------------------
# Safe Git Clone via Process-Safe GIT_ASKPASS
# -----------------------------------------------------------------------------

def safe_rmtree(dir_path: Union[str, Path]) -> None:
    """Safely removes a directory tree, clearing read-only flags (e.g. on Windows git objects)."""
    path = str(dir_path)
    if not os.path.exists(path):
        return
    import stat
    def handle_remove_readonly(func, p, exc):
        try:
            os.chmod(p, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
            func(p)
        except Exception:
            pass
    try:
        shutil.rmtree(path, onerror=handle_remove_readonly)
    except Exception:
        pass
    if os.path.exists(path):
        try:
            shutil.rmtree(path, ignore_errors=True)
        except Exception:
            pass


def safe_clone_github_repo(
    repo_url: str,
    target_dir: str,
    ref: Optional[str] = None,
    auth_token: Optional[str] = None,
    timeout_seconds: float = 30.0,
) -> str:
    """Clones a GitHub repository safely into target_dir and resolves commit SHA.
    
    Security Guarantees:
      - Tokens are NEVER placed in argv, command strings, process table, or clone URLs.
      - Ephemeral GIT_ASKPASS credential helper feeds the token via standard output to Git.
      - Git remote URL in .git/config contains only the clean public repository URL.
      - Pins commit SHA immediately via 'git rev-parse HEAD'.
      - Fails closed on any error (auth failure, 404, network timeout) and wipes target_dir.
      - Sanitizes all exceptions and output to guarantee zero token leakage.
      
    Args:
        repo_url: GitHub repository URL (e.g. 'https://github.com/owner/repo').
        target_dir: Destination scratch directory.
        ref: Commit SHA, tag, or branch name (default branch HEAD if omitted).
        auth_token: Optional GitHub App installation token for private repos.
        timeout_seconds: Subprocess execution timeout in seconds.
        
    Returns:
        Resolved 40-character commit SHA.
        
    Raises:
        CloneError: On any failure, with sanitized error description.
    """
    norm_url = normalize_repo_url(repo_url)
    dest_path = Path(target_dir).resolve()
    dest_path.mkdir(parents=True, exist_ok=True)
    
    # Ephemeral askpass directory to avoid argv or url token exposure
    askpass_dir = tempfile.mkdtemp(prefix="git_askpass_")
    askpass_script = Path(askpass_dir) / "askpass.py"
    token_file = Path(askpass_dir) / "token.secret"
    
    sensitive_tokens = [auth_token] if auth_token else []

    try:
        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GCM_INTERACTIVE"] = "never"
        
        if auth_token:
            # Write token to a restricted ephemeral file
            with open(token_file, "w", encoding="utf-8") as tf:
                tf.write(auth_token)
            if hasattr(os, "chmod"):
                try:
                    os.chmod(str(token_file), 0o600)
                except Exception:
                    pass
                    
            # Helper script that reads the token and writes to stdout when prompted
            with open(askpass_script, "w", encoding="utf-8") as sf:
                sf.write(
                    "import sys, pathlib\n"
                    f"token_path = pathlib.Path({repr(str(token_file))})\n"
                    "prompt = sys.argv[1] if len(sys.argv) > 1 else ''\n"
                    "if 'username' in prompt.lower():\n"
                    "    sys.stdout.write('x-access-token\\n')\n"
                    "else:\n"
                    "    if token_path.exists():\n"
                    "        sys.stdout.write(token_path.read_text(encoding='utf-8').strip() + '\\n')\n"
                    "sys.stdout.flush()\n"
                )
            
            env["GIT_ASKPASS"] = f"{sys.executable} \"{str(askpass_script)}\""

        # 1. Parameterized git clone (strictly argv list, shell=False, clean URL, override credential helper)
        clone_cmd = ["git", "-c", "credential.helper=", "clone", norm_url, str(dest_path)]
        try:
            res = subprocess.run(
                clone_cmd,
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                shell=False,
            )
            if res.returncode != 0:
                raw_err = res.stderr or res.stdout or "git clone exited with non-zero status"
                clean_err = sanitize_text(raw_err, sensitive_tokens)
                raise CloneError(f"Clone failed: {clean_err}", sensitive_tokens)
        except subprocess.TimeoutExpired:
            raise CloneError(f"Clone timed out after {timeout_seconds:.1f}s", sensitive_tokens)
        except Exception as e:
            if not isinstance(e, CloneError):
                raise CloneError(f"Git execution failure: {type(e).__name__}: {str(e)}", sensitive_tokens)
            raise

        # 2. Checkout explicit ref if specified
        if ref and ref.strip():
            ref_clean = ref.strip()
            checkout_cmd = ["git", "checkout", ref_clean]
            res = subprocess.run(
                checkout_cmd,
                cwd=str(dest_path),
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                shell=False,
            )
            if res.returncode != 0:
                raw_err = res.stderr or res.stdout or f"failed to checkout ref {ref_clean}"
                clean_err = sanitize_text(raw_err, sensitive_tokens)
                raise CloneError(f"Ref checkout failed: {clean_err}", sensitive_tokens)

        # 3. Pin commit SHA immediately via 'git rev-parse HEAD'
        rev_cmd = ["git", "rev-parse", "HEAD"]
        res = subprocess.run(
            rev_cmd,
            cwd=str(dest_path),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            shell=False,
        )
        if res.returncode != 0:
            raw_err = res.stderr or res.stdout or "failed to resolve commit SHA"
            clean_err = sanitize_text(raw_err, sensitive_tokens)
            raise CloneError(f"Commit SHA resolution failed: {clean_err}", sensitive_tokens)
            
        resolved_sha = res.stdout.strip()
        if not re.match(r"^[0-9a-fA-F]{40}$", resolved_sha):
            raise CloneError(f"Resolved commit hash has unexpected format: {resolved_sha}", sensitive_tokens)
            
        return resolved_sha

    except Exception:
        # Cleanup on failure: fail-closed discipline
        if dest_path.exists():
            safe_rmtree(dest_path)
        raise
    finally:
        # Clean up ephemeral askpass files immediately
        safe_rmtree(askpass_dir)


# -----------------------------------------------------------------------------
# Intake Records & Pipeline Orchestrator
# -----------------------------------------------------------------------------

@dataclass
class ListingVersion:
    """Represents a submitted listing version in scan-service."""
    listing_id: str
    version_id: str
    seller_id: str
    intake_source: IntakeSource
    status: ListingStatus = ListingStatus.PENDING_SCAN
    repo_url: Optional[str] = None
    ref: Optional[str] = None
    resolved_commit_sha: Optional[str] = None
    storage_location: str = "pending/"
    error_message: Optional[str] = None
    scan_result: Optional[PackageScanResult] = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "listing_id": self.listing_id,
            "version_id": self.version_id,
            "seller_id": self.seller_id,
            "intake_source": self.intake_source.value,
            "status": self.status.value,
            "repo_url": self.repo_url,
            "ref": self.ref,
            "resolved_commit_sha": self.resolved_commit_sha,
            "storage_location": self.storage_location,
            "error_message": self.error_message,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass
class UploadRecord:
    """Represents an upload intake submission."""
    upload_id: str
    listing_id: str
    version_id: str
    seller_id: str
    intake_source: IntakeSource
    status: ListingStatus = ListingStatus.PENDING_SCAN
    archive_path: Optional[str] = None
    repo_url: Optional[str] = None
    ref: Optional[str] = None
    resolved_commit_sha: Optional[str] = None
    error_message: Optional[str] = None
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "upload_id": self.upload_id,
            "listing_id": self.listing_id,
            "version_id": self.version_id,
            "seller_id": self.seller_id,
            "intake_source": self.intake_source.value,
            "status": self.status.value,
            "archive_path": self.archive_path,
            "repo_url": self.repo_url,
            "ref": self.ref,
            "resolved_commit_sha": self.resolved_commit_sha,
            "error_message": self.error_message,
            "created_at": self.created_at,
        }


def run_default_intake_scanners(scratch_dir: Union[str, Path], **kwargs: Any) -> PackageScanResult:
    """Executes the multi-scanner suite (secrets + static analysis) over intake scratch."""
    from .orchestrator import scan_package as scan_secrets
    from static_analysis.scanner import scan_package as scan_static
    from .contract import merge_package_results

    sec_res = scan_secrets(scratch_dir, **kwargs)
    stat_res = scan_static(scratch_dir, **kwargs)
    return merge_package_results(sec_res, stat_res)


class IntakePipeline:
    """Orchestrates intake ingestion, cloning/extraction, scanning, and storage transitions.
    
    Guarantees:
      - Cloned repos and file uploads feed into the identical scan pipeline.
      - Executes multi-scanner suite (secrets_scanner + static_analysis) by default.
      - scan_history=True is enabled by default for github_url.
      - Ephemeral scratch working directory is wiped after scan completion on any outcome.
      - Fail-closed error handling: on any clone failure, credential error, or worker exception,
        status transitions to SCAN_FAILED (never left in PENDING_SCAN or SCANNING).
      - Promotion from pending/ to live/ object storage on passed scan.
    """

    def __init__(
        self,
        credential_store: Optional[GitHubAppCredentialStore] = None,
        scanner_fn: Callable[..., PackageScanResult] = run_default_intake_scanners,
    ):
        self.credential_store = credential_store or GitHubAppCredentialStore()
        self.scanner_fn = scanner_fn
        # In-memory storage of versions and uploads (simulating database records)
        self.versions: Dict[Tuple[str, str], ListingVersion] = {}
        self.uploads: Dict[str, UploadRecord] = {}

    def submit_upload(
        self,
        listing_id: str,
        version_id: str,
        seller_id: str,
        intake_source: Union[IntakeSource, str],
        archive_path: Optional[str] = None,
        repo_url: Optional[str] = None,
        ref: Optional[str] = None,
        is_private: bool = False,
        scan_kwargs: Optional[Dict[str, Any]] = None,
        upload_id: Optional[str] = None,
    ) -> Tuple[UploadRecord, ListingVersion]:
        """Ingests a new package submission from file upload or GitHub repository URL.
        
        Returns:
            (UploadRecord, ListingVersion) representing the completed scan outcome.
        """
        source = IntakeSource(intake_source)
        
        key = (listing_id, version_id)
        if key in self.versions:
            version_rec = self.versions[key]
            version_rec.intake_source = source
            if repo_url:
                version_rec.repo_url = repo_url
            if ref:
                version_rec.ref = ref
        else:
            version_rec = ListingVersion(
                listing_id=listing_id,
                version_id=version_id,
                seller_id=seller_id,
                intake_source=source,
                status=ListingStatus.PENDING_SCAN,
                repo_url=repo_url,
                ref=ref,
                storage_location=f"pending/{listing_id}/{version_id}",
            )
            self.versions[key] = version_rec

        existing_upload = None
        if upload_id and upload_id in self.uploads:
            existing_upload = self.uploads[upload_id]
        else:
            for u in self.uploads.values():
                if u.listing_id == listing_id and u.version_id == version_id:
                    existing_upload = u
                    break

        if existing_upload:
            upload_rec = existing_upload
            upload_rec.intake_source = source
            if archive_path:
                upload_rec.archive_path = archive_path
            if repo_url:
                upload_rec.repo_url = repo_url
            if ref:
                upload_rec.ref = ref
        else:
            uid = upload_id or f"upl_{secrets.token_hex(8)}"
            upload_rec = UploadRecord(
                upload_id=uid,
                listing_id=listing_id,
                version_id=version_id,
                seller_id=seller_id,
                intake_source=source,
                status=ListingStatus.PENDING_SCAN,
                archive_path=archive_path,
                repo_url=repo_url,
                ref=ref,
            )
            self.uploads[uid] = upload_rec
        
        # Transition to SCANNING status
        self._update_status(upload_rec, version_rec, ListingStatus.SCANNING)
        
        scratch_dir = tempfile.mkdtemp(prefix="scan_scratch_")
        extra_tokens_to_sanitize: List[str] = []

        try:
            # 1. Intake Processing (Extraction vs Safe Clone)
            if source == IntakeSource.GITHUB_URL:
                if not repo_url:
                    raise IntakeError("Missing repository URL for github_url intake")
                    
                auth_token: Optional[str] = None
                if is_private:
                    auth_token = self.credential_store.retrieve_decrypted_token(seller_id, repo_url)
                    extra_tokens_to_sanitize.append(auth_token)
                    
                # Safe clone with GIT_ASKPASS and immediate commit SHA resolution
                resolved_sha = safe_clone_github_repo(
                    repo_url=repo_url,
                    target_dir=scratch_dir,
                    ref=ref,
                    auth_token=auth_token,
                )
                
                # Pin resolved commit SHA immutably
                version_rec.resolved_commit_sha = resolved_sha
                upload_rec.resolved_commit_sha = resolved_sha
                scan_history_default = True
                
            elif source == IntakeSource.FILE_UPLOAD:
                if not archive_path:
                    raise IntakeError("Missing archive_path for file_upload intake")
                    
                safe_extract_archive(archive_path, scratch_dir)
                scan_history_default = False
                
            else:
                raise IntakeError(f"Unsupported intake source: {source}")

            # 2. Scanner Pipeline Handoff
            kwargs = scan_kwargs.copy() if scan_kwargs else {}
            if "scan_history" not in kwargs:
                kwargs["scan_history"] = scan_history_default
                
            scan_result = self.scanner_fn(scratch_dir, **kwargs)
            version_rec.scan_result = scan_result
            
            # 3. Status Evaluation & Object Storage Transitions
            if scan_result.status == ContractStatus.PASSED.value:
                # Promotion to live storage
                version_rec.storage_location = f"live/{listing_id}/{version_id}"
                self._update_status(upload_rec, version_rec, ListingStatus.PASSED)
            elif scan_result.status == ContractStatus.FAILED.value:
                self._update_status(upload_rec, version_rec, ListingStatus.FAILED)
            else:  # ContractStatus.ERROR.value
                self._update_status(
                    upload_rec,
                    version_rec,
                    ListingStatus.SCAN_FAILED,
                    error_msg=scan_result.error_message or "Scan execution error",
                )

        except (CloneError, CredentialError, ArchiveSecurityError) as e:
            # Fail closed on clone failure, credential error, or corrupt archive
            sanitized_err = sanitize_text(str(e), extra_tokens_to_sanitize)
            logger.error("Intake processing failed for listing %s: %s", listing_id, sanitized_err)
            self._update_status(upload_rec, version_rec, ListingStatus.SCAN_FAILED, error_msg=sanitized_err)

        except Exception as e:
            # Fail closed on unexpected worker exception during SCANNING
            sanitized_err = sanitize_text(f"{type(e).__name__}: Operation failed safely", extra_tokens_to_sanitize)
            logger.exception("Unexpected error during intake scan for listing %s", listing_id)
            self._update_status(upload_rec, version_rec, ListingStatus.SCAN_FAILED, error_msg=sanitized_err)

        finally:
            # Cleanup guarantee: scratch working directory is wiped on all outcomes
            safe_rmtree(scratch_dir)

        return upload_rec, version_rec

    def resubmit_listing_version(
        self,
        listing_id: str,
        version_id: str,
        seller_id: str,
        ref: Optional[str] = None,
        is_private: bool = False,
    ) -> Tuple[UploadRecord, ListingVersion]:
        """Explicit seller-triggered re-scan action for a GitHub-backed listing version.
        
        Clones at the specified ref, pins newly resolved SHA, and scans.
        """
        # Retrieve original repo_url from previous version
        prev_version: Optional[ListingVersion] = None
        for (lid, _), v in self.versions.items():
            if lid == listing_id:
                prev_version = v
                break
                
        if not prev_version or not prev_version.repo_url:
            raise IntakeError(f"No existing GitHub repository registered for listing {listing_id}")
            
        return self.submit_upload(
            listing_id=listing_id,
            version_id=version_id,
            seller_id=seller_id,
            intake_source=IntakeSource.GITHUB_URL,
            repo_url=prev_version.repo_url,
            ref=ref,
            is_private=is_private,
        )

    def _update_status(
        self,
        upload_rec: UploadRecord,
        version_rec: ListingVersion,
        status: ListingStatus,
        error_msg: Optional[str] = None,
    ) -> None:
        upload_rec.status = status
        version_rec.status = status
        version_rec.updated_at = time.time()
        if error_msg:
            upload_rec.error_message = error_msg
            version_rec.error_message = error_msg
