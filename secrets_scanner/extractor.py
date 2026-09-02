"""Safe archive decompression utilities with adversarial protection."""

import os
import shutil
import tarfile
import time
import zipfile
from pathlib import Path
from typing import Optional


class ArchiveSecurityError(Exception):
    """Raised when an uploaded archive violates security constraints."""
    pass


def safe_extract_archive(
    archive_path: str,
    target_dir: str,
    max_total_bytes: int = 100 * 1024 * 1024,      # 100 MB max uncompressed
    max_single_file_bytes: int = 10 * 1024 * 1024, # 10 MB per single file
    max_total_files: int = 5000,                   # 5,000 files max
    timeout_seconds: float = 30.0,                 # 30s timeout budget
    allow_symlinks: bool = False
) -> str:
    """Safely extracts a ZIP or TAR archive enforcing strict security boundaries.
    
    Protections:
      - Path Traversal (Zip Slip / Tar Slip): Rejects absolute paths and traversal components ('..').
      - Zip/Tar Bombs: Incremental stream counting on every 64KB chunk during decompression.
      - Resource Exhaustion: Bounds total uncompressed bytes, individual file size, file count, and timeout.
      - Symlinks: Refused by default to prevent symbolic link creation.
      - Cleanup on Failure: Automatically wipes the target directory if extraction aborts or fails.
      
    Args:
        archive_path: Path to the .zip or .tar/.tar.gz archive.
        target_dir: Destination directory for extracted contents.
        max_total_bytes: Aggregate uncompressed size limit in bytes.
        max_single_file_bytes: Single uncompressed file size limit in bytes.
        max_total_files: Maximum allowed number of files in archive.
        timeout_seconds: Maximum wall-clock time in seconds for extraction.
        allow_symlinks: Whether to permit symlinks (default False).
        
    Returns:
        Absolute path to the extraction directory.
        
    Raises:
        ArchiveSecurityError: If any security boundary or budget is breached.
    """
    archive = Path(archive_path).resolve()
    target = Path(target_dir).resolve()
    
    if not archive.exists():
        raise FileNotFoundError(f"Archive not found: {archive_path}")
        
    os.makedirs(str(target), exist_ok=True)
    start_time = time.monotonic()
    
    total_uncompressed = 0
    total_files = 0
    extraction_successful = False

    try:
        if zipfile.is_zipfile(str(archive)):
            with zipfile.ZipFile(str(archive), "r") as zf:
                for info in zf.infolist():
                    # 1. Timeout check
                    if (time.monotonic() - start_time) > timeout_seconds:
                        raise ArchiveSecurityError(f"Archive extraction timed out ({timeout_seconds:.1f}s)")
                        
                    total_files += 1
                    if total_files > max_total_files:
                        raise ArchiveSecurityError(
                            f"Archive file count exceeded limit ({total_files} > {max_total_files})"
                        )
                        
                    # Early check against metadata header declared size
                    if info.file_size > max_single_file_bytes:
                        raise ArchiveSecurityError(
                            f"Single file size limit exceeded for {info.filename} ({info.file_size} > {max_single_file_bytes})"
                        )
                        
                    # 2. Path Traversal & Zip Slip check
                    normalized_name = os.path.normpath(info.filename)
                    if normalized_name.startswith("..") or os.path.isabs(info.filename):
                        raise ArchiveSecurityError(f"Path traversal detected in archive entry: {info.filename}")
                        
                    dest_file = os.path.abspath(os.path.join(str(target), normalized_name))
                    if not (dest_file == str(target) or dest_file.startswith(str(target) + os.sep)):
                        raise ArchiveSecurityError(f"Archive entry escapes target directory: {info.filename}")
                        
                    # 3. Handle directories and files
                    if info.is_dir():
                        os.makedirs(dest_file, exist_ok=True)
                        continue
                        
                    os.makedirs(os.path.dirname(dest_file), exist_ok=True)
                    
                    # 4. Incremental chunked decompression (defense against deceptive headers)
                    single_file_bytes = 0
                    with zf.open(info) as src, open(dest_file, "wb") as dst:
                        while True:
                            if (time.monotonic() - start_time) > timeout_seconds:
                                raise ArchiveSecurityError(f"Archive extraction timed out ({timeout_seconds:.1f}s)")
                                
                            chunk = src.read(65536)
                            if not chunk:
                                break
                                
                            chunk_len = len(chunk)
                            single_file_bytes += chunk_len
                            total_uncompressed += chunk_len
                            
                            if single_file_bytes > max_single_file_bytes:
                                raise ArchiveSecurityError(
                                    f"File {info.filename} exceeded max size during decompression"
                                )
                                
                            if total_uncompressed > max_total_bytes:
                                raise ArchiveSecurityError(
                                    f"Total archive uncompressed size exceeded limit ({total_uncompressed} > {max_total_bytes})"
                                )
                                
                            dst.write(chunk)

        elif tarfile.is_tarfile(str(archive)):
            with tarfile.open(str(archive), "r:*") as tf:
                for member in tf.getmembers():
                    if (time.monotonic() - start_time) > timeout_seconds:
                        raise ArchiveSecurityError(f"Archive extraction timed out ({timeout_seconds:.1f}s)")
                        
                    total_files += 1
                    if total_files > max_total_files:
                        raise ArchiveSecurityError(
                            f"Archive file count exceeded limit ({total_files} > {max_total_files})"
                        )
                        
                    # Symlink / Hardlink check
                    if (member.issym() or member.islnk()) and not allow_symlinks:
                        raise ArchiveSecurityError(f"Archive contains link entry: {member.name}")
                        
                    # Path Traversal & Tar Slip check
                    normalized_name = os.path.normpath(member.name)
                    if normalized_name.startswith("..") or os.path.isabs(member.name):
                        raise ArchiveSecurityError(f"Path traversal detected in tar entry: {member.name}")
                        
                    dest_file = os.path.abspath(os.path.join(str(target), normalized_name))
                    if not (dest_file == str(target) or dest_file.startswith(str(target) + os.sep)):
                        raise ArchiveSecurityError(f"Tar entry escapes target directory: {member.name}")
                        
                    if member.isdir():
                        os.makedirs(dest_file, exist_ok=True)
                        continue
                        
                    if member.isreg():
                        if member.size > max_single_file_bytes:
                            raise ArchiveSecurityError(
                                f"Single file size limit exceeded for {member.name} ({member.size} > {max_single_file_bytes})"
                            )
                            
                        os.makedirs(os.path.dirname(dest_file), exist_ok=True)
                        
                        single_file_bytes = 0
                        src = tf.extractfile(member)
                        if src is None:
                            continue
                            
                        with src, open(dest_file, "wb") as dst:
                            while True:
                                if (time.monotonic() - start_time) > timeout_seconds:
                                    raise ArchiveSecurityError(f"Archive extraction timed out ({timeout_seconds:.1f}s)")
                                    
                                chunk = src.read(65536)
                                if not chunk:
                                    break
                                    
                                chunk_len = len(chunk)
                                single_file_bytes += chunk_len
                                total_uncompressed += chunk_len
                                
                                if single_file_bytes > max_single_file_bytes:
                                    raise ArchiveSecurityError(
                                        f"File {member.name} exceeded max size during decompression"
                                    )
                                    
                                if total_uncompressed > max_total_bytes:
                                    raise ArchiveSecurityError(
                                        f"Total archive uncompressed size exceeded limit ({total_uncompressed} > {max_total_bytes})"
                                    )
                                    
                                dst.write(chunk)
        else:
            raise ArchiveSecurityError("Unsupported archive format (must be standard .zip or .tar/.tar.gz)")
            
        extraction_successful = True
        return str(target)

    finally:
        # Cleanup on failure: never leave partially decompressed or malicious artifacts on disk
        if not extraction_successful:
            if target.exists():
                shutil.rmtree(str(target), ignore_errors=True)
