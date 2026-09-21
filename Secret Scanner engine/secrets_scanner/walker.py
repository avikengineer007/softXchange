"""Filesystem walker with binary detection, symlink protection, encoding handling, and resource budget limits."""

import os
import time
from pathlib import Path
from typing import Generator, List, Optional, Set, Tuple
from .models import SkippedFile

DEFAULT_MAX_FILE_SIZE = 5 * 1024 * 1024       # 5 MB per file
DEFAULT_MAX_TOTAL_BYTES = 100 * 1024 * 1024   # 100 MB aggregate across all files
DEFAULT_MAX_TOTAL_FILES = 5000                # 5,000 total files max
DEFAULT_MAX_DIRECTORY_DEPTH = 20              # Max recursion depth
DEFAULT_IGNORED_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".next", "dist", "build", ".turbo"}
DEFAULT_IGNORED_FILES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "Cargo.lock",
    "composer.lock",
    "Gemfile.lock",
}
BINARY_SAMPLE_SIZE = 8192                     # 8 KB sample for binary detection


class ScanBudgetExceeded(Exception):
    """Raised when untrusted package scan limits (file count, depth, size, timeout) are exceeded."""
    pass


def is_binary_content(raw_bytes: bytes) -> Tuple[bool, str]:
    """Detects whether raw file bytes represent a binary file or text file.
    
    Handles UTF-8, UTF-16 (LE/BE), and UTF-8 BOM encodings.
    
    Returns:
        Tuple of (is_binary: bool, detected_encoding: str).
    """
    if not raw_bytes:
        return False, "utf-8"
        
    # Check for UTF-16 BOMs
    if raw_bytes.startswith(b"\xff\xfe") or raw_bytes.startswith(b"\xfe\xff"):
        return False, "utf-16"
        
    # Check for UTF-8 BOM
    if raw_bytes.startswith(b"\xef\xbb\xbf"):
        return False, "utf-8-sig"
        
    # If null byte is present without UTF-16 BOM, treat as binary
    if b"\x00" in raw_bytes:
        return True, "binary"
        
    # Try UTF-8 decoding
    try:
        raw_bytes.decode("utf-8")
        return False, "utf-8"
    except UnicodeDecodeError:
        # Fallback to Latin-1 for non-null byte 8-bit text encodings
        try:
            raw_bytes.decode("latin-1")
            return False, "latin-1"
        except Exception:
            return True, "binary"


def read_text_file(path: str) -> Tuple[bool, str, str, int]:
    """Reads a file safely handling various text encodings.
    
    Returns:
        Tuple of (success: bool, content_or_empty: str, skip_reason_or_encoding: str, byte_count: int)
    """
    try:
        with open(path, "rb") as f:
            sample = f.read(BINARY_SAMPLE_SIZE)
            is_bin, encoding = is_binary_content(sample)
            if is_bin:
                return False, "", "binary", len(sample)
                
            f.seek(0)
            full_bytes = f.read()
            byte_count = len(full_bytes)
            
        # Decode using determined encoding with graceful fallbacks
        try:
            content = full_bytes.decode(encoding)
            return True, content, encoding, byte_count
        except (UnicodeDecodeError, LookupError):
            try:
                content = full_bytes.decode("latin-1")
                return True, content, "latin-1", byte_count
            except Exception as e:
                return False, "", f"decode_error: {type(e).__name__}", byte_count
    except PermissionError:
        return False, "", "permission_denied", 0
    except Exception as e:
        return False, "", f"read_error: {type(e).__name__}", 0


def calculate_depth(root_path: Path, current_path: Path) -> int:
    """Calculates directory nesting depth relative to the root directory."""
    try:
        rel = current_path.relative_to(root_path)
        if str(rel) == ".":
            return 0
        return len(rel.parts)
    except ValueError:
        return 0


def walk_directory(
    root_dir: str,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_total_files: int = DEFAULT_MAX_TOTAL_FILES,
    max_depth: int = DEFAULT_MAX_DIRECTORY_DEPTH,
    timeout_seconds: Optional[float] = None,
    start_time: Optional[float] = None,
    ignored_dirs: Optional[Set[str]] = None,
    ignored_files: Optional[Set[str]] = None,
    follow_symlinks: bool = False
) -> Generator[Tuple[str, str], None, List[SkippedFile]]:
    """Recursively walks a directory yielding (file_path, content) for valid text files.
    
    Enforces strict adversarial protection budgets:
      - Max file size
      - Max total decompressed bytes across the entire scan
      - Max file count
      - Max directory recursion depth
      - Max wall-clock execution time
      - Symlink refusal by default
      
    Yields:
        (file_path, file_content) for each scanned text file.
        
    Returns:
        List of SkippedFile objects for skipped files/directories.
        
    Raises:
        ScanBudgetExceeded: If any resource limit is breached (fails closed).
    """
    if ignored_dirs is None:
        ignored_dirs = set(DEFAULT_IGNORED_DIRS)
    if ignored_files is None:
        ignored_files = set(DEFAULT_IGNORED_FILES)
        
    if start_time is None:
        start_time = time.monotonic()
        
    skipped: List[SkippedFile] = []
    root_path = Path(root_dir).resolve()
    
    if not root_path.exists():
        raise FileNotFoundError(f"Scan directory not found: {root_dir}")
        
    if not root_path.is_dir():
        raise NotADirectoryError(f"Target path is not a directory: {root_dir}")

    total_files_encountered = 0
    total_bytes_processed = 0

    for current_root, dirs, files in os.walk(str(root_path), followlinks=follow_symlinks):
        curr_path = Path(current_root)
        
        # Check timeout
        if timeout_seconds is not None and (time.monotonic() - start_time) > timeout_seconds:
            raise ScanBudgetExceeded(f"Scan wall-clock time limit exceeded ({timeout_seconds:.1f}s)")
            
        # Check directory depth
        depth = calculate_depth(root_path, curr_path)
        if depth > max_depth:
            raise ScanBudgetExceeded(f"Directory depth limit exceeded ({depth} > {max_depth}) at {current_root}")

        # 1. Prune ignored directories and symlinks in-place
        dirs_to_remove = []
        for d in dirs:
            dir_path = os.path.join(current_root, d)
            if not follow_symlinks and os.path.islink(dir_path):
                skipped.append(SkippedFile(file_path=dir_path, reason="symlink"))
                dirs_to_remove.append(d)
            elif d in ignored_dirs:
                skipped.append(SkippedFile(file_path=dir_path, reason="ignored_directory"))
                dirs_to_remove.append(d)
                
        for d in dirs_to_remove:
            dirs.remove(d)
            
        # 2. Process files in current directory
        for f in files:
            # Check timeout during file loops
            if timeout_seconds is not None and (time.monotonic() - start_time) > timeout_seconds:
                raise ScanBudgetExceeded(f"Scan wall-clock time limit exceeded ({timeout_seconds:.1f}s)")

            total_files_encountered += 1
            if total_files_encountered > max_total_files:
                raise ScanBudgetExceeded(f"Total file count limit exceeded ({total_files_encountered} > {max_total_files})")
                
            file_path = os.path.join(current_root, f)
            
            # Check ignored lockfiles / files
            if f in ignored_files:
                skipped.append(SkippedFile(file_path=file_path, reason="ignored_lockfile"))
                continue

            # Check symlink
            if not follow_symlinks and os.path.islink(file_path):
                skipped.append(SkippedFile(file_path=file_path, reason="symlink"))
                continue
                
            # Check individual file size
            try:
                stat_info = os.lstat(file_path) if not follow_symlinks else os.stat(file_path)
                file_size = stat_info.st_size
            except Exception as e:
                skipped.append(SkippedFile(file_path=file_path, reason=f"stat_error: {type(e).__name__}"))
                continue
                
            if file_size > max_file_size:
                skipped.append(SkippedFile(file_path=file_path, reason=f"size_limit_exceeded ({file_size} > {max_file_size})"))
                continue
                
            # Read file content safely
            success, content, reason, byte_count = read_text_file(file_path)
            
            total_bytes_processed += byte_count
            if total_bytes_processed > max_total_bytes:
                raise ScanBudgetExceeded(f"Total scan size limit exceeded ({total_bytes_processed} > {max_total_bytes} bytes)")
                
            if not success:
                skipped.append(SkippedFile(file_path=file_path, reason=reason))
                continue
                
            yield (file_path, content)
            
    return skipped
