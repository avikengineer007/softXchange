"""Git commit history and diff streaming scanner."""

import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, List, Optional
from .walker import DEFAULT_MAX_TOTAL_BYTES


class GitHistoryScanError(Exception):
    """Raised when git execution, repository validation, or diff streaming fails."""
    pass


@dataclass(frozen=True)
class GitDiffLine:
    """Represents an added or modified line in a git commit diff.
    
    Attributes:
        commit_hash: 40-character hex commit identifier.
        file_path: Relative path of the modified/created file.
        line_number: 1-indexed line number of this line in the new commit tree.
        content: The text content of the added line (without leading '+').
    """
    commit_hash: str
    file_path: str
    line_number: int
    content: str


def is_git_repository(target_dir: str) -> bool:
    """Checks whether the target directory contains a .git repository."""
    git_dir = Path(target_dir) / ".git"
    return git_dir.exists()


def stream_git_diff_entries(
    repo_dir: str,
    max_commits: int = 500,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    timeout_seconds: Optional[float] = 30.0,
    max_line_length: int = 1024 * 1024,
) -> Iterator[GitDiffLine]:
    """Streams added and modified lines across git commit history with bounded resources.
    
    Guarantees:
        - Subprocess invocation strictly uses argument list and shell=False.
        - Streams diff line-by-line without buffering large histories in memory.
        - Bounded by wall-clock timeout and total decompressed diff bytes.
        - Accurately tracks file renames, file copies, and 1-indexed hunk line numbers.
        - Fails closed on any subprocess error or malformed repository.

    Args:
        repo_dir: Path to the target git repository.
        max_commits: Maximum number of commits to walk (default 500).
        max_total_bytes: Maximum total bytes of diff output allowed (default 100MB).
        timeout_seconds: Wall-clock timeout budget in seconds.
        max_line_length: Maximum allowed length for a single diff line (default 1MB).
        
    Yields:
        GitDiffLine objects for each line added in the history.
        
    Raises:
        GitHistoryScanError: If git command fails, times out, or output budget is exceeded.
    """
    resolved_dir = Path(repo_dir).resolve()
    if not resolved_dir.is_dir():
        raise GitHistoryScanError(f"Target path is not a directory: {resolved_dir}")
        
    if not is_git_repository(str(resolved_dir)):
        raise GitHistoryScanError(f"Not a git repository (missing .git): {resolved_dir}")

    # Parameterized command: strictly argument list, never shell=True
    cmd = ["git", "log", "-p", "-U0", f"--max-count={max_commits}"]

    start_time = time.monotonic()
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(resolved_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
        )
    except Exception as e:
        raise GitHistoryScanError(f"Failed to spawn git subprocess: {e}") from e

    total_bytes = 0
    current_commit: Optional[str] = None
    current_file: Optional[str] = None
    current_line_num: int = 0
    is_deleted_file: bool = False

    hunk_regex = re.compile(r"^@@\s+-[0-9]+(?:,[0-9]+)?\s+\+([0-9]+)(?:,[0-9]+)?\s+@@")

    try:
        while True:
            # Enforce active wall-clock timeout
            if timeout_seconds is not None and (time.monotonic() - start_time) >= timeout_seconds:
                proc.kill()
                proc.wait()
                raise GitHistoryScanError(
                    f"Git history scan exceeded wall-clock timeout ({timeout_seconds:.1f}s)"
                )

            # pyrefly: ignore [missing-attribute]
            line = proc.stdout.readline()
            if not line:
                break

            total_bytes += len(line.encode("utf-8", errors="replace"))
            if total_bytes > max_total_bytes:
                proc.kill()
                proc.wait()
                raise GitHistoryScanError(
                    f"Git history diff volume exceeded budget limit ({max_total_bytes} bytes)"
                )

            raw_line = line.rstrip("\r\n")
            if len(raw_line) > max_line_length:
                raw_line = raw_line[:max_line_length]

            # 1. Commit boundary
            if raw_line.startswith("commit "):
                current_commit = raw_line[7:].strip().split()[0]
                current_file = None
                current_line_num = 0
                is_deleted_file = False

            # 2. File diff header (e.g. diff --git a/path b/path)
            elif raw_line.startswith("diff --git "):
                match = re.match(r"^diff --git a/(.*) b/(.*)$", raw_line)
                if match:
                    current_file = match.group(2).replace("\\", "/")
                else:
                    current_file = None
                current_line_num = 0
                is_deleted_file = False

            # 3. Rename or copy header
            elif raw_line.startswith("rename to "):
                current_file = raw_line[10:].strip().replace("\\", "/")
            elif raw_line.startswith("copy to "):
                current_file = raw_line[8:].strip().replace("\\", "/")

            # 4. Destination file mode header
            elif raw_line.startswith("+++ b/"):
                current_file = raw_line[6:].strip().replace("\\", "/")
                is_deleted_file = False
            elif raw_line.startswith("+++ /dev/null"):
                is_deleted_file = True

            # 5. Hunk header: @@ -old_start,count +new_start,count @@
            elif raw_line.startswith("@@ "):
                match = hunk_regex.match(raw_line)
                if match:
                    current_line_num = int(match.group(1))

            # 6. Added content line
            elif raw_line.startswith("+"):
                # Avoid matching +++ file headers
                if raw_line.startswith("+++"):
                    continue
                if is_deleted_file or not current_file or not current_commit:
                    continue

                added_content = raw_line[1:]
                yield GitDiffLine(
                    commit_hash=current_commit,
                    file_path=current_file,
                    line_number=current_line_num,
                    content=added_content
                )
                current_line_num += 1

            # 7. Context lines (if any)
            elif raw_line.startswith(" "):
                current_line_num += 1

            # 8. Deleted lines (-) or file metadata do not advance current_line_num

        # Check process completion and exit status
        stderr_output = proc.stderr.read() if proc.stderr else ""
        returncode = proc.wait()

        if returncode != 0:
            raise GitHistoryScanError(
                f"git log command failed with exit code {returncode}: {stderr_output.strip()}"
            )

    except GitHistoryScanError:
        raise
    except Exception as e:
        proc.kill()
        proc.wait()
        raise GitHistoryScanError(f"Unexpected error while streaming git diffs: {e}") from e
    finally:
        try:
            if proc.stdout:
                proc.stdout.close()
        except Exception:
            pass
        try:
            if proc.stderr:
                proc.stderr.close()
        except Exception:
            pass
