"""Allowlist mechanism for safely suppressing accepted findings and known false positives."""

import fnmatch
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional, Pattern, Union


@dataclass(frozen=True)
class AllowlistEntry:
    """An accepted rule-id + file-path combination.
    
    Attributes:
        rule_id: The specific rule ID to allow (e.g. 'AWS_ACCESS_KEY_ID') or '*' for all rules.
        file_path: Path or glob pattern of the accepted file (e.g. 'tests/fixtures/**', '*.env.example').
        reason: Human-readable rationale for the accepted exception.
    """
    rule_id: str
    file_path: str
    reason: str = "Accepted false positive"


def normalize_pattern_path(path_str: str) -> str:
    """Normalizes and canonicalizes a path pattern, preventing path traversal escapes.
    
    Args:
        path_str: Target path or glob pattern.
        
    Returns:
        Forward-slash normalized path string.
        
    Raises:
        ValueError: If path attempts directory traversal escaping (e.g. starting with ../).
    """
    cleaned = path_str.strip().replace("\\", "/")
    
    # Strip leading ./
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
        
    # Check for dangerous path traversal outside scope
    parts = cleaned.split("/")
    depth = 0
    for p in parts:
        if p == "..":
            depth -= 1
            if depth < 0:
                raise ValueError(f"Path traversal escape detected in allowlist entry: {path_str}")
        elif p and p not in (".", "*", "**"):
            depth += 1
            
    return cleaned


def _glob_to_regex(pattern: str) -> Pattern[str]:
    """Compiles a glob pattern supporting ** into a strict regex."""
    i, n = 0, len(pattern)
    res = []
    while i < n:
        c = pattern[i]
        if c == "*":
            if i + 1 < n and pattern[i + 1] == "*":
                # Double wildcard: match zero or more path segments
                i += 2
                if i < n and pattern[i] == "/":
                    i += 1
                    res.append(r"(?:.*/)?")
                else:
                    res.append(r".*")
            else:
                # Single wildcard: match characters within single segment
                i += 1
                res.append(r"[^/]*")
        elif c == "?":
            i += 1
            res.append(r"[^/]")
        else:
            res.append(re.escape(c))
            i += 1
    return re.compile(r"^" + "".join(res) + r"$")


def path_matches_pattern(file_path: str, pattern: str) -> bool:
    """Safely determines whether a normalized file path matches an allowlist pattern.
    
    Handles exact matches, basename matches, relative path suffixes, and globs (including **).
    """
    norm_file = file_path.replace("\\", "/").strip()
    while norm_file.startswith("./"):
        norm_file = norm_file[2:]
        
    norm_pat = pattern.replace("\\", "/").strip()
    while norm_pat.startswith("./"):
        norm_pat = norm_pat[2:]
        
    # Exact match
    if norm_file == norm_pat:
        return True
        
    # Basename match if pattern has no directory separators
    if "/" not in norm_pat:
        if fnmatch.fnmatch(os.path.basename(norm_file), norm_pat):
            return True
            
    # Suffix match (e.g. pattern 'fixtures/test.py' matches 'project/tests/fixtures/test.py')
    if norm_file.endswith("/" + norm_pat):
        return True
        
    # Full glob match
    try:
        regex = _glob_to_regex(norm_pat)
        if regex.match(norm_file):
            return True
    except Exception:
        pass
        
    # Suffix glob match (e.g. pattern 'fixtures/**' matches 'tests/fixtures/aws.py')
    try:
        suffix_regex = _glob_to_regex(f"**/{norm_pat}")
        if suffix_regex.match(norm_file):
            return True
    except Exception:
        pass

    # PurePosixPath fallback
    try:
        if PurePosixPath(norm_file).match(norm_pat):
            return True
    except Exception:
        pass

    return False


class AllowlistConfig:
    """Manages allowed secret findings based on rule IDs and normalized file paths."""
    
    def __init__(self, entries: Optional[List[AllowlistEntry]] = None):
        self.entries: List[AllowlistEntry] = entries or []
        
    @classmethod
    def from_file(cls, config_path: Union[str, Path]) -> "AllowlistConfig":
        """Loads and parses an allowlist config file from disk safely.
        
        Args:
            config_path: Path to the JSON configuration file.
            
        Returns:
            AllowlistConfig instance.
            
        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If file content is invalid or corrupted.
        """
        path = Path(config_path)
        if not path.is_file():
            raise FileNotFoundError(f"Allowlist config file not found: {config_path}")
            
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to parse allowlist JSON file {config_path}: {e}")
            
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: Union[Dict[str, Any], List[Dict[str, Any]]]) -> "AllowlistConfig":
        """Creates an AllowlistConfig from raw parsed JSON dictionary or list."""
        raw_entries: List[Dict[str, Any]] = []
        if isinstance(data, list):
            raw_entries = data
        elif isinstance(data, dict):
            if "accepted_findings" in data and isinstance(data["accepted_findings"], list):
                raw_entries = data["accepted_findings"]
            elif "allowlist" in data and isinstance(data["allowlist"], list):
                raw_entries = data["allowlist"]
            else:
                raise ValueError("Allowlist config dict must contain 'allowlist' or 'accepted_findings' list")
        else:
            raise ValueError("Allowlist config must be a JSON object or array")

        entries: List[AllowlistEntry] = []
        for item in raw_entries:
            if not isinstance(item, dict):
                continue
            rule_id = item.get("rule_id")
            file_path = item.get("file_path")
            reason = item.get("reason", "Accepted false positive")
            
            if not rule_id or not file_path:
                continue
                
            # Normalize path and validate safety
            normalized_path = normalize_pattern_path(str(file_path))
            entries.append(
                AllowlistEntry(
                    rule_id=str(rule_id).strip(),
                    file_path=normalized_path,
                    reason=str(reason).strip()
                )
            )

        return cls(entries)

    def match(self, rule_id: str, file_path: str) -> Optional[str]:
        """Checks whether a finding matches any entry in the allowlist.
        
        Args:
            rule_id: The ID of the detected rule.
            file_path: The file path where finding was detected.
            
        Returns:
            The suppression reason string if allowed, None otherwise.
        """
        for entry in self.entries:
            # Check rule ID match (* or exact case-insensitive match)
            if entry.rule_id != "*" and entry.rule_id.upper() != rule_id.upper():
                continue
                
            # Check path match
            if path_matches_pattern(file_path, entry.file_path):
                return entry.reason
                
        return None


def load_allowlist_config(source: Optional[Union[str, Path, AllowlistConfig, Dict[str, Any], List[Dict[str, Any]]]] = None) -> Optional[AllowlistConfig]:
    """Helper to convert any valid allowlist source into an AllowlistConfig object."""
    if source is None:
        return None
    if isinstance(source, AllowlistConfig):
        return source
    if isinstance(source, (str, Path)):
        return AllowlistConfig.from_file(source)
    if isinstance(source, (dict, list)):
        return AllowlistConfig.from_dict(source)
    raise TypeError(f"Unsupported allowlist source type: {type(source)}")
