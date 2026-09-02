"""Matcher interfaces and implementations for static analysis rules.

Includes:
  - BaseMatcher: Extensible abstract base class (ready for AST matchers in Phase 2).
  - RegexMatcher: ReDoS-bounded regex pattern matcher with optional exclusion patterns.
  - ContextAwareRegexMatcher: Proximity-based heuristic matcher for context-dependent rules.
  - ObfuscationMatcher: Heuristic matcher for packed/obfuscated code outside build paths.
"""

import os
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional, Pattern, Set, Tuple, Union

from .sanitizer import sanitize_snippet

# Default maximum line length cap to prevent ReDoS against adversarial/minified inputs
DEFAULT_MAX_LINE_LENGTH = 10_000
DEFAULT_MAX_MULTILINE_BYTES = 500_000


@dataclass(frozen=True)
class MatchResult:
    """Outcome of a successful rule match on a source file.
    
    Attributes:
        line_number: 1-indexed line number in source file.
        snippet: Credential-scrubbed, length-bounded snippet suitable for reports.
        matched_text: Raw matched substring.
    """
    line_number: int
    snippet: str
    matched_text: str


class BaseMatcher(ABC):
    """Abstract base class for all rule matchers (regex, AST, heuristic)."""

    @abstractmethod
    def match(self, content: str, file_path: str) -> List[MatchResult]:
        """Evaluates matcher against source content.
        
        Args:
            content: Entire text content of the file.
            file_path: Relative or absolute path to the file.
            
        Returns:
            List of MatchResult objects for each detection.
        """
        pass


class RegexMatcher(BaseMatcher):
    """Deterministic regex pattern matcher with ReDoS protection and snippet sanitization.
    
    Guarantees:
      - Per-line length capping (`max_line_length`) prevents catastrophic backtracking
        on minified or adversarial lines (matching git_history diff caps).
      - Optional `exclude_pattern` to skip literal or constant arguments.
      - All extracted snippets are passed through `sanitize_snippet` to scrub any
        embedded credentials (e.g. basic auth in curl commands or inline tokens).
    """

    def __init__(
        self,
        pattern: Union[str, Pattern[str]],
        flags: int = 0,
        multiline: bool = False,
        exclude_pattern: Optional[Union[str, Pattern[str]]] = None,
        check_capture_group: Optional[int] = None,
        max_line_length: int = DEFAULT_MAX_LINE_LENGTH,
        max_multiline_bytes: int = DEFAULT_MAX_MULTILINE_BYTES,
        context_window: int = 40,
        max_snippet_length: int = 160,
    ) -> None:
        self.regex = re.compile(pattern, flags) if isinstance(pattern, str) else pattern
        self.exclude_regex = (
            re.compile(exclude_pattern, flags) if isinstance(exclude_pattern, str) else exclude_pattern
        )
        self.check_capture_group = check_capture_group
        self.multiline = multiline
        self.max_line_length = max_line_length
        self.max_multiline_bytes = max_multiline_bytes
        self.context_window = context_window
        self.max_snippet_length = max_snippet_length

    def match(self, content: str, file_path: str) -> List[MatchResult]:
        """Matches regex against content with safety bounds."""
        if not content:
            return []

        results: List[MatchResult] = []

        if not self.multiline:
            lines = content.splitlines()
            for line_idx, line in enumerate(lines, start=1):
                bounded_line = line[:self.max_line_length] if len(line) > self.max_line_length else line

                for match in self.regex.finditer(bounded_line):
                    # Check exclusion pattern if specified
                    if self.exclude_regex:
                        target = (
                            match.group(self.check_capture_group)
                            if self.check_capture_group and match.lastindex and match.lastindex >= self.check_capture_group
                            else match.group(0)
                        )
                        if target and self.exclude_regex.search(target):
                            continue

                    start, end = match.start(), match.end()
                    safe_snippet = sanitize_snippet(
                        line,
                        (start, end),
                        context_window=self.context_window,
                        max_length=self.max_snippet_length,
                    )
                    results.append(
                        MatchResult(
                            line_number=line_idx,
                            snippet=safe_snippet,
                            matched_text=match.group(0),
                        )
                    )
        else:
            bounded_content = content[:self.max_multiline_bytes]
            for match in self.regex.finditer(bounded_content):
                if self.exclude_regex:
                    target = (
                        match.group(self.check_capture_group)
                        if self.check_capture_group and match.lastindex and match.lastindex >= self.check_capture_group
                        else match.group(0)
                    )
                    if target and self.exclude_regex.search(target):
                        continue

                start, end = match.start(), match.end()
                line_idx = content.count("\n", 0, start) + 1
                line_start = content.rfind("\n", 0, start) + 1
                line_end = content.find("\n", end)
                if line_end == -1:
                    line_end = len(content)
                line = content[line_start:line_end]

                col_start = start - line_start
                col_end = end - line_start

                safe_snippet = sanitize_snippet(
                    line,
                    (col_start, col_end),
                    context_window=self.context_window,
                    max_length=self.max_snippet_length,
                )
                results.append(
                    MatchResult(
                        line_number=line_idx,
                        snippet=safe_snippet,
                        matched_text=match.group(0),
                    )
                )

        return results


class ContextAwareRegexMatcher(BaseMatcher):
    """Matches a target pattern only when network or untrusted context keywords are present nearby.
    
    Used for context-dependent heuristics (like untrusted pickle deserialization)
    to limit false positives on purely internal serialization.
    """

    def __init__(
        self,
        pattern: Union[str, Pattern[str]],
        context_keywords: Set[str],
        context_window_lines: int = 5,
        exclude_pattern: Optional[Union[str, Pattern[str]]] = None,
        max_line_length: int = DEFAULT_MAX_LINE_LENGTH,
    ) -> None:
        self.regex = re.compile(pattern) if isinstance(pattern, str) else pattern
        self.exclude_regex = (
            re.compile(exclude_pattern) if isinstance(exclude_pattern, str) else exclude_pattern
        )
        self.context_keywords = {k.lower() for k in context_keywords}
        self.context_window_lines = context_window_lines
        self.max_line_length = max_line_length

    def match(self, content: str, file_path: str) -> List[MatchResult]:
        if not content:
            return []

        results: List[MatchResult] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines):
            bounded_line = line[:self.max_line_length] if len(line) > self.max_line_length else line
            match = self.regex.search(bounded_line)
            if not match:
                continue

            if self.exclude_regex and self.exclude_regex.search(match.group(0)):
                continue

            # Check context window (previous N lines + current line)
            start_window = max(0, idx - self.context_window_lines)
            surrounding_text = " ".join(lines[start_window:idx + 1]).lower()

            has_context = any(kw in surrounding_text for kw in self.context_keywords)
            if has_context:
                snippet = sanitize_snippet(line, (match.start(), match.end()))
                results.append(
                    MatchResult(
                        line_number=idx + 1,
                        snippet=snippet,
                        matched_text=match.group(0),
                    )
                )

        return results


class ObfuscationMatcher(BaseMatcher):
    r"""Heuristic matcher for packed or heavily obfuscated code in JS/TS.
    
    Skips build and bundle paths (dist/, build/, node_modules/, vendor/, .min.js).
    Flags:
      1. Known packers: eval(function(p,a,c,k,e,d)...)
      2. Extremely long single-line files with dense hex escape sequences (\\x..).
    """

    EXCLUDED_PATH_SUBSTRINGS = (
        "/dist/", "\\dist\\",
        "/build/", "\\build\\",
        "/node_modules/", "\\node_modules\\",
        "/vendor/", "\\vendor\\",
        "/out/", "\\out\\",
        ".min.js", ".bundle.js",
    )

    PACKED_JS_REGEX = re.compile(r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)")
    HEX_ESCAPE_REGEX = re.compile(r"\\x[0-9a-fA-F]{2}")

    def __init__(self, min_line_length: int = 1500, min_hex_escapes: int = 15) -> None:
        self.min_line_length = min_line_length
        self.min_hex_escapes = min_hex_escapes

    def match(self, content: str, file_path: str) -> List[MatchResult]:
        if not content:
            return []

        # Normalize with forward slashes and ensure leading slash for prefix checks
        norm_path = "/" + file_path.replace("\\", "/").strip("/").lower()
        if (
            "/dist/" in norm_path or norm_path.startswith("/dist/")
            or "/build/" in norm_path or norm_path.startswith("/build/")
            or "/node_modules/" in norm_path or norm_path.startswith("/node_modules/")
            or "/vendor/" in norm_path or norm_path.startswith("/vendor/")
            or "/out/" in norm_path or norm_path.startswith("/out/")
            or norm_path.endswith(".min.js")
            or norm_path.endswith(".bundle.js")
        ):
            return []

        results: List[MatchResult] = []
        lines = content.splitlines()

        # Check 1: Packed JS wrapper
        for idx, line in enumerate(lines, start=1):
            match = self.PACKED_JS_REGEX.search(line)
            if match:
                snippet = sanitize_snippet(line, (match.start(), match.end()), max_length=120)
                results.append(
                    MatchResult(
                        line_number=idx,
                        snippet=snippet,
                        matched_text="Packed JavaScript (p,a,c,k,e,d)",
                    )
                )
                return results

        # Check 2: Dense hex escapes on long minified-looking lines outside build
        for idx, line in enumerate(lines, start=1):
            if len(line) >= self.min_line_length:
                hex_matches = self.HEX_ESCAPE_REGEX.findall(line)
                if len(hex_matches) >= self.min_hex_escapes:
                    match_pos = line.find("\\x")
                    snippet = sanitize_snippet(line, (max(0, match_pos), max(0, match_pos) + 20), max_length=120)
                    results.append(
                        MatchResult(
                            line_number=idx,
                            snippet=snippet,
                            matched_text=f"Obfuscated code with {len(hex_matches)} hex escapes",
                        )
                    )
                    return results

        return results
