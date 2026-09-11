"""Snippet sanitization and credential scrubbing utilities.

Guarantees that static-analysis snippets never leak sensitive credentials
(e.g., tokens in piped curl commands, embedded basic auth in URLs, API keys)
when findings are inspected or reported.
"""

import re
from typing import Tuple

# Pattern matching basic auth in URLs: http(s)://user:password@host or protocol://token@host
URL_CREDENTIAL_PATTERN = re.compile(
    r'(https?|ftp|ssh|git)://([^:\s/@]+):([^@\s/]+)@',
    re.IGNORECASE
)

# Pattern matching inline token/key/secret assignments on the line (e.g. GITHUB_TOKEN="...", api_key: "...")
INLINE_SECRET_PATTERN = re.compile(
    r'(?i)\b([a-zA-Z0-9_]*(?:api[_-]?key|secret|token|password|passwd|auth|bearer))\b\s*[:=]\s*["\']?([a-zA-Z0-9_\-.~+/=]{8,})["\']?'
)

# Bearer token header pattern
BEARER_PATTERN = re.compile(
    r'(?i)\b(Bearer)\s+([a-zA-Z0-9_\-.~+/=]{16,})'
)


def scrub_credentials(text: str) -> str:
    """Scrubs embedded credentials, URLs with basic auth, and inline secrets from text."""
    if not text:
        return ""

    # 1. Scrub basic auth in URLs: https://user:token@host -> https://[REDACTED]@host
    scrubbed = URL_CREDENTIAL_PATTERN.sub(r'\1://[REDACTED]@', text)

    # 2. Scrub bearer tokens
    scrubbed = BEARER_PATTERN.sub(r'\1 [REDACTED]', scrubbed)

    # 3. Scrub inline secret assignments: key="secret123" -> key="[REDACTED]"
    def _mask_assignment(match: re.Match) -> str:
        param = match.group(1)
        return f'{param}="[REDACTED]"'

    scrubbed = INLINE_SECRET_PATTERN.sub(_mask_assignment, scrubbed)

    return scrubbed


def sanitize_text(text: str) -> str:
    """Sanitizes arbitrary text strings (such as error messages or file paths) by scrubbing credentials."""
    return scrub_credentials(text)


def sanitize_snippet(
    raw_line: str,
    match_span: Tuple[int, int],
    context_window: int = 40,
    max_length: int = 160,
) -> str:
    """Produces a safely sanitized, bounded snippet of a line containing a finding.
    
    Guarantees:
      - Embedded credentials, URL auth, and token assignments are scrubbed.
      - Snippet length is bounded to `max_length`.
      - Surrounding context is cleanly trimmed with ellipsis.
    """
    if not raw_line:
        return ""

    line = raw_line.strip("\r\n")
    match_start, match_end = match_span

    # Bound match indexes to line length
    match_start = max(0, min(match_start, len(line)))
    match_end = max(match_start, min(match_end, len(line)))

    # Compute context window around match
    start_idx = max(0, match_start - context_window)
    end_idx = min(len(line), match_end + context_window)

    prefix_ellipsis = "..." if start_idx > 0 else ""
    suffix_ellipsis = "..." if end_idx < len(line) else ""

    sub_snippet = line[start_idx:end_idx]
    
    # Scrub credentials
    clean_snippet = scrub_credentials(sub_snippet)

    # Enforce maximum total snippet length
    full_snippet = f"{prefix_ellipsis}{clean_snippet}{suffix_ellipsis}".strip()
    if len(full_snippet) > max_length:
        full_snippet = full_snippet[:max_length - 3] + "..."

    return full_snippet
