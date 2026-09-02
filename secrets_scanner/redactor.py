"""Redaction and safe string sanitization utilities."""

def redact_secret(value: str, prefix_len: int = 4, suffix_len: int = 4, mask_char: str = "*") -> str:
    """Redacts a sensitive secret string.
    
    Shows only the first 4 and last 4 characters, masking all middle characters.
    If the string length is <= 8 (prefix_len + suffix_len), it is masked entirely
    to avoid leaking too much of the secret.
    
    Args:
        value: The sensitive string.
        prefix_len: Number of characters to preserve at start (default 4).
        suffix_len: Number of characters to preserve at end (default 4).
        mask_char: Character used to mask middle content (default '*').
        
    Returns:
        Redacted string.
    """
    if not value:
        return ""
    
    val_len = len(value)
    if val_len <= (prefix_len + suffix_len):
        return mask_char * max(val_len, 8)
    
    middle_len = val_len - prefix_len - suffix_len
    return value[:prefix_len] + (mask_char * middle_len) + value[-suffix_len:]


def redact_line_snippet(
    line: str,
    match_start: int,
    match_end: int,
    context_window: int = 40,
    prefix_len: int = 4,
    suffix_len: int = 4
) -> str:
    """Produces a safely redacted snippet of a line containing a secret.
    
    Redacts the secret match within the line, and optionally trims surrounding
    context to keep snippets concise and readable.
    
    Args:
        line: The full line of text.
        match_start: Starting character index of the secret.
        match_end: Ending character index of the secret.
        context_window: Max characters to show before and after match.
        prefix_len: Unmasked prefix length for secret.
        suffix_len: Unmasked suffix length for secret.
        
    Returns:
        Redacted snippet string.
    """
    secret = line[match_start:match_end]
    redacted = redact_secret(secret, prefix_len=prefix_len, suffix_len=suffix_len)
    
    # Context boundaries
    start_idx = max(0, match_start - context_window)
    end_idx = min(len(line), match_end + context_window)
    
    prefix = line[start_idx:match_start]
    suffix = line[match_end:end_idx]
    
    prefix_ellipsis = "..." if start_idx > 0 else ""
    suffix_ellipsis = "..." if end_idx < len(line) else ""
    
    snippet = f"{prefix_ellipsis}{prefix}{redacted}{suffix}{suffix_ellipsis}"
    return snippet.strip()
