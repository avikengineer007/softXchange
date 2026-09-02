"""Shannon entropy calculations and charset-aware token evaluation."""

import collections
import math
import re
from typing import Dict, List, Optional, Tuple

# Regex to find quoted string literals and long unquoted tokens
QUOTED_STRING_PATTERN = re.compile(r"""(?:'([^'\\]*(?:\\.[^'\\]*)*)'|"([^"\\]*(?:\\.[^"\\]*)*)"|`([^`\\]*(?:\\.[^`\\]*)*)`)""")
UNQUOTED_TOKEN_PATTERN = re.compile(r"""\b([A-Za-z0-9_\-+/=]{20,})\b""")

# Charset definitions
HEX_CHARSET = set("0123456789abcdefABCDEF")
BASE64_CHARSET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-")

# Default thresholds
DEFAULT_HEX_THRESHOLD = 3.0
DEFAULT_BASE64_THRESHOLD = 4.5
DEFAULT_MIN_LEN = 20


def calculate_shannon_entropy(data: str) -> float:
    """Calculates Shannon entropy in bits per character: -sum(p * log2(p)).
    
    Args:
        data: Input string to measure.
        
    Returns:
        Entropy float value >= 0.0.
    """
    if not data:
        return 0.0
    
    length = len(data)
    counts = collections.Counter(data)
    entropy = 0.0
    
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
        
    return entropy


def detect_charset(token: str) -> str:
    """Classifies token into 'hex', 'base64', or 'general'.
    
    Args:
        token: Candidate secret token.
        
    Returns:
        Charset identifier ('hex', 'base64', or 'general').
    """
    token_chars = set(token)
    if token_chars.issubset(HEX_CHARSET):
        return "hex"
    if token_chars.issubset(BASE64_CHARSET):
        return "base64"
    return "general"


def is_high_entropy_token(
    token: str,
    thresholds: Optional[Dict[str, float]] = None,
    min_length: int = DEFAULT_MIN_LEN
) -> Tuple[bool, float, str]:
    """Determines whether a token is considered a high-entropy secret.
    
    Uses charset-specific thresholds to avoid false positives on base64
    or false negatives on hex tokens.
    
    Args:
        token: Candidate string token.
        thresholds: Dict mapping charset ('hex', 'base64', 'general') to threshold.
        min_length: Minimum length required for evaluation (default 20).
        
    Returns:
        Tuple of (is_high_entropy: bool, entropy_score: float, detected_charset: str).
    """
    if len(token) < min_length:
        return False, 0.0, "short"
    
    charset = detect_charset(token)
    
    thresh_map = {
        "hex": DEFAULT_HEX_THRESHOLD,
        "base64": DEFAULT_BASE64_THRESHOLD,
        "general": DEFAULT_BASE64_THRESHOLD,
    }
    if thresholds:
        thresh_map.update(thresholds)
        
    threshold = thresh_map.get(charset, DEFAULT_BASE64_THRESHOLD)
    score = calculate_shannon_entropy(token)
    
    return score >= threshold, score, charset


def extract_entropy_candidates(line: str, min_length: int = DEFAULT_MIN_LEN) -> List[Tuple[str, int, int]]:
    """Extracts quoted string contents and standalone tokens from a line.
    
    Returns:
        List of (token_content, start_index, end_index) within the line.
    """
    candidates: List[Tuple[str, int, int]] = []
    seen_spans = set()
    
    # 1. Quoted literals
    for match in QUOTED_STRING_PATTERN.finditer(line):
        # Find which quote group matched
        for group_idx in range(1, 4):
            val = match.group(group_idx)
            if val is not None:
                start = match.start(group_idx)
                end = match.end(group_idx)
                if len(val) >= min_length:
                    candidates.append((val, start, end))
                    seen_spans.add((start, end))
                break
                
    # 2. Unquoted long tokens
    for match in UNQUOTED_TOKEN_PATTERN.finditer(line):
        val = match.group(1)
        start = match.start(1)
        end = match.end(1)
        
        # Avoid duplicating if inside an already processed quoted string
        is_overlapping = any(
            q_start <= start and end <= q_end for q_start, q_end in seen_spans
        )
        if not is_overlapping and len(val) >= min_length:
            candidates.append((val, start, end))
            
    return candidates
