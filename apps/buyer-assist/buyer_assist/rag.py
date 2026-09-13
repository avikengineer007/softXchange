"""
apps/buyer-assist/buyer_assist/rag.py

DEPRECATED LOCATION / BACKWARD-COMPATIBILITY RE-EXPORT ONLY:
This module re-exports ListingQAService and AnswerResult from ml_shared.rag — do not add new logic here!
Do NOT import from buyer_assist.rag in other microservices. Always import shared ML logic directly from ml_shared.rag.
"""

from ml_shared.rag import (
    ListingQAService,
    AnswerResult,
    _SECURITY_INTENT_PATTERNS,
    _SECURITY_INTENT_REGEX,
    _ADVERSARIAL_REASSURANCE_PATTERNS,
    _ADVERSARIAL_REGEX,
)

__all__ = [
    "ListingQAService",
    "AnswerResult",
    "_SECURITY_INTENT_PATTERNS",
    "_SECURITY_INTENT_REGEX",
    "_ADVERSARIAL_REASSURANCE_PATTERNS",
    "_ADVERSARIAL_REGEX",
]
