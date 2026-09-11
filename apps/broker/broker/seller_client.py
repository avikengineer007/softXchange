"""
apps/broker/broker/seller_client.py

Server-to-server client for proactive draft generation with seller-assist.
Implements fail-soft resilience: drafting failures or guardrail refusals
never block or corrupt question routing.
"""

from typing import Optional, Dict, Any
import logging
import httpx

from broker.config import settings

logger = logging.getLogger("broker.seller_client")


class SellerAssistClient:
    """
    Internal HTTP client communicating with apps/seller-assist over the network.
    Uses internal service authentication.
    """

    def __init__(self, base_url: Optional[str] = None, timeout: float = 5.0):
        self.base_url = (base_url or settings.SELLER_ASSIST_URL).rstrip("/")
        self.timeout = timeout

    def trigger_draft_reply(
        self,
        question_id: str,
        forced_reply_for_test: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Calls POST /assist/seller/questions/{question_id}/draft-reply on seller-assist.
        Fails soft: returns None if drafting fails or is refused by guardrails.
        """
        url = f"{self.base_url}/assist/seller/questions/{question_id}/draft-reply"
        headers = {
            "Content-Type": "application/json",
            "X-Internal-Service": "broker",
        }
        payload = {}
        if forced_reply_for_test:
            payload["forced_reply_for_test"] = forced_reply_for_test

        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.post(url, headers=headers, json=payload if payload else None)
                if res.status_code == 200:
                    data = res.json()
                    logger.info(f"Successfully pre-generated draft reply for question {question_id}")
                    return data
                elif res.status_code == 422:
                    logger.warning(
                        f"Guardrail intercepted draft reply for question {question_id}: {res.text}"
                    )
                    return None
                else:
                    logger.warning(
                        f"Seller-assist returned HTTP {res.status_code} for question {question_id}: {res.text}"
                    )
                    return None
        except Exception as exc:
            # Degraded experience: seller starts from blank reply; question remains safely routed
            logger.warning(
                f"Proactive draft generation failed for question {question_id} (will degrade to manual drafting): {exc}"
            )
            return None


seller_client = SellerAssistClient()
