import logging
import time
from typing import Optional, Dict, Any
import razorpay
import razorpay.errors

from src.config import settings

logger = logging.getLogger("payments-service.razorpay_client")


class RazorpayClient:
    """
    Dedicated client for Razorpay Orders, Route linked accounts, and Payment verification.
    payments-service is the sole custodian of Razorpay keys in softXchange.
    """
    def __init__(
        self,
        key_id: Optional[str] = None,
        key_secret: Optional[str] = None,
    ):
        self.key_id = key_id or settings.RAZORPAY_KEY_ID
        self.key_secret = key_secret or settings.RAZORPAY_KEY_SECRET
        self.client: Any = razorpay.Client(auth=(self.key_id, self.key_secret))

    def create_order(
        self,
        amount_minor_units: int,
        currency: str = "INR",
        receipt: Optional[str] = None,
        notes: Optional[Dict[str, Any]] = None,
        transfers: Optional[list] = None,
    ) -> Dict[str, Any]:
        """
        Creates a Razorpay order in integer minor units (paise: 1 INR = 100 paise).
        """
        params: Dict[str, Any] = {
            "amount": amount_minor_units,
            "currency": currency.upper(),
        }
        if receipt:
            params["receipt"] = receipt[:40]
        if notes:
            params["notes"] = notes
        if transfers:
            params["transfers"] = transfers

        try:
            order = self.client.order.create(data=params)
            logger.info(f"Created Razorpay order {order.get('id')} for amount {amount_minor_units} {currency}")
            return order
        except Exception as exc:
            if settings.ENVIRONMENT != "production":
                logger.warning(f"Razorpay order creation fallback in {settings.ENVIRONMENT}: {exc}")
                return {
                    "id": f"order_dev_mock_{int(time.time())}",
                    "entity": "order",
                    "amount": amount_minor_units,
                    "currency": currency.upper(),
                    "status": "created",
                    "receipt": receipt,
                    "notes": notes or {},
                }
            raise

    def verify_payment_signature(
        self,
        razorpay_order_id: str,
        razorpay_payment_id: str,
        razorpay_signature: str,
    ) -> bool:
        """
        Verifies payment signature using Razorpay's constant-time utility verification.
        Never uses manual or naive string comparisons.
        """
        if not razorpay_order_id or not razorpay_payment_id or not razorpay_signature:
            return False

        try:
            self.client.utility.verify_payment_signature({
                "razorpay_order_id": razorpay_order_id,
                "razorpay_payment_id": razorpay_payment_id,
                "razorpay_signature": razorpay_signature,
            })
            return True
        except (razorpay.errors.SignatureVerificationError, Exception) as exc:
            logger.warning(f"Razorpay payment signature verification failed: {exc}")
            return False

    def verify_webhook_signature(
        self,
        payload_bytes: bytes,
        signature: str,
        webhook_secret: Optional[str] = None,
    ) -> bool:
        """
        Validates Razorpay webhook X-Razorpay-Signature using raw request payload.
        Fails closed on missing or invalid signature.
        """
        if not signature or not payload_bytes:
            return False

        secret = webhook_secret or settings.RAZORPAY_WEBHOOK_SECRET
        try:
            body_str = payload_bytes.decode("utf-8")
            self.client.utility.verify_webhook_signature(body_str, signature, secret)
            return True
        except (razorpay.errors.SignatureVerificationError, Exception) as exc:
            logger.warning(f"Razorpay webhook signature verification failed: {exc}")
            return False

    def refund_payment(
        self,
        payment_id: str,
        amount_minor_units: Optional[int] = None,
        notes: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Issues a refund via Razorpay for the specified payment ID.
        """
        params: Dict[str, Any] = {}
        if amount_minor_units:
            params["amount"] = amount_minor_units
        if notes:
            params["notes"] = notes

        try:
            return self.client.payment.refund(payment_id, data=params if params else None)
        except Exception as exc:
            if settings.ENVIRONMENT != "production" and ("mock" in payment_id or payment_id.startswith("pay_dev_mock")):
                logger.warning(f"Simulating dev mock refund for {payment_id}")
                return {
                    "id": f"rfnd_dev_mock_{int(time.time())}",
                    "entity": "refund",
                    "payment_id": payment_id,
                    "status": "processed",
                }
            raise

    def create_linked_account(
        self,
        user_id: str,
        email: Optional[str] = None,
        legal_business_name: Optional[str] = None,
        contact_name: Optional[str] = None,
        phone: Optional[str] = None,
    ) -> str:
        """
        Creates a Razorpay Route linked account for a marketplace seller.
        """
        params: Dict[str, Any] = {
            "email": email or f"seller_{user_id[:8]}@softxchange.io",
            "type": "route",
            "legal_business_name": legal_business_name or f"SoftXchange Seller {user_id[:8]}",
            "customer_facing_business_name": contact_name or f"Seller {user_id[:8]}",
            "notes": {"user_id": user_id},
        }
        if phone:
            params["phone"] = phone

        try:
            account = self.client.account.create(data=params)
            account_id = account.get("id")
            logger.info(f"Created Razorpay Route linked account {account_id} for seller {user_id}")
            return account_id
        except Exception as exc:
            if settings.ENVIRONMENT != "production":
                logger.warning(f"Razorpay linked account creation fallback in {settings.ENVIRONMENT} for {user_id}: {exc}")
                return f"acc_dev_mock_{user_id.replace('-', '')[:16]}"
            raise

    def get_account(self, account_id: str) -> Dict[str, Any]:
        """
        Queries Razorpay Route linked account status.
        """
        if account_id.startswith("acc_dev_mock"):
            return {
                "id": account_id,
                "status": "activated",
                "activated": True,
            }
        return self.client.account.fetch(account_id)


# Global default client
razorpay_client = RazorpayClient()
