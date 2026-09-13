import logging
from typing import Optional, Dict, Any
import stripe

from src.config import settings

logger = logging.getLogger("payments-service.stripe_client")

# Configure global Stripe API key
stripe.api_key = settings.STRIPE_SECRET_KEY


class StripeClient:
    """
    Dedicated client for Stripe Connect and Checkout operations.
    payments-service is the sole custodian of Stripe keys in softXchange.
    """
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.STRIPE_SECRET_KEY
        stripe.api_key = self.api_key

    def create_connect_account(self, user_id: str, email: Optional[str] = None) -> str:
        """
        Creates a Stripe Connect Express account for a seller.
        """
        params: Dict[str, Any] = {
            "type": "express",
            "capabilities": {
                "card_payments": {"requested": True},
                "transfers": {"requested": True},
            },
            "metadata": {"user_id": user_id},
        }
        try:
            account = stripe.Account.create(**params)
            logger.info(f"Created Stripe Connect account {account.id} for seller {user_id}")
            return account.id
        except Exception as e:
            if settings.ENVIRONMENT != "production" and ("signed up for Connect" in str(e) or "Connect" in str(e)):
                logger.warning(f"Stripe Connect not enabled on test key, using dev mock account for {user_id}: {e}")
                return f"acct_dev_mock_{user_id.replace('-', '')[:16]}"
            raise

    def create_account_link(
        self,
        account_id: str,
        refresh_url: str,
        return_url: str,
    ) -> str:
        """
        Creates a Stripe Account Link for hosted seller identity & bank onboarding.
        """
        if account_id.startswith("acct_dev_mock"):
            return return_url

        link = stripe.AccountLink.create(
            account=account_id,
            refresh_url=refresh_url,
            return_url=return_url,
            type="account_onboarding",
        )
        return link.url

    def create_payment_intent(
        self,
        amount_cents: int,
        application_fee_cents: int,
        destination_account_id: str,
        metadata: Dict[str, str],
    ) -> Dict[str, Any]:
        """
        Creates a Stripe PaymentIntent using Connect's destination charge model.
        Automatically transfers net payout to destination seller upon charge success.
        """
        if destination_account_id.startswith("acct_dev_mock"):
            import time
            return {
                "id": f"pi_dev_mock_{int(time.time())}",
                "client_secret": f"pi_dev_mock_secret_{int(time.time())}",
                "status": "requires_payment_method",
            }

        intent = stripe.PaymentIntent.create(
            amount=amount_cents,
            currency="usd",
            application_fee_amount=application_fee_cents,
            transfer_data={"destination": destination_account_id},
            metadata=metadata,
        )
        return {
            "id": intent.id,
            "client_secret": intent.client_secret,
            "status": intent.status,
        }

    def construct_webhook_event(
        self,
        payload: bytes,
        sig_header: str,
        webhook_secret: Optional[str] = None,
    ) -> Any:
        """
        Validates Stripe webhook signature using the raw payload.
        Fails closed on any invalid or missing signature.
        """
        secret = webhook_secret or settings.STRIPE_WEBHOOK_SECRET
        return stripe.Webhook.construct_event(payload, sig_header, secret)

    def refund_payment_intent(
        self,
        payment_intent_id: str,
        reason: str = "requested_by_customer",
    ) -> Any:
        """
        Refunds a charge and reverses application fees / transfers via Stripe.
        """
        return stripe.Refund.create(
            payment_intent=payment_intent_id,
            reason=reason,
            reverse_transfer=True,
            refund_application_fee=True,
        )


# Global default client
stripe_client = StripeClient()
