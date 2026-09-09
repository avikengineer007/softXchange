from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger("auth-service.kyc.provider")


class KYCProvider(ABC):
    """
    Abstract interface for seller identity verification and KYC onboarding.
    Can be backed by Stripe Connect Express, Razorpay Route, or an internal compliance service.
    """

    @abstractmethod
    def start_onboarding(self, user_id: str) -> Dict[str, Any]:
        """
        Initiate identity verification / onboarding flow for the seller.
        Returns provider-specific onboarding session metadata (e.g. hosted onboarding URL).
        """
        pass

    @abstractmethod
    def check_status(self, user_id: str) -> str:
        """
        Query current verification status from provider.
        Returns one of: 'pending', 'verified', 'rejected'.
        """
        pass


class MockKYCProvider(KYCProvider):
    """
    Mock/fake KYC provider for testing and development.
    Allows configuring deterministic test outcomes.
    """
    def __init__(self):
        # Maps user_id -> status
        self._user_statuses: Dict[str, str] = {}
        self._simulate_error: bool = False

    def set_user_status(self, user_id: str, status: str) -> None:
        """Helper to force a specific provider status during tests."""
        self._user_statuses[user_id] = status

    def set_simulate_error(self, simulate: bool) -> None:
        """Helper to simulate provider outages or unhandled exceptions."""
        self._simulate_error = simulate

    def start_onboarding(self, user_id: str) -> Dict[str, Any]:
        if self._simulate_error:
            raise RuntimeError("Provider connection failed during start_onboarding")
        
        self._user_statuses[user_id] = "pending"
        return {
            "provider": "mock_stripe_connect",
            "onboarding_url": f"https://connect.stripe.com/setup/s/mock_{user_id}",
            "status": "pending",
        }

    def check_status(self, user_id: str) -> str:
        if self._simulate_error:
            raise RuntimeError("Provider connection failed during check_status")
        return self._user_statuses.get(user_id, "pending")


# Global active provider instance (can be swapped via dependency injection or config)
active_kyc_provider: KYCProvider = MockKYCProvider()


def get_kyc_provider() -> KYCProvider:
    return active_kyc_provider


def set_active_kyc_provider(provider: KYCProvider) -> None:
    global active_kyc_provider
    active_kyc_provider = provider
