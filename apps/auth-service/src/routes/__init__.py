from src.routes.auth import router as auth_router
from src.routes.kyc import router as kyc_router, interservice_kyc_router, legacy_kyc_router

__all__ = ["auth_router", "kyc_router", "interservice_kyc_router", "legacy_kyc_router"]
