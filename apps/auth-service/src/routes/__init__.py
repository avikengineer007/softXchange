from src.routes.auth import router as auth_router
from src.routes.kyc import router as kyc_router, interservice_kyc_router, legacy_kyc_router
from src.routes.admin import router as admin_router

__all__ = ["auth_router", "kyc_router", "interservice_kyc_router", "legacy_kyc_router", "admin_router"]

