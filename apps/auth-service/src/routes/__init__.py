from src.routes.auth import router as auth_router
from src.routes.kyc import router as kyc_router, interservice_kyc_router, legacy_kyc_router
from src.routes.admin import router as admin_router
from src.routes.notifications import router as notifications_router
from src.routes.github import router as seller_github_router, seller_trust_router

__all__ = ["auth_router", "kyc_router", "interservice_kyc_router", "legacy_kyc_router", "admin_router", "notifications_router", "seller_github_router", "seller_trust_router"]


