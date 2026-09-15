from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse

from src.config import settings
from src.database import init_db
from src.routes import auth_router, kyc_router, interservice_kyc_router, admin_router, notifications_router, seller_github_router, seller_trust_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    if settings.ENVIRONMENT.lower() == "production":
        import hashlib
        dev_code = "sx_admin_sec_9f7a28e4c19d4b8e8f2a1b3c4d5e6f7a"
        dev_hash = "d5d662badcebe19e8cbe13310123c1c9199f4959f8a7f87461208abf0d59278c"

        code = settings.ADMIN_PROVISIONING_CODE or ""
        code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()

        if code == dev_code:
            raise RuntimeError(
                "FATAL SECURITY FAILURE: ADMIN_PROVISIONING_CODE is set to the known dev default string! "
                "The production operator code must be explicitly rotated to a fresh, high-entropy value."
            )
        if code_hash == dev_hash:
            raise RuntimeError(
                "FATAL SECURITY FAILURE: ADMIN_PROVISIONING_CODE matches the cryptographic hash of the known dev default! "
                "The production operator code must be explicitly rotated to a fresh, high-entropy value."
            )
        if len(code) < 32:
            raise RuntimeError(
                "FATAL SECURITY FAILURE: ADMIN_PROVISIONING_CODE must be set and have at least 32 characters in production."
            )
        if not settings.ADMIN_CODE_EXPLICITLY_ROTATED and ("dev" in code.lower() or "default" in code.lower()):
            raise RuntimeError(
                "FATAL SECURITY FAILURE: ADMIN_PROVISIONING_CODE appears to be a dev token and has not been explicitly rotated. "
                "Set ADMIN_CODE_EXPLICITLY_ROTATED=True only after rotating to a fresh production secret."
            )
    init_db()
    yield


app = FastAPI(
    title="softXchange Auth Service",
    description="Authentication and Identity service for Manifest's marketplace.",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS middleware for web frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_origin_regex=r"^https?://.*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth_router)
app.include_router(kyc_router)
app.include_router(interservice_kyc_router)
app.include_router(admin_router)
app.include_router(notifications_router)
app.include_router(seller_github_router)
app.include_router(seller_trust_router)


@app.get("/", include_in_schema=False)
def root_redirect():
    return RedirectResponse(url="http://localhost:8000/login-customer.html")


@app.get("/healthz", tags=["Health"])
def health_check():
    return {
        "status": "ok",
        "service": "auth-service",
        "environment": settings.ENVIRONMENT,
        "algorithm": settings.JWT_ALGORITHM,
    }
