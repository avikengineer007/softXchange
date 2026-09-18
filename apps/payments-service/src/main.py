from contextlib import asynccontextmanager
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse

from src.config import settings
from src.database import init_db
from src.routes import (
    connect_router,
    connect_alias_router,
    connect_direct_alias_router,
    orders_router,
    webhooks_router,
    admin_router,
    seller_router,
    seller_alias_router,
)

logger = logging.getLogger("payments-service.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    if settings.ENVIRONMENT.lower() == "production":
        # Hard fail-closed assertion: verify test-confirm route is NEVER registered in production
        for route in app.routes:
            if hasattr(route, "path") and "test-confirm" in route.path:
                raise RuntimeError(
                    "SECURITY FATAL: Test-confirm endpoint is registered in production! Refusing startup."
                )

        # Hard fail-closed assertion: refuse mock or dev-default Razorpay credentials in production
        mock_indicators = ["mock", "test_softxchange"]
        has_mock_key = any(ind in settings.RAZORPAY_KEY_ID.lower() for ind in mock_indicators)
        has_mock_secret = any(ind in settings.RAZORPAY_KEY_SECRET.lower() for ind in mock_indicators)
        has_mock_webhook = any(ind in settings.RAZORPAY_WEBHOOK_SECRET.lower() for ind in mock_indicators)

        if (
            has_mock_key
            or has_mock_secret
            or has_mock_webhook
            or len(settings.RAZORPAY_KEY_ID.strip()) < 8
            or len(settings.RAZORPAY_KEY_SECRET.strip()) < 16
            or len(settings.RAZORPAY_WEBHOOK_SECRET.strip()) < 16
        ):
            raise RuntimeError(
                "SECURITY FATAL: Mock or dev-default Razorpay credentials detected in production! Real live credentials required."
            )

    logger.info("Initializing payments-service database schema...")
    init_db()
    yield


app = FastAPI(
    title="softXchange Payments Service",
    description="Dedicated payments and Razorpay Route orchestration microservice.",
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

# Include all route controllers
app.include_router(connect_router)
app.include_router(connect_alias_router)
app.include_router(connect_direct_alias_router)
app.include_router(orders_router)
app.include_router(webhooks_router)
app.include_router(admin_router)
app.include_router(seller_router)
app.include_router(seller_alias_router)


@app.get("/", include_in_schema=False)
def root_redirect():
    return RedirectResponse(url="http://localhost:8000/")


@app.get("/healthz", tags=["Health"])
def health_check():
    return {
        "status": "ok",
        "service": "payments-service",
        "environment": settings.ENVIRONMENT,
    }
