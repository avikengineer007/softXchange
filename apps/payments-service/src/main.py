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
    logger.info("Initializing payments-service database schema...")
    init_db()
    yield


app = FastAPI(
    title="softXchange Payments Service",
    description="Dedicated payments and Stripe Connect orchestration microservice.",
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
