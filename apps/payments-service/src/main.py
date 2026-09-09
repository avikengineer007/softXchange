from contextlib import asynccontextmanager
import logging
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from src.config import settings
from src.database import init_db
from src.routes import (
    connect_router,
    orders_router,
    webhooks_router,
    admin_router,
    seller_router,
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
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include all route controllers
app.include_router(connect_router)
app.include_router(orders_router)
app.include_router(webhooks_router)
app.include_router(admin_router)
app.include_router(seller_router)

# Mount static frontend pages
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")


@app.get("/healthz", tags=["Health"])
def health_check():
    return {
        "status": "ok",
        "service": "payments-service",
        "environment": settings.ENVIRONMENT,
    }
