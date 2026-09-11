"""
apps/broker/broker/main.py

Main entry point for the softXchange Broker Service (Phase 3 final ML component).
Connects buyer inquiries to verified answers or proactive seller drafts.
Surfaces non-committal, privacy-preserving aggregate demand signals.
"""

from contextlib import asynccontextmanager
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from broker.config import settings
from broker.routes.routing import router as routing_router
from broker.routes.demand import router as demand_router
from src.database import engine
from src.models.listing import Base

logger = logging.getLogger("broker.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure database schemas are synchronized
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Broker database tables verified.")
    except Exception as e:
        logger.warning(f"Error checking broker database tables: {e}")
    yield


app = FastAPI(
    title="softXchange Broker Service",
    description="Deterministic question routing and observational demand signals for softXchange.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(routing_router)
app.include_router(demand_router)


@app.get("/health", tags=["Health"])
@app.get("/healthz", tags=["Health"])
def health_check():
    return {
        "status": "ok",
        "service": "broker",
        "version": "1.0.0",
    }
