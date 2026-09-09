"""
apps/buyer-assist/buyer_assist/main.py

Main entry point for the softXchange Buyer Assist Service.
Exposes natural-language discovery and buyer intelligence for softXchange marketplace.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from buyer_assist.config import settings
from buyer_assist.routes.assist import router as assist_router

app = FastAPI(
    title="softXchange Buyer Assist Service",
    description="Natural-language discovery and buyer intelligence for softXchange marketplace.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(assist_router)


@app.get("/healthz", tags=["Health"])
def health_check():
    return {
        "status": "ok",
        "service": "buyer-assist",
    }
