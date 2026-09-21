"""
apps/seller-assist/seller_assist/main.py

FastAPI application entrypoint for seller-assist service.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from seller_assist.config import settings
from seller_assist.routes.suggest import router as suggest_router
from seller_assist.routes.explain import router as explain_router
from seller_assist.routes.reply import router as reply_router

app = FastAPI(
    title="softXchange Seller Assist Service",
    description=(
        "AI-powered seller assistance microservice: copy suggestions, pricing guidance, "
        "plain-English scan summaries, and drafted buyer replies."
    ),
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(suggest_router)
app.include_router(explain_router)
app.include_router(reply_router)




@app.get("/healthz", tags=["Health"])
def health_check():
    return {
        "status": "ok",
        "service": "seller-assist",
        "version": "0.1.0",
    }
