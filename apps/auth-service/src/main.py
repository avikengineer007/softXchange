from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from src.config import settings
from src.database import init_db
from src.routes import auth_router, kyc_router, interservice_kyc_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database tables on startup
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
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth_router)
app.include_router(kyc_router)
app.include_router(interservice_kyc_router)

# Mount static directory for frontend login/signup pages
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")


@app.get("/", include_in_schema=False)
def root_redirect():
    return RedirectResponse(url="/static/login-customer.html")


@app.get("/healthz", tags=["Health"])
def health_check():
    return {
        "status": "ok",
        "service": "auth-service",
        "environment": settings.ENVIRONMENT,
        "algorithm": settings.JWT_ALGORITHM,
    }
