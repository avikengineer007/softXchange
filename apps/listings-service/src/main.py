from contextlib import asynccontextmanager
import logging
import threading
import time
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse

from src.config import settings
from src.database import init_db, SessionLocal
from src.routes import listings_router
from src.models.listing import Listing, ListingVersion, ListingStatus, ScanStatus
from src.scanner_client import scanner_client
from src.gate import evaluate_publish_gate

logger = logging.getLogger("listings-service.main")

_stop_poller = threading.Event()
_poller_thread = None


def _background_scan_poller():
    """
    Background job periodically querying pending scans and evaluating the publish gate.
    Ensures sellers do not need to keep their browser tab open.
    """
    logger.info("Background scan poller started.")
    while not _stop_poller.is_set():
        try:
            with SessionLocal() as db:
                pending_versions = (
                    db.query(ListingVersion)
                    .filter(ListingVersion.scan_status == ScanStatus.PENDING_SCAN.value)
                    .all()
                )
                for version in pending_versions:
                    try:
                        status_res = scanner_client.query_status(version.listing_id, version.version_label)
                        raw_status = status_res.get("scan_status")
                        if raw_status and raw_status != ScanStatus.PENDING_SCAN.value:
                            version.scan_status = raw_status
                            version.storage_location = status_res.get("storage_location")
                            version.findings_summary = status_res.get("severity_counts", {})
                            version.findings_detail = status_res.get("findings", [])
                            db.commit()

                            listing = db.query(Listing).filter(Listing.id == version.listing_id).first()
                            if listing:
                                evaluate_publish_gate(listing, version, db)
                    except Exception as err:
                        logger.debug(f"Poller query skipped for version {version.id}: {err}")
        except Exception as exc:
            logger.error(f"Error in background poller: {exc}")

        time.sleep(2.0)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _poller_thread
    init_db()
    _stop_poller.clear()
    _poller_thread = threading.Thread(target=_background_scan_poller, daemon=True)
    _poller_thread.start()
    yield
    _stop_poller.set()


app = FastAPI(
    title="softXchange Listings Service",
    description="Listing lifecycle, security gate enforcement, and catalog management for softXchange.",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(listings_router)

@app.get("/", include_in_schema=False)
def root_redirect():
    return RedirectResponse(url="http://localhost:8000/browse-listings.html")


@app.get("/healthz", tags=["Health"])
def health_check():
    return {
        "status": "ok",
        "service": "listings-service",
        "environment": settings.ENVIRONMENT,
    }
