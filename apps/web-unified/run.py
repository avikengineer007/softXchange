"""
softXchange Unified Web Application Server
Serves all marketplace frontend pages from http://localhost:8000.
Calls backend services (auth-service, listings-service, payments-service,
scan-service, buyer-assist, seller-assist) purely as APIs.
"""

from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
import uvicorn

STATIC_DIR = Path(__file__).resolve().parent / "static"

app = FastAPI(
    title="softXchange Unified Frontend",
    description="Consolidated web frontend for the softXchange marketplace platform",
    version="1.0.0",
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Health endpoint
@app.get("/healthz", tags=["Health"])
def healthz():
    return {"status": "ok", "app": "web-unified", "port": 8000}


# Direct HTML page routes for clean URLs and backward-compatibility
PAGES = [
    "index.html",
    "browse-listings.html",
    "listing-detail.html",
    "seller-listings.html",
    "seller-payouts.html",
    "checkout.html",
    "order-confirmation.html",
    "login-customer.html",
    "signup-customer.html",
    "login-seller.html",
    "signup-seller.html",
    "dashboard-customer.html",
    "dashboard-seller.html",
    "admin-dashboard.html",
]

for page in PAGES:
    def make_handler(page_name=page):
        async def page_handler():
            target = STATIC_DIR / page_name
            if not target.exists():
                raise HTTPException(status_code=404, detail=f"Page {page_name} not found")
            return FileResponse(str(target), media_type="text/html")
        return page_handler

    # Support both /page.html and /static/page.html
    app.add_api_route(f"/{page}", make_handler(page), methods=["GET"], include_in_schema=False)
    app.add_api_route(f"/static/{page}", make_handler(page), methods=["GET"], include_in_schema=False)


# Root redirect -> landing page
@app.get("/", include_in_schema=False)
def root():
    return FileResponse(str(STATIC_DIR / "index.html"), media_type="text/html")


# Mount static assets
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")


if __name__ == "__main__":
    uvicorn.run("run:app", host="0.0.0.0", port=8000, reload=True)
