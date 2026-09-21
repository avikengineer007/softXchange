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

# Cache static assets to prevent repeated slow downloads over network tunnels
@app.middleware("http")
async def add_cache_headers(request, call_next):
    response = await call_next(request)
    path = request.url.path
    if any(path.endswith(ext) for ext in [".css", ".js", ".png", ".jpg", ".svg", ".woff2", ".glb", ".gltf"]):
        response.headers["Cache-Control"] = "public, max-age=3600"
    else:
        response.headers["Cache-Control"] = "no-cache, must-revalidate"
    return response

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
    "reset-password.html",
    "wishlist.html",
    "payment-interface.html",
    "payments.html",
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

# Dynamic fallback for any additional HTML files in static directory
@app.get("/{page_name}.html", include_in_schema=False)
async def dynamic_html_handler(page_name: str):
    target = STATIC_DIR / f"{page_name}.html"
    if target.exists() and target.is_file():
        return FileResponse(str(target), media_type="text/html")
    raise HTTPException(status_code=404, detail=f"Page {page_name}.html not found")


# Root redirect -> landing page
@app.get("/", include_in_schema=False)
def root():
    return FileResponse(str(STATIC_DIR / "index.html"), media_type="text/html")


# Gracefully handle any relative mailto link resolution
@app.get("/mailto:{rest:path}", include_in_schema=False)
def mailto_handler(rest: str):
    return RedirectResponse(url=f"mailto:{rest}", status_code=301)


# Mount static assets
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")


if __name__ == "__main__":
    uvicorn.run("run:app", host="0.0.0.0", port=8000, reload=True)
