from src.routes.connect import router as connect_router
from src.routes.orders import router as orders_router
from src.routes.webhooks import router as webhooks_router
from src.routes.admin import router as admin_router
from src.routes.seller import router as seller_router

__all__ = [
    "connect_router",
    "orders_router",
    "webhooks_router",
    "admin_router",
    "seller_router",
]
