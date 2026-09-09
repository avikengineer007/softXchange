import uvicorn
from seller_assist.config import settings

if __name__ == "__main__":
    uvicorn.run("seller_assist.main:app", host="0.0.0.0", port=settings.PORT, reload=True)
