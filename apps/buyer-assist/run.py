import uvicorn
from buyer_assist.config import settings

if __name__ == "__main__":
    uvicorn.run("buyer_assist.main:app", host="0.0.0.0", port=settings.PORT, reload=True)
