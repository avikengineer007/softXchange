import uvicorn
from broker.config import settings

if __name__ == "__main__":
    uvicorn.run("broker.main:app", host="0.0.0.0", port=settings.PORT, reload=True)
