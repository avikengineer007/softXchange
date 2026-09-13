from typing import Any, Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker, Session

from src.config import settings

engine_kwargs: dict[str, Any] = {"pool_pre_ping": True}
if settings.DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}
else:
    engine_kwargs.update({
        "pool_size": 10,
        "max_overflow": 20,
        "pool_recycle": 3600,
    })

engine = create_engine(
    settings.DATABASE_URL,
    **engine_kwargs,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    if settings.ENVIRONMENT.lower() == "production":
        # In production, tables MUST be created via Alembic migrations.
        # Calling create_all() is strictly prohibited to prevent untracked schema drift.
        return
    # Ensure models are imported before metadata creation
    import src.models.listing  # noqa: F401
    import src.models.embedding  # noqa: F401
    Base.metadata.create_all(bind=engine)
