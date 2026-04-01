import os

from sqlalchemy import create_engine
from sqlalchemy import event as sa_event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import DB_PATH
from app.db.models import Base

# In-memory SQLite needs a single shared connection pool; otherwise each pooled
# connection sees a fresh empty database and schema created in init_db is invisible.
if DB_PATH == ":memory:":
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
else:
    engine = create_engine(
        f"sqlite:///{DB_PATH}",
        connect_args={"check_same_thread": False},
    )
SessionLocal = sessionmaker(bind=engine)


@sa_event.listens_for(engine, "connect")
def _set_sqlite_wal(dbapi_connection, connection_record):
    if DB_PATH == ":memory:":
        return
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.close()


def init_db():
    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
