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


def _add_missing_columns():
    """Add columns defined in models but absent from the SQLite tables."""
    from sqlalchemy import inspect as sa_inspect
    from sqlalchemy import text

    inspector = sa_inspect(engine)
    with engine.connect() as conn:
        for table_name, table in Base.metadata.tables.items():
            if not inspector.has_table(table_name):
                continue
            existing = {c["name"] for c in inspector.get_columns(table_name)}
            for col in table.columns:
                if col.name in existing:
                    continue
                col_type = col.type.compile(engine.dialect)
                default = "DEFAULT 0" if "INT" in col_type or "FLOAT" in col_type else ""
                conn.execute(text(
                    f"ALTER TABLE {table_name} ADD COLUMN {col.name} {col_type} {default}"
                ))
        conn.commit()


def init_db():
    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    Base.metadata.create_all(bind=engine)
    _add_missing_columns()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
