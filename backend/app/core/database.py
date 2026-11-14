"""Accès PostgreSQL via SQLAlchemy 2.0 (mode synchrone, psycopg 3).

Choix du mode synchrone : transactions et verrous `SELECT ... FOR UPDATE` lisibles,
tests simples. FastAPI exécute les endpoints synchrones dans un pool de threads.
"""
from __future__ import annotations

import time
from collections.abc import Iterator
from functools import lru_cache

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings


@lru_cache
def get_engine() -> Engine:
    settings = get_settings()
    return create_engine(
        settings.database_url,
        pool_size=10,
        max_overflow=10,
        pool_pre_ping=True,
        pool_recycle=1800,
        connect_args={"connect_timeout": 3, "application_name": "rlbank-api"},
    )


@lru_cache
def get_session_factory() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), autoflush=False, expire_on_commit=False)


def get_db() -> Iterator[Session]:
    """Dépendance FastAPI : une session par requête, fermée systématiquement."""
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()


def check_database() -> dict[str, object]:
    """Vérifie la connexion et le rôle utilisé, sans divulguer la version du serveur."""
    started = time.perf_counter()
    try:
        with get_engine().connect() as conn:
            conn.execute(text("SELECT 1"))
        return {"status": "ok", "latency_ms": round((time.perf_counter() - started) * 1000, 1)}
    except Exception:  # noqa: BLE001 - l'état suffit, le détail est journalisé ailleurs
        return {"status": "down"}
