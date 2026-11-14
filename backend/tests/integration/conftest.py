"""Tests d'intégration sur un vrai PostgreSQL (base <POSTGRES_DB>_test, jamais la base principale).

Activation : RLBANK_INTEGRATION=1 (make test-integration). Sans cette variable, les tests sont ignorés.
Le schéma est reconstruit de zéro (downgrade base puis upgrade head), puis le seed est exécuté une fois.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

INTEGRATION = os.environ.get("RLBANK_INTEGRATION") == "1"
if INTEGRATION:
    base_db = os.environ.get("POSTGRES_DB", "rlbank").removesuffix("_test")
    os.environ["POSTGRES_DB"] = f"{base_db}_test"


def pytest_collection_modifyitems(config, items):
    if INTEGRATION:
        return
    skip = pytest.mark.skip(reason="RLBANK_INTEGRATION=1 requis (base PostgreSQL de test)")
    for item in items:
        if "integration" in str(item.fspath):
            item.add_marker(skip)


@pytest.fixture(scope="session")
def migrated():
    from alembic import command
    from alembic.config import Config

    from app.core.config import get_settings
    from app.core.database import get_engine, get_session_factory

    for cached in (get_settings, get_engine, get_session_factory):
        cached.cache_clear()
    assert get_settings().postgres_db.endswith("_test"), "Refus : les tests ne tournent que sur la base _test"
    cfg = Config(str(Path(__file__).resolve().parents[2] / "alembic.ini"))
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")
    yield cfg


@pytest.fixture(scope="session")
def seeded(migrated):
    from app.core.database import get_session_factory
    from app.seed.runner import run_seed

    with get_session_factory()() as db:
        summary = run_seed(db)
        db.commit()
    return summary


@pytest.fixture
def db(seeded):
    """Session du rôle APPLICATIF, annulée après chaque test."""
    from app.core.database import get_session_factory

    session = get_session_factory()()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def owner_conn(migrated):
    """Connexion du rôle PROPRIÉTAIRE (migrations), transaction annulée après le test."""
    from sqlalchemy import create_engine

    from app.core.config import get_settings

    engine = create_engine(get_settings().migration_database_url)
    conn = engine.connect()
    trans = conn.begin()
    try:
        yield conn
    finally:
        trans.rollback()
        conn.close()
        engine.dispose()
