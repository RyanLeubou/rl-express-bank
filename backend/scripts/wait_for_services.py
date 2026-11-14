"""Attend PostgreSQL (rôle propriétaire) et Valkey avant de lancer migrations et API."""
from __future__ import annotations

import sys
import time

import redis
from sqlalchemy import create_engine, text

from app.core.config import get_settings

TIMEOUT_SECONDS = 90


def wait(name: str, probe) -> None:
    deadline = time.time() + TIMEOUT_SECONDS
    while True:
        try:
            probe()
            print(f"[attente] {name} disponible", flush=True)
            return
        except Exception as exc:  # noqa: BLE001
            if time.time() > deadline:
                print(f"[attente] {name} indisponible après {TIMEOUT_SECONDS}s : {type(exc).__name__}",
                      file=sys.stderr, flush=True)
                sys.exit(1)
            time.sleep(2)


def main() -> None:
    settings = get_settings()

    def pg() -> None:
        engine = create_engine(settings.migration_database_url, connect_args={"connect_timeout": 3})
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        engine.dispose()

    def vk() -> None:
        redis.Redis.from_url(settings.valkey_url, socket_timeout=2).ping()

    wait("PostgreSQL", pg)
    wait("Valkey", vk)


if __name__ == "__main__":
    main()
