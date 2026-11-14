"""Client Valkey (compatible protocole Redis) : rate limiting, challenges courts, heartbeats."""
from __future__ import annotations

import time
from functools import lru_cache

import redis

from app.core.config import get_settings

WORKER_HEARTBEAT_KEY = "rlbank:worker:heartbeat"


@lru_cache
def get_valkey() -> redis.Redis:
    return redis.Redis.from_url(
        get_settings().valkey_url,
        socket_timeout=2,
        socket_connect_timeout=2,
        decode_responses=True,
        health_check_interval=30,
    )


def check_cache() -> dict[str, object]:
    started = time.perf_counter()
    try:
        get_valkey().ping()
        return {"status": "ok", "latency_ms": round((time.perf_counter() - started) * 1000, 1)}
    except Exception:  # noqa: BLE001
        return {"status": "down"}


def check_worker() -> dict[str, object]:
    """Le worker écrit un heartbeat avec expiration : absent = worker arrêté."""
    try:
        last = get_valkey().get(WORKER_HEARTBEAT_KEY)
    except Exception:  # noqa: BLE001
        return {"status": "unknown"}
    if last is None:
        return {"status": "down"}
    return {"status": "ok", "seconds_since_heartbeat": round(time.time() - float(last), 1)}
