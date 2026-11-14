"""Endpoints de santé.

- /health/live  : le processus répond (utilisé par le healthcheck Docker).
- /health/ready : les dépendances répondent (PostgreSQL, Valkey, worker).
Aucune version de logiciel tiers ni information d'infrastructure n'est exposée.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Literal

from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel

from app.core.cache import check_cache, check_worker
from app.core.config import Settings, get_settings
from app.core.database import check_database

router = APIRouter(prefix="/health", tags=["Santé"])

CheckFn = Callable[[], dict[str, object]]


class LiveResponse(BaseModel):
    status: Literal["ok"]
    service: str
    version: str


class CheckResult(BaseModel):
    status: str
    latency_ms: float | None = None
    seconds_since_heartbeat: float | None = None


class ReadyResponse(BaseModel):
    status: Literal["ok", "degraded", "down"]
    environment: str
    lab_mode: bool
    checks: dict[str, CheckResult]


def get_health_checks() -> dict[str, CheckFn]:
    """Dépendance remplaçable dans les tests."""
    return {"database": check_database, "cache": check_cache, "worker": check_worker}


# Dépendances critiques : sans elles l'API ne peut pas servir de requête bancaire
CRITICAL = {"database", "cache"}


@router.get("/live", response_model=LiveResponse, summary="Le processus API répond")
def live(settings: Settings = Depends(get_settings)) -> LiveResponse:
    return LiveResponse(status="ok", service="rl-express-bank-api", version=settings.app_version)


@router.get("/ready", response_model=ReadyResponse, response_model_exclude_none=True,
            summary="Les dépendances répondent",
            responses={503: {"description": "Une dépendance critique est indisponible"}})
def ready(response: Response,
          settings: Settings = Depends(get_settings),
          checks: dict[str, CheckFn] = Depends(get_health_checks)) -> ReadyResponse:
    results = {name: CheckResult(**fn()) for name, fn in checks.items()}
    critical_down = any(results[n].status != "ok" for n in CRITICAL if n in results)
    other_down = any(r.status != "ok" for n, r in results.items() if n not in CRITICAL)
    status = "down" if critical_down else "degraded" if other_down else "ok"
    if critical_down:
        response.status_code = 503
    return ReadyResponse(status=status, environment=settings.app_env,
                         lab_mode=settings.lab_mode, checks=results)
