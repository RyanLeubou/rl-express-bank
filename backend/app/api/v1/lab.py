"""Laboratoire : lancement de scénarios d'attaque (désactivé hors LAB_MODE)."""
from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.core.config import Settings, get_settings
from app.core.database import get_db
from app.events.audit import record_audit
from app.models import SimulationRun, User
from app.models.enums import UserType
from app.security.auth.deps import AuthContext, check_origin, client_ip, require_aal, require_permission
from app.security.auth.errors import AuthError
from app.simulations.scenarios import SCENARIOS, run_scenario

router = APIRouter(prefix="/lab", tags=["Laboratoire"], dependencies=[Depends(check_origin)])


class RunIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scenario: str
    victim_id: uuid.UUID | None = None


def _run(r: SimulationRun) -> dict[str, Any]:
    return {"id": r.id, "scenario": r.scenario, "status": r.status, "started_at": r.started_at,
            "ended_at": r.ended_at, "summary": r.summary}


@router.get("/scenarios", summary="Scénarios disponibles")
def scenarios(_: AuthContext = Depends(require_permission("simulation:run:any"))):
    return [{"id": k, "description": v[0]} for k, v in SCENARIOS.items()]


@router.get("/runs", summary="Exécutions")
def runs(_: AuthContext = Depends(require_permission("simulation:run:any")), db: DbSession = Depends(get_db)):
    return [_run(r) for r in db.scalars(select(SimulationRun).order_by(SimulationRun.started_at.desc()).limit(30))]


@router.post("/runs", status_code=201, summary="Lancer un scénario")
def launch(body: RunIn, request: Request, ctx: AuthContext = Depends(require_permission("simulation:run:any")),
           _: object = Depends(require_aal(2)), db: DbSession = Depends(get_db),
           settings: Settings = Depends(get_settings)):
    if not settings.lab_mode:
        raise AuthError(403, "lab_disabled", "Le mode laboratoire est désactivé.")
    if body.scenario not in SCENARIOS:
        raise AuthError(404, "unknown_scenario", "Scénario inconnu.")
    victim = db.get(User, body.victim_id) if body.victim_id else db.scalar(
        # Ordre stable : à date de création égale (clients de démo), départage par e-mail plutôt qu'au hasard
        select(User).where(User.user_type == UserType.CUSTOMER).order_by(User.created_at, User.email).limit(1))
    if victim is None or victim.user_type != UserType.CUSTOMER:
        raise AuthError(404, "user_not_found", "Client introuvable.")
    run = run_scenario(db, body.scenario, victim, ctx.user, {"victim": str(victim.id)})
    record_audit(db, action="SIMULATION_RUN", target_type="simulation", target_id=run.id, actor_id=ctx.user.id,
                 after={"scenario": body.scenario}, ip_address=client_ip(request))
    db.commit()
    return _run(run)
