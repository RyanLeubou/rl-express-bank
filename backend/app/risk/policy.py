"""Politique de sécurité : (opération, niveau) -> décision. Échec fermé : sans politique, BLOCK."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import SecurityPolicy
from app.models.enums import PolicyDecision as D
from app.models.enums import RiskLevel, RiskOperation

_ORDER = [D.ALLOW, D.ALLOW_AND_MONITOR, D.STEP_UP_TOTP, D.STEP_UP_PASSKEY, D.BLOCK]


def level_for(score: int, settings: Settings) -> RiskLevel:
    if score >= settings.risk_critical_from:
        return RiskLevel.CRITICAL
    if score >= settings.risk_high_from:
        return RiskLevel.HIGH
    if score >= settings.risk_medium_from:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def stricter(a: D, b: D) -> D:
    return a if _ORDER.index(a) >= _ORDER.index(b) else b


def resolve(db: Session, op: RiskOperation, level: RiskLevel) -> tuple[D, list[str]]:
    row = db.scalars(select(SecurityPolicy).where(
        SecurityPolicy.operation_type == op, SecurityPolicy.risk_level == level,
        SecurityPolicy.enabled.is_(True)).order_by(SecurityPolicy.version.desc())).first()
    if row is None:
        return D.BLOCK, []
    decision = stricter(D(row.decision), D(row.floor_decision)) if row.floor_decision else D(row.decision)
    return decision, list(row.actions or [])


def needs_step_up(decision: D) -> bool:
    return decision in (D.STEP_UP_TOTP, D.STEP_UP_PASSKEY)
