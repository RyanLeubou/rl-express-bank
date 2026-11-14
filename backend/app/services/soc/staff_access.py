"""UEBA du personnel : toute consultation d'un dossier client est tracée, évaluée et, si besoin, refusée."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.events.catalog import EventType as E
from app.events.logger import emit
from app.models import Session as AuthSession
from app.models import SupportTicket, User
from app.models.enums import PolicyDecision, RiskOperation, RoleCode, SecurityActionType, TicketStatus
from app.risk import response as resp
from app.risk.context import OperationContext
from app.risk.engine import evaluate, save_assessment
from app.security.auth.errors import AuthError


def has_ticket_access(db: Session, agent_id: uuid.UUID, customer_id: uuid.UUID) -> bool:
    now = datetime.now(UTC)
    return db.scalar(select(SupportTicket.id).where(
        SupportTicket.assigned_agent_id == agent_id, SupportTicket.user_id == customer_id,
        SupportTicket.status.in_([TicketStatus.OPEN, TicketStatus.IN_PROGRESS]),
        SupportTicket.access_expires_at > now).limit(1)) is not None


def record_staff_access(db: Session, staff: User, session: AuthSession, customer_id: uuid.UUID, *, purpose: str,
                        ip: str | None) -> None:
    """Lève 403 (et alerte le SOC) si l'accès est interdit ; sinon trace l'accès."""
    roles = {r.code for r in staff.roles}
    agent = RoleCode.SUPPORT_AGENT in roles and not roles & {RoleCode.SUPER_ADMIN, RoleCode.SECURITY_ANALYST}
    op = RiskOperation.SUPPORT_ACTION if agent else RiskOperation.ADMIN_ACTION
    assigned = has_ticket_access(db, staff.id, customer_id) if agent else None
    ctx = OperationContext(user=staff, op=op, session=session, ip=ip, target_user_id=customer_id,
                           extra={"assigned": assigned})
    result = evaluate(db, ctx)
    save_assessment(db, ctx, result)
    meta = {"customer_id": str(customer_id), "purpose": purpose, "reasons": result.reasons}
    base = dict(user_id=staff.id, session_id=session.id, ip_address=ip)
    if agent and assigned is False:
        ev = emit(db, E.STAFF_ACCESS_DENIED, risk_score=result.score, metadata=meta, **base)
        resp.raise_alert(db, user_id=staff.id, title="Agent : accès à un client sans ticket assigné",
                         result=result, event=ev)
        db.commit()
        raise AuthError(403, "no_assigned_ticket", "Aucun ticket assigné ne vous donne accès à ce client.")
    ev = emit(db, E.STAFF_CUSTOMER_ACCESSED, risk_score=result.score, metadata=meta, **base)
    if result.decision == PolicyDecision.BLOCK:
        emit(db, E.STAFF_PRIVILEGE_ABUSE_DETECTED, risk_score=result.score, metadata=meta, **base)
        alert = resp.raise_alert(db, user_id=staff.id, title="Comportement interne anormal : accès bloqué",
                                 result=result, event=ev)
        resp.execute_action(db, SecurityActionType.REVOKE_SESSION, target_id=session.id, user=staff, alert=alert)
        db.commit()
        raise AuthError(403, "access_blocked", "Accès bloqué par la politique de sécurité.", clear_session=True)
    if any(r["code"] == "STAFF_BULK_ACCESS" for r in result.reasons):
        emit(db, E.STAFF_BULK_ACCESS_DETECTED, risk_score=result.score, metadata=meta, **base)
    if result.score >= 30:
        resp.raise_alert(db, user_id=staff.id, title="Accès inhabituel d'un membre du personnel",
                         result=result, event=ev)
