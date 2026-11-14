"""Centre d'opérations de sécurité : alertes, investigations, actions, événements, statistiques, dossier client."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict, StringConstraints
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from app.core.database import get_db
from app.events.audit import record_audit
from app.events.catalog import EventType as E
from app.events.logger import emit
from app.models import (
    ATM,
    Account,
    AlertEvent,
    Card,
    CardPayment,
    Device,
    Investigation,
    InvestigationNote,
    RiskAssessment,
    SecurityAction,
    SecurityAlert,
    SecurityEvent,
    Transfer,
    User,
    Withdrawal,
)
from app.models.enums import (
    AccountType,
    AlertStatus,
    AtmStatus,
    InvestigationStatus,
    SecurityActionStatus,
    SecurityActionType,
    Severity,
)
from app.risk import response as resp
from app.security.auth.deps import AuthContext, check_origin, client_ip, require_permission
from app.security.auth.errors import AuthError
from app.services.soc.staff_access import record_staff_access

router = APIRouter(prefix="/soc", tags=["SOC"], dependencies=[Depends(check_origin)])
Text = Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=2000)]
ANALYST_ACTIONS = {SecurityActionType.LOCK_CARD, SecurityActionType.REVOKE_SESSION, SecurityActionType.BLOCK_DEVICE,
                   SecurityActionType.CANCEL_CARDLESS_CODES, SecurityActionType.NOTIFY_CUSTOMER}


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AlertPatch(Strict):
    status: AlertStatus | None = None
    assigned_to: uuid.UUID | None = None
    resolution_note: Text | None = None
    investigation_id: uuid.UUID | None = None


class ActionIn(Strict):
    action_type: SecurityActionType
    target_id: uuid.UUID
    justification: Text


class RevertIn(Strict):
    justification: Text


class InvestigationIn(Strict):
    title: Annotated[str, StringConstraints(min_length=3, max_length=160)]
    alert_ids: list[uuid.UUID] = []


class NoteIn(Strict):
    note: Text


class CloseIn(Strict):
    summary: Text


def _alert(a: SecurityAlert) -> dict[str, Any]:
    return {"id": a.id, "title": a.title, "severity": a.severity, "risk_score": a.risk_score,
            "risk_level": a.risk_level, "status": a.status, "source": a.source, "user_id": a.user_id,
            "reasons": a.reasons, "mitre": a.mitre_techniques, "assigned_to": a.assigned_to,
            "investigation_id": a.investigation_id, "resolution_note": a.resolution_note,
            "created_at": a.created_at, "updated_at": a.updated_at}


def _event(e: SecurityEvent) -> dict[str, Any]:
    return {"id": e.id, "seq": e.seq, "timestamp": e.timestamp, "type": e.event_type, "category": e.category,
            "severity": e.severity, "user_id": e.user_id, "ip": str(e.ip_address) if e.ip_address else None,
            "device": e.device, "location": e.location, "amount": e.amount, "status": e.status,
            "risk_score": e.risk_score, "atm_id": e.atm_id, "simulation_run_id": e.simulation_run_id,
            "metadata": e.metadata_}


def _action(a: SecurityAction) -> dict[str, Any]:
    return {"id": a.id, "alert_id": a.alert_id, "type": a.action_type, "target_type": a.target_type,
            "target_id": a.target_id, "executed_by": a.executed_by, "status": a.status,
            "justification": a.justification, "created_at": a.created_at, "reverted_at": a.reverted_at}


# ---- alertes ----------------------------------------------------------------------------------------
@router.get("/alerts", summary="Alertes de sécurité")
def alerts(status: AlertStatus | None = None, severity: Severity | None = None, user_id: uuid.UUID | None = None,
           limit: int = Query(50, ge=1, le=200), _: AuthContext = Depends(require_permission("alert:read:any")),
           db: DbSession = Depends(get_db)):
    q = select(SecurityAlert).order_by(SecurityAlert.created_at.desc()).limit(limit)
    if status:
        q = q.where(SecurityAlert.status == status)
    if severity:
        q = q.where(SecurityAlert.severity == severity)
    if user_id:
        q = q.where(SecurityAlert.user_id == user_id)
    users = {}
    out = []
    for a in db.scalars(q):
        d = _alert(a)
        if a.user_id and a.user_id not in users:
            u = db.get(User, a.user_id)
            users[a.user_id] = f"{u.full_name} ({u.user_type.lower()})" if u else None
        d["user_label"] = users.get(a.user_id)
        out.append(d)
    return out


@router.get("/alerts/{alert_id}", summary="Détail d'une alerte")
def alert_detail(alert_id: uuid.UUID, _: AuthContext = Depends(require_permission("alert:read:any")),
                 db: DbSession = Depends(get_db)):
    a = db.get(SecurityAlert, alert_id)
    if a is None:
        raise AuthError(404, "alert_not_found", "Alerte introuvable.")
    events = db.scalars(select(SecurityEvent).join(AlertEvent, AlertEvent.security_event_id == SecurityEvent.id)
                        .where(AlertEvent.alert_id == a.id).order_by(SecurityEvent.timestamp))
    actions = db.scalars(select(SecurityAction).where(SecurityAction.alert_id == a.id)
                         .order_by(SecurityAction.created_at))
    user = db.get(User, a.user_id) if a.user_id else None
    return {**_alert(a), "events": [_event(e) for e in events], "actions": [_action(x) for x in actions],
            "user": {"id": user.id, "name": user.full_name, "email": user.email, "type": user.user_type,
                     "status": user.status} if user else None}


@router.patch("/alerts/{alert_id}", summary="Trier, assigner, clôturer")
def patch_alert(alert_id: uuid.UUID, body: AlertPatch, request: Request,
                ctx: AuthContext = Depends(require_permission("alert:update:any")), db: DbSession = Depends(get_db)):
    a = db.get(SecurityAlert, alert_id)
    if a is None:
        raise AuthError(404, "alert_not_found", "Alerte introuvable.")
    before = {"status": str(a.status), "assigned_to": str(a.assigned_to) if a.assigned_to else None}
    if body.assigned_to is not None:
        if "alert:assign:any" not in ctx.permissions:
            raise AuthError(403, "forbidden", "Action non autorisée pour votre profil.")
        a.assigned_to = body.assigned_to
    if body.investigation_id is not None:
        a.investigation_id = body.investigation_id
    if body.status is not None:
        if body.status in (AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE):
            if not (body.resolution_note or a.resolution_note):
                raise AuthError(422, "note_required", "Une note de résolution est obligatoire.")
            a.resolution_note = body.resolution_note or a.resolution_note
            a.resolved_at = datetime.now(UTC)
        a.status = body.status
        emit(db, E.ALERT_STATUS_CHANGED, user_id=ctx.user.id, metadata={"alert_id": str(a.id),
                                                                           "status": str(body.status)})
    record_audit(db, action="ALERT_UPDATED", target_type="alert", target_id=a.id, actor_id=ctx.user.id,
                 before=before, after={"status": str(a.status), "assigned_to": str(a.assigned_to or "")},
                 justification=body.resolution_note, ip_address=client_ip(request))
    db.commit()
    return _alert(a)


# ---- actions de sécurité ---------------------------------------------------------------------------
@router.get("/actions", summary="Actions de sécurité")
def actions(limit: int = Query(50, ge=1, le=200),
            _: AuthContext = Depends(require_permission("security_action:read:any")),
            db: DbSession = Depends(get_db)):
    return [_action(a) for a in db.scalars(select(SecurityAction).order_by(SecurityAction.created_at.desc())
                                           .limit(limit))]


@router.post("/actions", summary="Exécuter une action de sécurité")
def run_action(body: ActionIn, request: Request, alert_id: uuid.UUID | None = None,
               ctx: AuthContext = Depends(require_permission("security_action:execute:any")),
               db: DbSession = Depends(get_db)):
    if body.action_type not in ANALYST_ACTIONS:
        raise AuthError(403, "forbidden", "Cette action est réservée à l'administration.")
    return _perform(db, ctx, body, alert_id, request)


@router.post("/admin-actions", summary="Exécuter une action de sécurité (administration)")
def run_admin_action(body: ActionIn, request: Request, alert_id: uuid.UUID | None = None,
                     ctx: AuthContext = Depends(require_permission("security_action:execute_admin:any")),
                     db: DbSession = Depends(get_db)):
    return _perform(db, ctx, body, alert_id, request)


def _perform(db: DbSession, ctx: AuthContext, body: ActionIn, alert_id: uuid.UUID | None, request: Request):
    alert = db.get(SecurityAlert, alert_id) if alert_id else None
    owner = _owner(db, body.action_type, body.target_id)
    row = resp.execute_action(db, body.action_type, target_id=body.target_id, user=owner, alert=alert, by=ctx.user,
                              justification=body.justification)
    if row.status == SecurityActionStatus.FAILED:
        db.commit()
        raise AuthError(404, "target_not_found", "Cible introuvable.")
    db.commit()
    return _action(row)


def _owner(db: DbSession, action: SecurityActionType, target_id: uuid.UUID) -> User | None:
    from app.models import Session as AuthSession
    model = {SecurityActionType.LOCK_CARD: Card, SecurityActionType.BLOCK_DEVICE: Device,
             SecurityActionType.FREEZE_ACCOUNT: Account, SecurityActionType.REVOKE_SESSION: AuthSession}.get(action)
    if model is None:
        return db.get(User, target_id)
    obj = db.get(model, target_id)
    return db.get(User, obj.user_id) if obj is not None else None


@router.post("/actions/{action_id}/revert", summary="Annuler une action réversible")
def revert(action_id: uuid.UUID, body: RevertIn,
           ctx: AuthContext = Depends(require_permission("security_action:execute:any")),
           db: DbSession = Depends(get_db)):
    row = db.get(SecurityAction, action_id)
    if row is None:
        raise AuthError(404, "action_not_found", "Action introuvable.")
    if row.action_type in (SecurityActionType.FREEZE_ACCOUNT, SecurityActionType.FORCE_PASSWORD_RESET) and \
            "security_action:execute_admin:any" not in ctx.permissions:
        raise AuthError(403, "forbidden", "Cette action est réservée à l'administration.")
    try:
        resp.revert_action(db, row, ctx.user, body.justification)
    except ValueError as exc:
        raise AuthError(409, "not_revertible", str(exc)) from exc
    db.commit()
    return _action(row)


# ---- investigations ---------------------------------------------------------------------------------
@router.get("/investigations", summary="Investigations")
def investigations(_: AuthContext = Depends(require_permission("investigation:read:any")),
                   db: DbSession = Depends(get_db)):
    rows = db.scalars(select(Investigation).order_by(Investigation.created_at.desc()).limit(100))
    return [{"id": i.id, "title": i.title, "status": i.status, "lead": i.lead_analyst_id, "summary": i.summary,
             "created_at": i.created_at, "closed_at": i.closed_at} for i in rows]


@router.post("/investigations", status_code=201, summary="Ouvrir une investigation")
def open_investigation(body: InvestigationIn, ctx: AuthContext = Depends(require_permission("investigation:write:any")),
                       db: DbSession = Depends(get_db)):
    inv = Investigation(title=body.title, lead_analyst_id=ctx.user.id)
    db.add(inv)
    db.flush()
    for alert in db.scalars(select(SecurityAlert).where(SecurityAlert.id.in_(body.alert_ids))):
        alert.investigation_id = inv.id
        if alert.status == AlertStatus.NEW:
            alert.status = AlertStatus.INVESTIGATING
    record_audit(db, action="INVESTIGATION_OPENED", target_type="investigation", target_id=inv.id,
                 actor_id=ctx.user.id, after={"alerts": len(body.alert_ids)})
    db.commit()
    return {"id": inv.id, "title": inv.title, "status": inv.status}


@router.get("/investigations/{inv_id}", summary="Détail d'une investigation")
def investigation(inv_id: uuid.UUID, _: AuthContext = Depends(require_permission("investigation:read:any")),
                  db: DbSession = Depends(get_db)):
    inv = db.get(Investigation, inv_id)
    if inv is None:
        raise AuthError(404, "investigation_not_found", "Investigation introuvable.")
    notes = db.scalars(select(InvestigationNote).where(InvestigationNote.investigation_id == inv.id)
                       .order_by(InvestigationNote.created_at))
    alerts_ = db.scalars(select(SecurityAlert).where(SecurityAlert.investigation_id == inv.id))
    return {"id": inv.id, "title": inv.title, "status": inv.status, "summary": inv.summary,
            "notes": [{"id": n.id, "author": n.author_id, "note": n.note, "created_at": n.created_at} for n in notes],
            "alerts": [_alert(a) for a in alerts_]}


@router.post("/investigations/{inv_id}/notes", status_code=201, summary="Ajouter une note")
def add_note(inv_id: uuid.UUID, body: NoteIn, ctx: AuthContext = Depends(require_permission("investigation:write:any")),
             db: DbSession = Depends(get_db)):
    if db.get(Investigation, inv_id) is None:
        raise AuthError(404, "investigation_not_found", "Investigation introuvable.")
    db.add(InvestigationNote(investigation_id=inv_id, author_id=ctx.user.id, note=body.note))
    db.commit()
    return {"ok": True}


@router.post("/investigations/{inv_id}/close", summary="Clôturer une investigation")
def close_investigation(inv_id: uuid.UUID, body: CloseIn,
                        ctx: AuthContext = Depends(require_permission("investigation:write:any")),
                        db: DbSession = Depends(get_db)):
    inv = db.get(Investigation, inv_id)
    if inv is None:
        raise AuthError(404, "investigation_not_found", "Investigation introuvable.")
    inv.status, inv.summary, inv.closed_at = InvestigationStatus.CLOSED, body.summary, datetime.now(UTC)
    record_audit(db, action="INVESTIGATION_CLOSED", target_type="investigation", target_id=inv.id,
                 actor_id=ctx.user.id, justification=body.summary)
    db.commit()
    return {"id": inv.id, "status": inv.status}


# ---- événements, risque, statistiques --------------------------------------------------------------
@router.get("/events", summary="Recherche d'événements de sécurité")
def events(event_type: str | None = None, category: str | None = None, severity: Severity | None = None,
           user_id: uuid.UUID | None = None, simulation_run_id: uuid.UUID | None = None,
           before_seq: int | None = None, limit: int = Query(100, ge=1, le=500),
           _: AuthContext = Depends(require_permission("security_event:read:any")), db: DbSession = Depends(get_db)):
    q = select(SecurityEvent).order_by(SecurityEvent.seq.desc()).limit(limit)
    for col, val in ((SecurityEvent.event_type, event_type), (SecurityEvent.category, category),
                     (SecurityEvent.severity, severity), (SecurityEvent.user_id, user_id),
                     (SecurityEvent.simulation_run_id, simulation_run_id)):
        if val is not None:
            q = q.where(col == val)
    if before_seq:
        q = q.where(SecurityEvent.seq < before_seq)
    return [_event(e) for e in db.scalars(q)]


@router.get("/risk-assessments", summary="Évaluations de risque")
def assessments(user_id: uuid.UUID | None = None, limit: int = Query(50, ge=1, le=200),
                _: AuthContext = Depends(require_permission("risk:read:any")), db: DbSession = Depends(get_db)):
    q = select(RiskAssessment).order_by(RiskAssessment.created_at.desc()).limit(limit)
    if user_id:
        q = q.where(RiskAssessment.user_id == user_id)
    return [{"id": r.id, "user_id": r.user_id, "operation": r.operation_type, "score": r.score, "level": r.level,
             "decision": r.decision, "reasons": r.reasons, "ai_score": r.ai_score, "model_version": r.model_version,
             "degraded": r.degraded, "created_at": r.created_at} for r in db.scalars(q)]


@router.get("/stats", summary="Indicateurs de sécurité")
def stats(hours: int = Query(24, ge=1, le=720),
          _: AuthContext = Depends(require_permission("stats:read_security:any")), db: DbSession = Depends(get_db)):
    since = datetime.now(UTC) - timedelta(hours=hours)
    by_sev = dict(db.execute(select(SecurityAlert.severity, func.count()).where(SecurityAlert.created_at >= since)
                             .group_by(SecurityAlert.severity)).all())
    by_status = dict(db.execute(select(SecurityAlert.status, func.count()).group_by(SecurityAlert.status)).all())
    by_cat = dict(db.execute(select(SecurityEvent.category, func.count()).where(SecurityEvent.timestamp >= since)
                             .group_by(SecurityEvent.category)).all())
    by_decision = dict(db.execute(select(RiskAssessment.decision, func.count())
                                  .where(RiskAssessment.created_at >= since).group_by(RiskAssessment.decision)).all())
    reasons: dict[str, int] = {}
    for (rs,) in db.execute(select(RiskAssessment.reasons).where(RiskAssessment.created_at >= since)):
        for r in rs:
            reasons[r["code"]] = reasons.get(r["code"], 0) + 1
    blocked = db.scalar(select(func.count()).select_from(SecurityEvent).where(
        SecurityEvent.timestamp >= since, SecurityEvent.event_type.in_(
            ["TRANSFER_BLOCKED", "CARD_PAYMENT_BLOCKED", "WITHDRAWAL_BLOCKED"]))) or 0
    hourly = db.execute(select(func.date_trunc("hour", SecurityEvent.timestamp).label("h"), func.count())
                        .where(SecurityEvent.timestamp >= since).group_by("h").order_by("h")).all()
    return {"hours": hours, "alerts_by_severity": {str(k): v for k, v in by_sev.items()},
            "alerts_by_status": {str(k): v for k, v in by_status.items()},
            "events_by_category": by_cat, "decisions": {str(k): v for k, v in by_decision.items()},
            "top_rules": sorted(({"code": k, "count": v} for k, v in reasons.items()), key=lambda x: -x["count"])[:8],
            "blocked_operations": blocked,
            "events_per_hour": [{"hour": h, "count": c} for h, c in hourly],
            "open_alerts": sum(v for k, v in by_status.items() if k in (AlertStatus.NEW, AlertStatus.TRIAGED,
                                                                         AlertStatus.INVESTIGATING))}


# ---- dossier client (accès tracé et évalué) ---------------------------------------------------------
@router.get("/users", summary="Rechercher un utilisateur")
def users(q: str = Query(min_length=2, max_length=60), _: AuthContext = Depends(require_permission("account:read:any")),
          db: DbSession = Depends(get_db)):
    like = f"%{q}%"
    rows = db.scalars(select(User).where((User.email.ilike(like)) | (User.last_name.ilike(like))
                                         | (User.first_name.ilike(like)), User.user_type != "SYSTEM").limit(20))
    return [{"id": u.id, "name": u.full_name, "email": u.email, "type": u.user_type, "status": u.status} for u in rows]


@router.get("/customers/{user_id}", summary="Dossier client (consultation tracée)")
def customer(user_id: uuid.UUID, request: Request, ctx: AuthContext = Depends(require_permission("account:read:any")),
             db: DbSession = Depends(get_db)):
    u = db.get(User, user_id)
    if u is None:
        raise AuthError(404, "user_not_found", "Utilisateur introuvable.")
    record_staff_access(db, ctx.user, ctx.session, u.id, purpose="soc_customer_view", ip=client_ip(request))
    db.commit()
    return customer_file(db, u)


def customer_file(db: DbSession, u: User) -> dict[str, Any]:
    accounts = db.scalars(select(Account).where(Account.user_id == u.id, Account.account_type != AccountType.INTERNAL))
    cards = db.scalars(select(Card).where(Card.user_id == u.id))
    devices = db.scalars(select(Device).where(Device.user_id == u.id))
    transfers = db.scalars(select(Transfer).where(Transfer.user_id == u.id)
                           .order_by(Transfer.created_at.desc()).limit(10))
    payments = db.scalars(select(CardPayment).where(CardPayment.user_id == u.id)
                          .order_by(CardPayment.occurred_at.desc()).limit(10))
    withdrawals = db.scalars(select(Withdrawal).where(Withdrawal.user_id == u.id)
                             .order_by(Withdrawal.created_at.desc()).limit(10))
    return {
        "user": {"id": u.id, "name": u.full_name, "email": u.email, "city": u.city, "status": u.status,
                 "type": u.user_type},
        "accounts": [{"id": a.id, "label": a.label, "balance": a.balance, "available": a.available_balance,
                      "status": a.status, "iban_masked": f"{a.iban[:4]} •••• {a.iban[-4:]}"} for a in accounts],
        "cards": [{"id": c.id, "masked_pan": c.masked_pan, "status": c.status, "blocked_reason": c.blocked_reason}
                  for c in cards],
        "devices": [{"id": d.id, "name": d.name, "status": d.status, "city": d.last_city, "last_seen": d.last_seen}
                    for d in devices],
        "transfers": [{"id": t.id, "amount": t.amount, "status": t.status, "date": t.created_at,
                       "risk_score": t.risk_score} for t in transfers],
        "payments": [{"id": p.id, "merchant": p.merchant_name, "amount": p.amount, "status": p.status,
                      "date": p.occurred_at} for p in payments],
        "withdrawals": [{"id": w.id, "type": w.withdrawal_type, "amount": w.amount, "status": w.status,
                         "city": w.city, "date": w.created_at} for w in withdrawals],
    }


# ---- ATM ---------------------------------------------------------------------------------------------
class AtmFlag(Strict):
    suspicious: bool
    justification: Text


@router.post("/atms/{atm_id}/flag", summary="Marquer ou démarquer un ATM suspect")
def flag_atm(atm_id: uuid.UUID, body: AtmFlag, ctx: AuthContext = Depends(require_permission("atm:flag:any")),
             db: DbSession = Depends(get_db)):
    atm = db.get(ATM, atm_id)
    if atm is None:
        raise AuthError(404, "atm_not_found", "Distributeur introuvable.")
    before = str(atm.status)
    atm.status = AtmStatus.SUSPICIOUS if body.suspicious else AtmStatus.ONLINE
    record_audit(db, action="ATM_FLAGGED", target_type="atm", target_id=atm.id, actor_id=ctx.user.id,
                 before={"status": before}, after={"status": str(atm.status)}, justification=body.justification)
    db.commit()
    return {"id": atm.id, "status": atm.status}
