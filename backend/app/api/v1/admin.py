"""Administration : règles de risque, politiques, utilisateurs, comptes, ATM, réinitialisation MFA, audit."""
from __future__ import annotations

import csv
import io
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session as DbSession

from app.core.config import get_settings
from app.core.database import get_db
from app.events.audit import record_audit, verify_audit_chain
from app.events.catalog import EventType as E
from app.events.logger import emit
from app.models import (
    ATM,
    Account,
    AuditLog,
    MFAConfiguration,
    RecoveryCode,
    RiskRule,
    SecurityPolicy,
    User,
)
from app.models import Session as AuthSession
from app.models.enums import (
    AccountStatus,
    AtmStatus,
    PolicyDecision,
    SessionStatus,
    UserStatus,
    UserType,
)
from app.security.auth.deps import (
    AuthContext,
    check_origin,
    client_ip,
    get_auth_context,
    require_aal,
    require_permission,
)
from app.security.auth.errors import AuthError

router = APIRouter(prefix="/admin", tags=["Administration"], dependencies=[Depends(check_origin)])
audit_router = APIRouter(prefix="/audit", tags=["Audit"], dependencies=[Depends(check_origin)])
Note = Annotated[str, StringConstraints(strip_whitespace=True, min_length=5, max_length=1000)]
STAFF_AAL = Depends(require_aal(2))


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RulePatch(Strict):
    weight: int | None = Field(default=None, ge=-50, le=50)
    enabled: bool | None = None
    params: dict[str, Any] | None = None
    justification: Note


class PolicyPatch(Strict):
    decision: PolicyDecision | None = None
    floor_decision: PolicyDecision | None = None
    actions: list[str] | None = None
    enabled: bool | None = None
    justification: Note


class StatusIn(Strict):
    status: str
    justification: Note


def _admin_audit(db: DbSession, ctx: AuthContext, request: Request, action: str, target_type: str,
                 target_id: Any, before: dict, after: dict, why: str) -> None:
    record_audit(db, action=action, target_type=target_type, target_id=target_id, actor_id=ctx.user.id,
                 actor_role=",".join(sorted(r.code for r in ctx.user.roles)), before=before, after=after,
                 justification=why, ip_address=client_ip(request))


# ---- règles et politiques --------------------------------------------------------------------------
@router.get("/risk-rules", summary="Règles de risque")
def rules(_: AuthContext = Depends(require_permission("risk_policy:read:any")), db: DbSession = Depends(get_db)):
    return [{"id": r.id, "code": r.code, "description": r.description, "operations": r.operation_types,
             "weight": r.weight, "params": r.params, "enabled": r.enabled, "version": r.version}
            for r in db.scalars(select(RiskRule).order_by(RiskRule.code))]


@router.patch("/risk-rules/{rule_id}", summary="Modifier une règle de risque")
def patch_rule(rule_id: uuid.UUID, body: RulePatch, request: Request,
               ctx: AuthContext = Depends(require_permission("risk_policy:update:any")), _: object = STAFF_AAL,
               db: DbSession = Depends(get_db)):
    r = db.get(RiskRule, rule_id)
    if r is None:
        raise AuthError(404, "rule_not_found", "Règle introuvable.")
    before = {"weight": r.weight, "enabled": r.enabled, "params": r.params, "version": r.version}
    if body.weight is not None:
        r.weight = body.weight
    if body.enabled is not None:
        r.enabled = body.enabled
    if body.params is not None:
        r.params = body.params
    r.version += 1
    emit(db, E.RISK_RULE_UPDATED, user_id=ctx.user.id, metadata={"rule": r.code})
    _admin_audit(db, ctx, request, "RISK_RULE_UPDATED", "risk_rule", r.id, before,
                 {"weight": r.weight, "enabled": r.enabled, "params": r.params, "version": r.version},
                 body.justification)
    db.commit()
    return {"id": r.id, "code": r.code, "weight": r.weight, "enabled": r.enabled, "version": r.version}


@router.get("/policies", summary="Politiques de sécurité")
def policies(_: AuthContext = Depends(require_permission("risk_policy:read:any")), db: DbSession = Depends(get_db)):
    return [{"id": p.id, "operation": p.operation_type, "level": p.risk_level, "decision": p.decision,
             "floor": p.floor_decision, "actions": p.actions, "enabled": p.enabled, "version": p.version}
            for p in db.scalars(select(SecurityPolicy).order_by(SecurityPolicy.operation_type,
                                                                 SecurityPolicy.risk_level))]


@router.patch("/policies/{policy_id}", summary="Modifier une politique")
def patch_policy(policy_id: uuid.UUID, body: PolicyPatch, request: Request,
                 ctx: AuthContext = Depends(require_permission("risk_policy:update:any")), _: object = STAFF_AAL,
                 db: DbSession = Depends(get_db)):
    p = db.get(SecurityPolicy, policy_id)
    if p is None:
        raise AuthError(404, "policy_not_found", "Politique introuvable.")
    before = {"decision": str(p.decision), "floor": str(p.floor_decision), "actions": p.actions,
              "enabled": p.enabled}
    if body.decision is not None:
        p.decision = body.decision
    if body.floor_decision is not None:
        p.floor_decision = body.floor_decision
    if body.actions is not None:
        p.actions = body.actions
    if body.enabled is not None:
        p.enabled = body.enabled
    p.version += 1
    _admin_audit(db, ctx, request, "SECURITY_POLICY_UPDATED", "security_policy", p.id, before,
                 {"decision": str(p.decision), "floor": str(p.floor_decision), "actions": p.actions,
                  "enabled": p.enabled}, body.justification)
    db.commit()
    return {"id": p.id, "decision": p.decision, "version": p.version}


# ---- utilisateurs, comptes, ATM ---------------------------------------------------------------------
@router.get("/users", summary="Utilisateurs")
def users(_: AuthContext = Depends(require_permission("user:read:any")), db: DbSession = Depends(get_db)):
    return [{"id": u.id, "name": u.full_name, "email": u.email, "type": u.user_type, "status": u.status,
             "roles": sorted(r.code for r in u.roles), "last_login_at": u.last_login_at}
            for u in db.scalars(select(User).where(User.user_type != UserType.SYSTEM).order_by(User.last_name))]


@router.post("/users/{user_id}/status", summary="Activer ou désactiver un utilisateur")
def user_status(user_id: uuid.UUID, body: StatusIn, request: Request,
                ctx: AuthContext = Depends(require_permission("user:manage:any")), _: object = STAFF_AAL,
                db: DbSession = Depends(get_db)):
    u = db.get(User, user_id)
    if u is None or u.user_type == UserType.SYSTEM:
        raise AuthError(404, "user_not_found", "Utilisateur introuvable.")
    if u.id == ctx.user.id:
        raise AuthError(409, "self_change", "Vous ne pouvez pas modifier votre propre statut.")
    if body.status not in (UserStatus.ACTIVE, UserStatus.DISABLED):
        raise AuthError(422, "invalid_status", "Statut invalide.")
    before = str(u.status)
    u.status = UserStatus(body.status)
    if u.status == UserStatus.DISABLED:
        db.execute(update(AuthSession).where(AuthSession.user_id == u.id, AuthSession.status == SessionStatus.ACTIVE)
                   .values(status=SessionStatus.REVOKED, revoked_at=datetime.now(UTC), revoked_reason="user_disabled"))
    _admin_audit(db, ctx, request, "USER_STATUS_CHANGED", "user", u.id, {"status": before}, {"status": body.status},
                 body.justification)
    db.commit()
    return {"id": u.id, "status": u.status}


@router.post("/users/{user_id}/mfa-reset", summary="Réinitialiser la MFA d'un utilisateur")
def mfa_reset(user_id: uuid.UUID, body: StatusIn, request: Request,
              ctx: AuthContext = Depends(require_permission("mfa:reset:any")), _: object = STAFF_AAL,
              db: DbSession = Depends(get_db)):
    from app.models.enums import PolicyDecision as D
    from app.models.enums import RiskLevel
    from app.risk import response as resp
    from app.risk.engine import RiskResult
    u = db.get(User, user_id)
    if u is None or u.id == ctx.user.id:
        raise AuthError(404, "user_not_found", "Utilisateur introuvable.")
    db.execute(delete(MFAConfiguration).where(MFAConfiguration.user_id == u.id))
    db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == u.id))
    db.execute(update(AuthSession).where(AuthSession.user_id == u.id, AuthSession.status == SessionStatus.ACTIVE)
               .values(status=SessionStatus.REVOKED, revoked_at=datetime.now(UTC), revoked_reason="mfa_reset"))
    emit(db, E.MFA_DISABLED, user_id=u.id, metadata={"by": str(ctx.user.id), "reason": "admin_reset"})
    resp.raise_alert(db, user_id=u.id, title="Réinitialisation MFA par un administrateur",
                     result=RiskResult(40, RiskLevel.MEDIUM, D.ALLOW_AND_MONITOR, [],
                                       [{"code": "ADMIN_MFA_RESET", "points": 40, "detail": body.justification}]))
    resp.notify(db, u.id, "MFA_RESET", "Votre authentification à deux facteurs a été réinitialisée",
                "Un administrateur a réinitialisé votre MFA. Reconfigurez-la à la prochaine connexion.")
    _admin_audit(db, ctx, request, "MFA_RESET", "user", u.id, {}, {"mfa": "removed"}, body.justification)
    db.commit()
    return {"id": u.id, "mfa": "reset"}


@router.post("/accounts/{account_id}/status", summary="Suspendre, bloquer ou réactiver un compte")
def account_status(account_id: uuid.UUID, body: StatusIn, request: Request,
                   ctx: AuthContext = Depends(require_permission("account:update_status:any")),
                   _: object = STAFF_AAL, db: DbSession = Depends(get_db)):
    a = db.get(Account, account_id)
    if a is None:
        raise AuthError(404, "account_not_found", "Compte introuvable.")
    if body.status not in (AccountStatus.ACTIVE, AccountStatus.SUSPENDED, AccountStatus.BLOCKED):
        raise AuthError(422, "invalid_status", "Statut invalide.")
    before = str(a.status)
    a.status = AccountStatus(body.status)
    emit(db, E.ACCOUNT_FROZEN if a.status != AccountStatus.ACTIVE else E.ACCOUNT_UNFROZEN, user_id=a.user_id)
    _admin_audit(db, ctx, request, "ACCOUNT_STATUS_CHANGED", "account", a.id, {"status": before},
                 {"status": body.status}, body.justification)
    db.commit()
    return {"id": a.id, "status": a.status}


@router.post("/atms/{atm_id}/status", summary="Changer l'état d'un ATM")
def atm_status(atm_id: uuid.UUID, body: StatusIn, request: Request,
               ctx: AuthContext = Depends(require_permission("atm:manage:any")), _: object = STAFF_AAL,
               db: DbSession = Depends(get_db)):
    atm = db.get(ATM, atm_id)
    if atm is None:
        raise AuthError(404, "atm_not_found", "Distributeur introuvable.")
    if body.status not in {s.value for s in AtmStatus}:
        raise AuthError(422, "invalid_status", "Statut invalide.")
    before = str(atm.status)
    atm.status = AtmStatus(body.status)
    _admin_audit(db, ctx, request, "ATM_STATUS_CHANGED", "atm", atm.id, {"status": before},
                 {"status": body.status}, body.justification)
    db.commit()
    return {"id": atm.id, "status": atm.status}


@router.get("/config", summary="Configuration de sécurité effective (sans secret)")
def config(_: AuthContext = Depends(require_permission("risk_policy:read:any"))):
    s = get_settings()
    return {"risk_thresholds": {"medium": s.risk_medium_from, "high": s.risk_high_from,
                                "critical": s.risk_critical_from},
            "lab_mode": s.lab_mode, "access_token_seconds": s.jwt_access_ttl_seconds,
            "refresh_idle_seconds": s.refresh_idle_ttl_seconds,
            "session_absolute_seconds": s.session_absolute_ttl_seconds}


# ---- audit ----------------------------------------------------------------------------------------
def _audit_row(a: AuditLog) -> dict[str, Any]:
    return {"seq": a.seq, "timestamp": a.timestamp, "actor_id": a.actor_id, "actor_role": a.actor_role,
            "actor_type": a.actor_type, "action": a.action, "target_type": a.target_type, "target_id": a.target_id,
            "before": a.before, "after": a.after, "justification": a.justification, "hash": a.hash}


def _audit_query(ctx: AuthContext, limit: int, before_seq: int | None, action: str | None):
    if "audit:read:any" not in ctx.permissions and "audit:read_security:any" not in ctx.permissions:
        raise AuthError(403, "forbidden", "Action non autorisée pour votre profil.")
    q = select(AuditLog).order_by(AuditLog.seq.desc()).limit(limit)
    if "audit:read:any" not in ctx.permissions:       # analyste : périmètre sécurité uniquement
        q = q.where(AuditLog.target_type.in_(["alert", "investigation", "card", "session", "device", "atm", "user"]))
    if before_seq:
        q = q.where(AuditLog.seq < before_seq)
    if action:
        q = q.where(AuditLog.action.ilike(f"%{action}%"))
    return q


@audit_router.get("/logs", summary="Journal d'audit")
def audit_logs(limit: int = Query(100, ge=1, le=500), before_seq: int | None = None, action: str | None = None,
               ctx: AuthContext = Depends(get_auth_context),
               db: DbSession = Depends(get_db)):
    return [_audit_row(a) for a in db.scalars(_audit_query(ctx, limit, before_seq, action))]


@audit_router.get("/verify", summary="Vérifier l'intégrité de la chaîne d'audit")
def audit_verify(ctx: AuthContext = Depends(get_auth_context), db: DbSession = Depends(get_db)):
    _audit_query(ctx, 1, None, None)          # même contrôle de droits que la lecture du journal
    report = verify_audit_chain(db)
    return {"valid": report.valid, "entries": report.entries, "broken_at_seq": report.broken_at_seq}


@audit_router.get("/export", summary="Exporter le journal d'audit (CSV)")
def audit_export(request: Request, ctx: AuthContext = Depends(require_permission("audit:export:any")),
                 db: DbSession = Depends(get_db)):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["seq", "timestamp", "actor_role", "action", "target_type", "target_id", "justification", "hash"])
    for a in db.scalars(select(AuditLog).order_by(AuditLog.seq)):
        w.writerow([a.seq, a.timestamp.isoformat(), a.actor_role or "", a.action, a.target_type, a.target_id or "",
                    (a.justification or "").replace("\n", " "), a.hash])
    record_audit(db, action="AUDIT_EXPORTED", target_type="audit", actor_id=ctx.user.id, ip_address=client_ip(request))
    db.commit()
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="audit.csv"'})
