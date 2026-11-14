"""Réponse automatisée : notifications, alertes SOC corrélées, actions de sécurité réversibles."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.events.audit import record_audit
from app.events.catalog import EventType as E
from app.events.logger import emit
from app.models import (
    Account,
    AlertEvent,
    Card,
    CardlessCode,
    Device,
    Notification,
    SecurityAction,
    SecurityAlert,
    SecurityEvent,
    User,
    Withdrawal,
)
from app.models import Session as AuthSession
from app.models.enums import (
    AccountStatus,
    ActorType,
    AlertSource,
    CardlessCodeStatus,
    CardStatus,
    DeviceStatus,
    SecurityActionStatus,
    SecurityActionType,
    SessionStatus,
    Severity,
    WithdrawalStatus,
)
from app.risk.engine import RiskResult
from app.services.banking.holds import release_hold

A = SecurityActionType
MITRE = {  # technique ATT&CK la plus représentative de chaque règle (informatif)
    "NEW_DEVICE": "T1078", "IMPOSSIBLE_TRAVEL": "T1078", "FAILED_LOGINS_RECENT": "T1110",
    "MULE_BENEFICIARY": "T1657", "DRAIN_BALANCE": "T1657", "SCAM_SIGNAL_REPORTED": "T1566",
    "RECENT_BENEFICIARY": "T1657", "SECURITY_CHANGE_RECENT": "T1098", "STAFF_BULK_ACCESS": "T1530",
    "STAFF_UNASSIGNED_ACCESS": "T1078", "SUSPICIOUS_ATM": "T1657", "MULTIPLE_WITHDRAWALS": "T1657",
}
_SEV = {"LOW": Severity.LOW, "MEDIUM": Severity.MEDIUM, "HIGH": Severity.HIGH, "CRITICAL": Severity.CRITICAL}


def notify(db: Session, user_id: uuid.UUID, kind: str, title: str, body: str,
           severity: Severity = Severity.INFO) -> Notification:
    n = Notification(user_id=user_id, type=kind, title=title[:120], body=body, severity=severity)
    db.add(n)
    return n


def raise_alert(db: Session, *, user_id: uuid.UUID | None, title: str, result: RiskResult,
                event: SecurityEvent | None = None, source: AlertSource = AlertSource.APP) -> SecurityAlert:
    """Une alerte par utilisateur et par heure : les événements suivants s'y rattachent (corrélation)."""
    now = datetime.now(UTC)
    key = f"{user_id}:{now:%Y%m%d%H}"
    severity = _SEV.get(str(result.level), Severity.MEDIUM)
    alert = db.scalar(select(SecurityAlert).where(SecurityAlert.correlation_key == key))
    if alert is None:
        techniques = sorted({MITRE[r["code"]] for r in result.reasons if r["code"] in MITRE})
        alert = SecurityAlert(user_id=user_id, title=title[:160], severity=severity, risk_score=result.score,
                              risk_level=result.level, reasons=result.reasons, source=source,
                              correlation_key=key, mitre_techniques=techniques)
        try:
            with db.begin_nested():
                db.add(alert)
                db.flush()
        except IntegrityError:
            alert = db.scalar(select(SecurityAlert).where(SecurityAlert.correlation_key == key))
        else:
            emit(db, E.SECURITY_ALERT_CREATED, actor_type=ActorType.SYSTEM, user_id=user_id,
                 risk_score=result.score, metadata={"alert_id": str(alert.id), "title": title})
    elif result.score > (alert.risk_score or 0):
        alert.risk_score, alert.risk_level, alert.reasons = result.score, result.level, result.reasons
        if _rank(severity) > _rank(alert.severity):
            alert.severity = severity
    if event is not None:
        exists = db.get(AlertEvent, (alert.id, event.id))
        if exists is None:
            db.flush()
            db.add(AlertEvent(alert_id=alert.id, security_event_id=event.id))
    return alert


def _rank(s: Severity) -> int:
    return list(Severity).index(Severity(s))


def execute_action(db: Session, action: SecurityActionType, *, target_id: uuid.UUID, user: User | None,
                   alert: SecurityAlert | None = None, by: User | None = None,
                   justification: str | None = None) -> SecurityAction:
    """Exécute une action de sécurité et la trace. `by=None` = décision automatique du système."""
    status, target_type, note = SecurityActionStatus.EXECUTED, "user", justification
    try:
        target_type = _apply(db, action, target_id, user)
    except LookupError as exc:
        status, note = SecurityActionStatus.FAILED, f"{justification or ''} {exc}".strip()
    row = SecurityAction(alert_id=alert.id if alert else None, action_type=action, target_type=target_type,
                         target_id=target_id, executed_by=by.id if by else None, status=status,
                         justification=note)
    db.add(row)
    db.flush()
    emit(db, E.SECURITY_ACTION_EXECUTED, actor_type=ActorType.USER if by else ActorType.SYSTEM,
         user_id=user.id if user else None, metadata={"action": str(action), "status": str(status),
                                                      "target_id": str(target_id)})
    record_audit(db, action=f"SECURITY_ACTION_{action}", target_type=target_type, target_id=target_id,
                 actor_id=by.id if by else None, actor_type=ActorType.USER if by else ActorType.SYSTEM,
                 after={"status": str(status)}, justification=note)
    return row


def _apply(db: Session, action: SecurityActionType, target_id: uuid.UUID, user: User | None) -> str:  # noqa: C901
    if action == A.LOCK_CARD:
        card = db.get(Card, target_id)
        if card is None:
            raise LookupError("carte introuvable")
        card.status, card.blocked_reason = CardStatus.BLOCKED, "SECURITY_LOCK"
        emit(db, E.CARD_LOCKED_BY_SECURITY, actor_type=ActorType.SYSTEM, user_id=card.user_id)
        return "card"
    if action == A.REVOKE_SESSION:
        s = db.get(AuthSession, target_id)
        if s is None:
            raise LookupError("session introuvable")
        s.status, s.revoked_at, s.revoked_reason = SessionStatus.REVOKED, datetime.now(UTC), "security_action"
        return "session"
    if action == A.BLOCK_DEVICE:
        d = db.get(Device, target_id)
        if d is None:
            raise LookupError("appareil introuvable")
        d.status = DeviceStatus.BLOCKED
        emit(db, E.DEVICE_BLOCKED, actor_type=ActorType.SYSTEM, user_id=d.user_id, device_id=d.id)
        return "device"
    if action == A.FREEZE_ACCOUNT:
        a = db.get(Account, target_id)
        if a is None:
            raise LookupError("compte introuvable")
        a.status = AccountStatus.SUSPENDED
        emit(db, E.ACCOUNT_FROZEN, actor_type=ActorType.SYSTEM, user_id=a.user_id)
        return "account"
    if action == A.CANCEL_CARDLESS_CODES:
        n = 0
        for code in db.scalars(select(CardlessCode).where(CardlessCode.user_id == target_id,
                                                           CardlessCode.status == CardlessCodeStatus.ACTIVE)):
            code.status = CardlessCodeStatus.CANCELLED
            if code.hold_id:
                release_hold(db, code.hold_id)
            w = db.get(Withdrawal, code.withdrawal_id)
            if w and w.status == WithdrawalStatus.PENDING:
                w.status = WithdrawalStatus.CANCELLED
            n += 1
        if n:
            emit(db, E.CARDLESS_CODE_CANCELLED, actor_type=ActorType.SYSTEM, user_id=target_id,
                 metadata={"count": n})
        return "user"
    if action == A.FORCE_PASSWORD_RESET:
        u = db.get(User, target_id)
        if u is None:
            raise LookupError("utilisateur introuvable")
        u.must_change_password = True
        return "user"
    if action == A.NOTIFY_CUSTOMER and user is not None:
        notify(db, user.id, "SECURITY_NOTICE", "Activité inhabituelle détectée",
               "Une opération a été interrompue par mesure de sécurité. Si ce n'était pas vous, contactez RL SOLUTION.",
               Severity.HIGH)
    return "user"


def run_policy_actions(db: Session, result: RiskResult, user: User, *, card: Card | None = None,
                       session: AuthSession | None = None, device: Device | None = None,
                       alert: SecurityAlert | None = None) -> list[SecurityAction]:
    """Applique les actions CRITICAL de la politique à leurs cibles naturelles."""
    done: list[SecurityAction] = []
    for name in result.actions:
        action = SecurityActionType(name)
        target: uuid.UUID | None = {
            A.LOCK_CARD: card.id if card else None, A.REVOKE_SESSION: session.id if session else None,
            A.BLOCK_DEVICE: device.id if device else None, A.CANCEL_CARDLESS_CODES: user.id,
            A.NOTIFY_CUSTOMER: user.id, A.FORCE_PASSWORD_RESET: user.id, A.FREEZE_ACCOUNT: None,
        }.get(action)
        if target is not None:
            done.append(execute_action(db, action, target_id=target, user=user, alert=alert))
    return done


def revert_action(db: Session, row: SecurityAction, by: User, justification: str) -> SecurityAction:
    """Annule une action réversible (carte, compte, appareil, mot de passe). Une session révoquée ne revient pas."""
    if row.status != SecurityActionStatus.EXECUTED:
        raise ValueError("Action déjà annulée ou en échec")
    t = row.action_type
    if t == A.LOCK_CARD and (card := db.get(Card, row.target_id)):
        card.status, card.blocked_reason, card.pin_failed_attempts = CardStatus.ACTIVE, None, 0
    elif t == A.FREEZE_ACCOUNT and (acc := db.get(Account, row.target_id)):
        acc.status = AccountStatus.ACTIVE
        emit(db, E.ACCOUNT_UNFROZEN, actor_type=ActorType.USER, user_id=acc.user_id)
    elif t == A.BLOCK_DEVICE and (dev := db.get(Device, row.target_id)):
        dev.status = DeviceStatus.NEW
    elif t == A.FORCE_PASSWORD_RESET and (u := db.get(User, row.target_id)):
        u.must_change_password = False
    else:
        raise ValueError("Cette action n'est pas réversible")
    row.status, row.reverted_at, row.reverted_by = SecurityActionStatus.REVERTED, datetime.now(UTC), by.id
    record_audit(db, action=f"SECURITY_ACTION_REVERTED_{t}", target_type=row.target_type, target_id=row.target_id,
                 actor_id=by.id, justification=justification)
    return row


