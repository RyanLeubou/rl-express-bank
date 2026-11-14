"""Règles de risque explicables. Chaque évaluateur retourne None (non déclenchée) ou le détail lisible
qui justifie la règle ; le poids vient de la table `risk_rules` (modifiable par l'administrateur).
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import distinct, func, select
from sqlalchemy.orm import Session

from app.models import (
    Beneficiary,
    SecurityEvent,
    SupportConversation,
    Transfer,
    Withdrawal,
)
from app.models.enums import AtmStatus
from app.risk.context import OperationContext
from app.risk.geo import distance_km
from app.risk.state import LOCAL_OFFSET, Baseline


@dataclass
class RuleEnv:
    db: Session
    ctx: OperationContext
    base: Baseline
    params: dict


def _local_hour(env: RuleEnv) -> int:
    return (env.ctx.occurred_at + LOCAL_OFFSET).hour


def new_device(env: RuleEnv) -> str | None:
    d = env.ctx.device
    if d is not None and d.id not in env.base.known_devices:
        return f"Appareil « {d.name} » non reconnu comme de confiance"
    return None


def new_location(env: RuleEnv) -> str | None:
    city = env.ctx.city
    if env.base.cold_start or not city or env.base.cities.get(city):
        return None
    return f"Ville « {city} » absente de l'historique du client"


def unusual_amount(env: RuleEnv) -> str | None:
    amount, kind = env.ctx.amount, env.ctx.kind
    if not amount or env.base.cold_start:
        return None
    p95 = env.base.percentile(kind, env.params.get("percentile", 95))
    if p95 and amount > p95:
        return f"{amount} XAF dépasse le 95e centile habituel ({p95} XAF)"
    return None


def unusual_time(env: RuleEnv) -> str | None:
    hour = _local_hour(env)
    total = sum(env.base.hours.values())
    if env.base.cold_start or total < 10:
        return None
    if env.base.hours.get(hour, 0) == 0 and (hour < 6 or hour >= 22 or env.base.hours.get(hour, 0) / total < 0.01):
        return f"Heure inhabituelle ({hour:02d} h) pour ce client"
    return None


def multiple_withdrawals(env: RuleEnv) -> str | None:
    window = timedelta(minutes=env.params.get("window_minutes", 60))
    n = env.db.scalar(select(func.count()).select_from(Withdrawal).where(
        Withdrawal.user_id == env.ctx.user.id, Withdrawal.created_at >= env.ctx.occurred_at - window)) or 0
    need = env.params.get("count", 3)
    return f"{n + 1} tentatives de retrait en {window.seconds // 60} min" if n + 1 >= need else None


def recent_beneficiary(env: RuleEnv) -> str | None:
    b = env.ctx.beneficiary
    if b is None:
        return None
    since = b.activated_at or b.created_at
    if env.ctx.occurred_at - since < timedelta(hours=env.params.get("hours", 24)):
        return "Bénéficiaire ajouté il y a moins de 24 h"
    return None


def failed_logins_recent(env: RuleEnv) -> str | None:
    window = timedelta(minutes=env.params.get("window_minutes", 30))
    n = env.db.scalar(select(func.count()).select_from(SecurityEvent).where(
        SecurityEvent.user_id == env.ctx.user.id, SecurityEvent.event_type == "LOGIN_FAILED",
        SecurityEvent.timestamp >= env.ctx.occurred_at - window)) or 0
    return f"{n} échecs de connexion récents" if n >= env.params.get("count", 3) else None


def impossible_travel(env: RuleEnv) -> str | None:
    city = env.ctx.city
    if not city:
        return None
    last = next((o for o in reversed(env.base.ops) if o.city and o.at < env.ctx.occurred_at), None)
    if last is None or last.city == city:
        return None
    km = distance_km(last.city, city)
    hours = max((env.ctx.occurred_at - last.at).total_seconds() / 3600, 1 / 60)
    if km and km / hours > env.params.get("max_speed_kmh", 900):
        return f"{last.city} → {city} ({round(km)} km) en {round(hours * 60)} min"
    return None


def scam_signal(env: RuleEnv) -> str | None:
    since = env.ctx.occurred_at - timedelta(hours=env.params.get("hours", 24))
    found = env.db.scalar(select(func.count()).select_from(SupportConversation).where(
        SupportConversation.user_id == env.ctx.user.id, SupportConversation.scam_signal.is_(True),
        SupportConversation.updated_at >= since))
    return "Arnaque déclarée à RL SOLUTION il y a moins de 24 h" if found else None


def strong_auth(env: RuleEnv) -> str | None:
    return "Authentification forte vérifiée" if env.ctx.strong_auth else None


def mule_beneficiary(env: RuleEnv) -> str | None:
    b = env.ctx.beneficiary
    if b is None:
        return None
    since = env.ctx.occurred_at - timedelta(days=env.params.get("days", 7))
    senders = env.db.scalar(select(func.count(distinct(Beneficiary.user_id))).where(
        Beneficiary.iban == b.iban, Beneficiary.user_id != env.ctx.user.id, Beneficiary.created_at >= since)) or 0
    senders += env.db.scalar(select(func.count(distinct(Transfer.user_id))).join(
        Beneficiary, Beneficiary.id == Transfer.beneficiary_id).where(
        Beneficiary.iban == b.iban, Transfer.user_id != env.ctx.user.id, Transfer.created_at >= since)) or 0
    return f"{senders} autres clients ciblent ce même compte" if senders >= env.params.get(
        "distinct_senders", 3) else None


def drain_balance(env: RuleEnv) -> str | None:
    a, acc = env.ctx.amount, env.ctx.account
    if not a or acc is None or a < env.params.get("min_amount", 100_000):
        return None
    if acc.balance and a >= env.params.get("share", 0.8) * acc.balance:
        return f"{round(100 * a / acc.balance)} % du solde"
    return None


def security_change_recent(env: RuleEnv) -> str | None:
    since = env.ctx.occurred_at - timedelta(hours=env.params.get("hours", 24))
    n = env.db.scalar(select(func.count()).select_from(SecurityEvent).where(
        SecurityEvent.user_id == env.ctx.user.id, SecurityEvent.timestamp >= since,
        SecurityEvent.event_type.in_(["PASSWORD_CHANGED", "MFA_DISABLED", "MFA_ENABLED", "DEVICE_TRUSTED"])))
    return "Réglage de sécurité modifié il y a moins de 24 h" if n else None


def suspicious_atm(env: RuleEnv) -> str | None:
    atm = env.ctx.atm
    return f"ATM {atm.atm_code} marqué suspect" if atm and atm.status == AtmStatus.SUSPICIOUS else None


def staff_bulk_access(env: RuleEnv) -> str | None:
    window = timedelta(minutes=env.params.get("window_minutes", 15))
    n = env.db.scalar(select(func.count(distinct(SecurityEvent.metadata_["customer_id"].astext))).where(
        SecurityEvent.user_id == env.ctx.user.id, SecurityEvent.event_type == "STAFF_CUSTOMER_ACCESSED",
        SecurityEvent.timestamp >= env.ctx.occurred_at - window)) or 0
    return f"{n + 1} dossiers clients consultés en {window.seconds // 60} min" if n + 1 >= env.params.get(
        "distinct_customers", 8) else None


def staff_off_hours(env: RuleEnv) -> str | None:
    hour = _local_hour(env)
    start, end = env.params.get("from_hour", 21), env.params.get("to_hour", 6)
    return f"Accès à {hour:02d} h" if hour >= start or hour < end else None


def staff_unassigned(env: RuleEnv) -> str | None:
    return "Aucun ticket assigné ni fenêtre d'accès valide" if env.ctx.extra.get("assigned") is False else None


EVALUATORS: dict[str, Callable[[RuleEnv], str | None]] = {
    "NEW_DEVICE": new_device, "NEW_LOCATION": new_location, "UNUSUAL_AMOUNT": unusual_amount,
    "UNUSUAL_TIME": unusual_time, "MULTIPLE_WITHDRAWALS": multiple_withdrawals,
    "RECENT_BENEFICIARY": recent_beneficiary, "FAILED_LOGINS_RECENT": failed_logins_recent,
    "IMPOSSIBLE_TRAVEL": impossible_travel, "SCAM_SIGNAL_REPORTED": scam_signal,
    "STRONG_AUTH_VERIFIED": strong_auth, "MULE_BENEFICIARY": mule_beneficiary, "DRAIN_BALANCE": drain_balance,
    "SECURITY_CHANGE_RECENT": security_change_recent, "SUSPICIOUS_ATM": suspicious_atm,
    "STAFF_BULK_ACCESS": staff_bulk_access, "STAFF_OFF_HOURS": staff_off_hours,
    "STAFF_UNASSIGNED_ACCESS": staff_unassigned,
}
