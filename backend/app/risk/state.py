"""Profil de référence (baseline) d'un client, calculé à partir de son historique d'événements.

Aucune IA ici : de simples statistiques (percentiles, histogramme des heures, villes, appareils connus).
"""
from __future__ import annotations

import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.auth import Device
from app.models.enums import DeviceStatus
from app.models.security import SecurityEvent

MIN_HISTORY = 10                    # en dessous : « démarrage à froid », règles statistiques neutralisées
LOCAL_OFFSET = timedelta(hours=1)   # Africa/Douala
HISTORY_DAYS = 120
HABIT_DELAY = timedelta(hours=24)
_KINDS = {
    "ATM_WITHDRAWAL": "withdrawal", "CARDLESS_WITHDRAWAL": "withdrawal", "TRANSFER_COMPLETED": "transfer",
    "CARD_PAYMENT_APPROVED": "payment", "USER_LOGIN": "login",
}


@dataclass
class PastOp:
    at: datetime
    kind: str
    amount: int | None
    city: str | None
    device_id: uuid.UUID | None
    atm_id: uuid.UUID | None
    simulated: bool = False


@dataclass
class Baseline:
    ops: list[PastOp] = field(default_factory=list)
    known_devices: set[uuid.UUID] = field(default_factory=set)
    habit_ops: list[PastOp] = field(default_factory=list)
    cities: Counter = field(default_factory=Counter)
    hours: Counter = field(default_factory=Counter)
    cold_start: bool = True

    def amounts(self, kind: str) -> list[int]:
        return sorted(o.amount for o in self.habit_ops if o.kind == kind and o.amount)

    def percentile(self, kind: str, pct: float) -> int | None:
        values = self.amounts(kind)
        if len(values) < 5:
            return None
        return values[min(len(values) - 1, round(pct / 100 * (len(values) - 1)))]


def load_ops(db: Session, user_id: uuid.UUID, now: datetime) -> list[PastOp]:
    rows = db.scalars(
        select(SecurityEvent).where(SecurityEvent.user_id == user_id, SecurityEvent.event_type.in_(_KINDS),
                                    SecurityEvent.timestamp >= now - timedelta(days=HISTORY_DAYS),
                                    SecurityEvent.timestamp <= now).order_by(SecurityEvent.timestamp))
    return [PastOp(e.timestamp, _KINDS[e.event_type], e.amount, e.location, e.device_id, e.atm_id,
                  e.simulation_run_id is not None) for e in rows]


def baseline_for(db: Session, user_id: uuid.UUID, now: datetime | None = None) -> Baseline:
    now = now or datetime.now(UTC)
    ops = load_ops(db, user_id, now)
    known = {d for (d,) in db.execute(select(Device.id).where(Device.user_id == user_id,
                                                              Device.status == DeviceStatus.TRUSTED))}
    # Habitudes = opérations établies : ni les 24 dernières heures (une attaque en cours ne doit pas devenir
    # « normale »), ni les événements de simulation.
    habits = [o for o in ops if not o.simulated and o.at <= now - HABIT_DELAY]
    cities = Counter(o.city for o in habits if o.city)
    hours = Counter((o.at + LOCAL_OFFSET).hour for o in habits)
    return Baseline(ops, known, habits, cities, hours,
                    cold_start=len([o for o in habits if o.kind != "login"]) < MIN_HISTORY)
