"""Génération d'un historique réaliste et déterministe (graine fixe) sur 90 jours.

Chaque opération passe par le grand livre en partie double : les soldes sont toujours
cohérents avec les écritures. Chaque opération émet son événement de sécurité daté.
"""
from __future__ import annotations

import hashlib
import random
import statistics
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.events.catalog import EventType as E
from app.events.logger import emit
from app.models import (
    ATM,
    Account,
    BehaviorProfile,
    Beneficiary,
    Card,
    CardPayment,
    Device,
    Transfer,
    User,
    Withdrawal,
)
from app.models.enums import (
    ActorType,
    BeneficiaryStatus,
    LedgerOperation,
    PaymentStatus,
    RiskLevel,
    TransferStatus,
    WithdrawalStatus,
    WithdrawalType,
)
from app.seed.people import MERCHANTS, ClientProfile
from app.services.banking.ledger import LedgerError, post_transfer

HISTORY_DAYS = 90
LOCAL_OFFSET = timedelta(hours=1)  # Africa/Douala = UTC+1, sans heure d'été


@dataclass
class ClientContext:
    profile: ClientProfile
    user: User
    current: Account
    card: Card
    devices: list[Device]
    beneficiaries: list[Beneficiary]
    ip: str
    withdrawals: list[tuple[datetime, int, str, str]] = field(default_factory=list)  # ts, montant, atm, ville
    payments: list[tuple[datetime, str, str]] = field(default_factory=list)          # ts, catégorie, ville
    transfers: list[tuple[datetime, uuid.UUID]] = field(default_factory=list)


def _local_to_utc(day: datetime, hour: int, minute: int) -> datetime:
    return day.replace(hour=hour, minute=minute, second=0, microsecond=0) - LOCAL_OFFSET


def device_fingerprint(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def generate_history(db: Session, ctx: ClientContext, internal: dict[str, Account], atms: dict[str, ATM],
                     rng: random.Random, now: datetime) -> None:
    p = ctx.profile
    start_local = (now + LOCAL_OFFSET).replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(
        days=HISTORY_DAYS)
    main_device = ctx.devices[0]
    base = dict(user_id=ctx.user.id, device_id=main_device.id, ip_address=ctx.ip, device=main_device.name,
                os=main_device.os, browser=main_device.browser, country="CM")

    for d in range(HISTORY_DAYS):
        day = start_local + timedelta(days=d)
        if day.day == 25:  # salaire mensuel
            ts = _local_to_utc(day, 6, 0)
            post_transfer(db, debit_account_id=internal["EXTERNAL"].id, credit_account_id=ctx.current.id,
                          amount=p.salary, operation_type=LedgerOperation.SALARY, operation_id=None,
                          description="Salaire (virement reçu fictif)", value_date=ts)

        if rng.random() < 0.6:  # connexions quotidiennes à l'application
            ts = _local_to_utc(day, rng.randint(*p.hours), rng.randint(0, 59))
            emit(db, E.USER_LOGIN, occurred_at=ts, location=p.city, status="SUCCESS", **base)

        if rng.random() < p.withdrawals_per_week / 7:
            _withdrawal(db, ctx, internal, atms, rng, day, base)
        for _ in range(2):
            if rng.random() < p.payments_per_week / 14:
                _payment(db, ctx, internal, rng, day, base)
        if rng.random() < p.transfers_per_month / 30:
            _transfer(db, ctx, internal, rng, day, base)


def _withdrawal(db, ctx: ClientContext, internal, atms, rng, day, base) -> None:
    p = ctx.profile
    lo, hi = p.withdrawal_range
    amount = rng.randrange(lo, hi + 1, 5_000)
    atm_code = rng.choices(p.usual_atms, weights=[0.7, 0.3][:len(p.usual_atms)] or [1])[0]
    atm = atms[atm_code]
    ts = _local_to_utc(day, rng.randint(p.hours[0], p.hours[1] - 1), rng.randint(0, 59))
    cardless = rng.random() < p.cardless_share
    w = Withdrawal(id=uuid.uuid4(), user_id=ctx.user.id, account_id=ctx.current.id,
                   card_id=None if cardless else ctx.card.id, atm_id=atm.id,
                   withdrawal_type=WithdrawalType.CARDLESS if cardless else WithdrawalType.CARD,
                   amount=amount, city=atm.city, country="CM", device_id=base["device_id"],
                   status=WithdrawalStatus.APPROVED, risk_score=rng.randint(0, 15), risk_level=RiskLevel.LOW,
                   authentication_method="TOTP" if cardless else "PIN", occurred_at=ts, created_at=ts,
                   updated_at=ts)
    try:
        post_transfer(db, debit_account_id=ctx.current.id, credit_account_id=internal["ATM"].id, amount=amount,
                      operation_type=LedgerOperation.WITHDRAWAL, operation_id=w.id,
                      description=f"Retrait {atm.atm_code}", value_date=ts)
    except LedgerError:
        return
    db.add(w)
    db.flush()
    event = emit(db, E.CARDLESS_WITHDRAWAL if cardless else E.ATM_WITHDRAWAL, occurred_at=ts,
                 actor_type=ActorType.ATM, withdrawal_id=w.id, atm_id=atm.id, amount=amount, location=atm.city,
                 status="APPROVED", risk_score=w.risk_score, **base)
    db.flush()
    w.security_event_id = event.id
    ctx.withdrawals.append((ts, amount, atm.atm_code, atm.city))


def _payment(db, ctx: ClientContext, internal, rng, day, base) -> None:
    p = ctx.profile
    category = rng.choices(list(p.categories), weights=list(p.categories.values()))[0]
    name, lo, hi = rng.choice(MERCHANTS[category])
    amount = rng.randrange(lo, hi + 1, 500)
    ts = _local_to_utc(day, rng.randint(p.hours[0], p.hours[1] - 1), rng.randint(0, 59))
    pay = CardPayment(id=uuid.uuid4(), card_id=ctx.card.id, account_id=ctx.current.id, user_id=ctx.user.id,
                      merchant_name=name, category=category, country="CM", city=p.city, amount=amount,
                      status=PaymentStatus.APPROVED, risk_score=rng.randint(0, 12), risk_level=RiskLevel.LOW,
                      occurred_at=ts, created_at=ts, updated_at=ts)
    try:
        post_transfer(db, debit_account_id=ctx.current.id, credit_account_id=internal["CARD"].id, amount=amount,
                      operation_type=LedgerOperation.CARD_PAYMENT, operation_id=pay.id,
                      description=f"Paiement {name}", value_date=ts)
    except LedgerError:
        return
    db.add(pay)
    db.flush()
    emit(db, E.CARD_PAYMENT_APPROVED, occurred_at=ts, card_payment_id=pay.id, amount=amount, location=p.city,
         status="APPROVED", risk_score=pay.risk_score, metadata={"merchant": name, "category": str(category)},
         **base)
    ctx.payments.append((ts, str(category), p.city))


def _transfer(db, ctx: ClientContext, internal, rng, day, base) -> None:
    p = ctx.profile
    beneficiary = rng.choice(ctx.beneficiaries)
    amount = rng.randrange(10_000, 120_001, 5_000)
    ts = _local_to_utc(day, rng.randint(p.hours[0], p.hours[1] - 1), rng.randint(0, 59))
    destination = beneficiary.internal_account_id
    t = Transfer(id=uuid.uuid4(), user_id=ctx.user.id, source_account_id=ctx.current.id,
                 beneficiary_id=beneficiary.id, destination_account_id=destination, amount=amount,
                 reference=rng.choice(["Loyer", "Participation famille", "Remboursement", "Scolarité",
                                       "Tontine"]),
                 status=TransferStatus.COMPLETED, risk_score=rng.randint(0, 20), risk_level=RiskLevel.LOW,
                 device_id=base["device_id"], executed_at=ts, created_at=ts, updated_at=ts)
    try:
        post_transfer(db, debit_account_id=ctx.current.id,
                      credit_account_id=destination or internal["EXTERNAL"].id, amount=amount,
                      operation_type=LedgerOperation.TRANSFER, operation_id=t.id,
                      description=f"Virement {t.reference}", value_date=ts)
    except LedgerError:
        return
    db.add(t)
    db.flush()
    emit(db, E.TRANSFER_COMPLETED, occurred_at=ts, transfer_id=t.id, beneficiary_id=beneficiary.id,
         amount=amount, location=p.city, status="COMPLETED", risk_score=t.risk_score, **base)
    ctx.transfers.append((ts, beneficiary.id))


def _stats(values: list[int]) -> dict[str, float]:
    if not values:
        return {}
    ordered = sorted(values)
    p95 = ordered[min(len(ordered) - 1, round(0.95 * (len(ordered) - 1)))]
    return {"count": len(values), "mean": round(statistics.fmean(values)), "p95": p95, "max": ordered[-1],
            "std": round(statistics.pstdev(values)) if len(values) > 1 else 0}


def build_behavior_profile(ctx: ClientContext, atms: dict[str, ATM]) -> BehaviorProfile:
    weeks = HISTORY_DAYS / 7
    hours = [0] * 24
    for ts, *_ in ctx.withdrawals + ctx.payments:
        hours[(ts + LOCAL_OFFSET).hour] += 1
    cities = Counter(c for *_, c in ctx.withdrawals) + Counter(c for *_, c in ctx.payments)
    atm_counts = Counter(code for _, _, code, _ in ctx.withdrawals)
    return BehaviorProfile(
        user_id=ctx.user.id,
        sample_size=len(ctx.withdrawals) + len(ctx.payments) + len(ctx.transfers),
        amount_stats={"withdrawal": _stats([a for _, a, _, _ in ctx.withdrawals])},
        usual_hours=hours,
        usual_cities=dict(cities),
        usual_atm_ids=[str(atms[c].id) for c, _ in atm_counts.most_common(3)],
        known_device_ids=[str(d.id) for d in ctx.devices],
        withdrawals_per_week=round(len(ctx.withdrawals) / weeks, 2),
        transfers_per_week=round(len(ctx.transfers) / weeks, 2),
        payment_categories=dict(Counter(c for _, c, _ in ctx.payments)),
        usual_beneficiary_ids=[str(b) for b, _ in Counter(b for _, b in ctx.transfers).most_common(5)],
    )


def ensure_beneficiary_active(b: Beneficiary, when: datetime) -> None:
    b.status = BeneficiaryStatus.ACTIVE
    b.activated_at = when
    b.created_at = when
    b.updated_at = when


def now_utc() -> datetime:
    return datetime.now(UTC)
