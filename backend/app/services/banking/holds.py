"""Réservations de fonds (retrait sans carte) : réduisent le solde disponible sans toucher au solde comptable."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Account, AccountHold
from app.models.enums import HoldStatus
from app.services.banking.ledger import LedgerError


def create_hold(db: Session, account_id: uuid.UUID, amount: int, reason: str, reference_id: uuid.UUID | None,
                expires_at: datetime) -> AccountHold:
    account = db.scalar(select(Account).where(Account.id == account_id).with_for_update())
    if account is None or account.available_balance < amount:
        raise LedgerError("insufficient_funds", "Solde disponible insuffisant")
    account.available_balance -= amount
    hold = AccountHold(account_id=account_id, amount=amount, reason=reason, reference_id=reference_id,
                       expires_at=expires_at)
    db.add(hold)
    db.flush()
    return hold


def release_hold(db: Session, hold_id: uuid.UUID, status: HoldStatus = HoldStatus.RELEASED) -> None:
    hold = db.scalar(select(AccountHold).where(AccountHold.id == hold_id).with_for_update())
    if hold is None or hold.status != HoldStatus.ACTIVE:
        return
    account = db.scalar(select(Account).where(Account.id == hold.account_id).with_for_update())
    account.available_balance += hold.amount
    hold.status = status
    db.flush()
