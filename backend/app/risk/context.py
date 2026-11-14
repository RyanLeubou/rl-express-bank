"""Contexte d'une opération soumise à l'évaluation du risque."""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.models.auth import Device
from app.models.auth import Session as AuthSession
from app.models.banking import Account, Beneficiary
from app.models.cards import ATM
from app.models.enums import RiskOperation
from app.models.identity import User

_KIND = {
    RiskOperation.LOGIN: "login", RiskOperation.BENEFICIARY: "beneficiary", RiskOperation.TRANSFER: "transfer",
    RiskOperation.CARD_PAYMENT: "payment", RiskOperation.WITHDRAWAL_CARD: "withdrawal",
    RiskOperation.WITHDRAWAL_CARDLESS: "withdrawal",
}


@dataclass
class OperationContext:
    user: User
    op: RiskOperation
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    amount: int | None = None
    account: Account | None = None
    city: str | None = None
    country: str | None = None
    device: Device | None = None
    session: AuthSession | None = None
    ip: str | None = None
    atm: ATM | None = None
    beneficiary: Beneficiary | None = None
    merchant: str | None = None
    strong_auth: bool = False
    target_user_id: uuid.UUID | None = None      # personnel : client consulté
    extra: dict[str, Any] = field(default_factory=dict)
    simulation_run_id: uuid.UUID | None = None

    @property
    def kind(self) -> str:
        return _KIND.get(self.op, "other")
