"""Schémas d'entrée stricts des opérations bancaires (aucun champ inconnu accepté)."""
from __future__ import annotations

import uuid
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from app.models.enums import MerchantCategory, WithdrawalType

Amount = Annotated[int, Field(gt=0, le=50_000_000)]
Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=80)]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class BeneficiaryIn(Strict):
    first_name: Name
    last_name: Name
    bank_name: Name
    iban: Annotated[str, StringConstraints(min_length=15, max_length=42)]
    simulated_city: str | None = None


class TransferIn(Strict):
    source_account_id: uuid.UUID
    beneficiary_id: uuid.UUID
    amount: Amount
    reference: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=140)]
    simulated_city: str | None = None


class PaymentIn(Strict):
    card_id: uuid.UUID
    amount: Amount
    merchant: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=120)]
    category: MerchantCategory
    city: Annotated[str, StringConstraints(max_length=80)]


class WithdrawalIn(Strict):
    type: WithdrawalType
    account_id: uuid.UUID
    amount: Amount
    atm_id: uuid.UUID | None = None
    card_id: uuid.UUID | None = None
    pin: Annotated[str, StringConstraints(pattern=r"^\d{4}$")] | None = None
    simulated_city: str | None = None


class StepUpVerifyIn(Strict):
    code: Annotated[str, StringConstraints(min_length=6, max_length=6, pattern=r"^\d{6}$")]


class RibEventIn(Strict):
    action: Annotated[str, StringConstraints(pattern=r"^(copied|downloaded)$")]


class AtmRedeemIn(Strict):
    reference: Annotated[str, StringConstraints(min_length=8, max_length=8)]
    code: Annotated[str, StringConstraints(pattern=r"^\d{6}$")]
