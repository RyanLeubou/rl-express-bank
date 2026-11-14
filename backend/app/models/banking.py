"""Cœur bancaire : comptes, grand livre en partie double, réservations, bénéficiaires, virements.

Montants en BIGINT, unités entières de XAF (le franc CFA n'a pas de subdivision).
Chaque mouvement produit deux écritures de même journal dont la somme est nulle.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    ForeignKey,
    Identity,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.enums import (
    AccountStatus,
    AccountType,
    BeneficiaryStatus,
    HoldStatus,
    LedgerOperation,
    RiskLevel,
    TransferStatus,
)
from app.models.mixins import CreatedAt, Timestamps, UUIDPk, enum_col, tz


class Account(UUIDPk, Timestamps, Base):
    __tablename__ = "accounts"
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), index=True)
    label: Mapped[str] = mapped_column(String(80))
    account_number: Mapped[str] = mapped_column(String(11), unique=True)
    bank_code: Mapped[str] = mapped_column(String(5))
    branch_code: Mapped[str] = mapped_column(String(5))
    rib_key: Mapped[str] = mapped_column(String(2))
    iban: Mapped[str] = mapped_column(String(34), unique=True)
    bic: Mapped[str] = mapped_column(String(11))
    account_type: Mapped[AccountType] = mapped_column(enum_col(AccountType))
    currency: Mapped[str] = mapped_column(String(3), default="XAF")
    balance: Mapped[int] = mapped_column(BigInteger, default=0)
    available_balance: Mapped[int] = mapped_column(BigInteger, default=0)
    status: Mapped[AccountStatus] = mapped_column(enum_col(AccountStatus), default=AccountStatus.ACTIVE)
    # Verrouillage optimiste en complément du SELECT ... FOR UPDATE
    version: Mapped[int] = mapped_column(Integer, default=1)

    __mapper_args__ = {"version_id_col": version}
    __table_args__ = (
        CheckConstraint("account_type = 'INTERNAL' OR balance >= 0", name="balance_non_negative"),
        CheckConstraint("account_type = 'INTERNAL' OR available_balance >= 0", name="available_non_negative"),
        CheckConstraint("available_balance <= balance", name="available_le_balance"),
        CheckConstraint("currency = 'XAF'", name="currency_xaf"),
        CheckConstraint("account_number ~ '^[0-9]{11}$'", name="account_number_format"),
        CheckConstraint("rib_key ~ '^[0-9]{2}$'", name="rib_key_format"),
    )


class LedgerEntry(UUIDPk, CreatedAt, Base):
    """Écriture comptable. Table en ajout seul (droits + trigger)."""
    __tablename__ = "ledger_entries"
    seq: Mapped[int] = mapped_column(BigInteger, Identity(always=True), unique=True)
    journal_id: Mapped[uuid.UUID] = mapped_column(index=True)
    account_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("accounts.id", ondelete="RESTRICT"))
    amount: Mapped[int] = mapped_column(BigInteger)          # signé : crédit > 0, débit < 0
    balance_after: Mapped[int] = mapped_column(BigInteger)
    operation_type: Mapped[LedgerOperation] = mapped_column(enum_col(LedgerOperation))
    operation_id: Mapped[uuid.UUID | None] = mapped_column()
    description: Mapped[str] = mapped_column(String(160))
    value_date: Mapped[datetime] = mapped_column(tz(), server_default=text("now()"))

    __table_args__ = (
        CheckConstraint("amount <> 0", name="amount_non_zero"),
        Index("ix_ledger_entries_account_date", "account_id", "value_date"),
    )


class AccountHold(UUIDPk, Timestamps, Base):
    """Réservation de fonds (ex. code de retrait sans carte émis) : réduit le solde disponible."""
    __tablename__ = "account_holds"
    account_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("accounts.id", ondelete="RESTRICT"), index=True)
    amount: Mapped[int] = mapped_column(BigInteger)
    reason: Mapped[str] = mapped_column(String(80))
    reference_id: Mapped[uuid.UUID | None] = mapped_column()
    status: Mapped[HoldStatus] = mapped_column(enum_col(HoldStatus), default=HoldStatus.ACTIVE)
    expires_at: Mapped[datetime] = mapped_column(tz())

    __table_args__ = (CheckConstraint("amount > 0", name="amount_positive"),)


class Beneficiary(UUIDPk, Timestamps, Base):
    __tablename__ = "beneficiaries"
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), index=True)
    first_name: Mapped[str] = mapped_column(String(80))
    last_name: Mapped[str] = mapped_column(String(80))
    bank_name: Mapped[str] = mapped_column(String(120))
    iban: Mapped[str] = mapped_column(String(34))
    # Compte interne RL si le bénéficiaire est client de la banque (virement interne)
    internal_account_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("accounts.id", ondelete="RESTRICT"))
    status: Mapped[BeneficiaryStatus] = mapped_column(enum_col(BeneficiaryStatus),
                                                      default=BeneficiaryStatus.PENDING_VERIFICATION)
    activated_at: Mapped[datetime | None] = mapped_column(tz())
    deleted_at: Mapped[datetime | None] = mapped_column(tz())

    __table_args__ = (
        # Un même IBAN une seule fois par client, suppression logique exclue
        Index("uq_beneficiaries_user_iban_active", "user_id", "iban", unique=True,
              postgresql_where=text("status <> 'DELETED'")),
        CheckConstraint("status <> 'DELETED' OR deleted_at IS NOT NULL", name="deleted_has_date"),
    )


class Transfer(UUIDPk, Timestamps, Base):
    __tablename__ = "transfers"
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), index=True)
    source_account_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("accounts.id", ondelete="RESTRICT"))
    beneficiary_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("beneficiaries.id", ondelete="RESTRICT"))
    destination_account_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("accounts.id", ondelete="RESTRICT"))
    amount: Mapped[int] = mapped_column(BigInteger)
    currency: Mapped[str] = mapped_column(String(3), default="XAF")
    reference: Mapped[str] = mapped_column(String(140))     # motif (donnée, jamais une instruction)
    status: Mapped[TransferStatus] = mapped_column(enum_col(TransferStatus), default=TransferStatus.PENDING)
    risk_score: Mapped[int | None] = mapped_column(SmallInteger)
    risk_level: Mapped[RiskLevel | None] = mapped_column(enum_col(RiskLevel))
    failure_reason: Mapped[str | None] = mapped_column(Text)
    idempotency_key: Mapped[str | None] = mapped_column(String(100))
    device_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("devices.id", ondelete="RESTRICT"))
    executed_at: Mapped[datetime | None] = mapped_column(tz())

    __table_args__ = (
        CheckConstraint("amount > 0", name="amount_positive"),
        CheckConstraint("risk_score IS NULL OR risk_score BETWEEN 0 AND 100", name="risk_score_range"),
        CheckConstraint("status <> 'COMPLETED' OR executed_at IS NOT NULL", name="completed_has_date"),
        CheckConstraint("destination_account_id IS NULL OR destination_account_id <> source_account_id",
                        name="no_self_transfer"),
        Index("ix_transfers_source_created", "source_account_id", "created_at"),
    )
