"""Monétique simulée : cartes fictives, paiements, ATM, retraits avec et sans carte.

Aucun numéro de carte complet ni CVV n'est stocké : seulement last4, un PAN masqué et un jeton aléatoire.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    SmallInteger,
    String,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.enums import (
    AtmStatus,
    CardlessCodeStatus,
    CardStatus,
    CardType,
    MerchantCategory,
    PaymentStatus,
    RiskLevel,
    WithdrawalStatus,
    WithdrawalType,
)
from app.models.mixins import Timestamps, UUIDPk, enum_col, tz


class Card(UUIDPk, Timestamps, Base):
    __tablename__ = "cards"
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), index=True)
    account_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("accounts.id", ondelete="RESTRICT"))
    card_token: Mapped[str] = mapped_column(String(64), unique=True)
    masked_pan: Mapped[str] = mapped_column(String(19))
    last4: Mapped[str] = mapped_column(String(4))
    holder_name: Mapped[str] = mapped_column(String(80))
    card_type: Mapped[CardType] = mapped_column(enum_col(CardType), default=CardType.DEBIT)
    expiry_month: Mapped[int] = mapped_column(SmallInteger)
    expiry_year: Mapped[int] = mapped_column(SmallInteger)
    status: Mapped[CardStatus] = mapped_column(enum_col(CardStatus), default=CardStatus.ACTIVE)
    daily_withdrawal_limit: Mapped[int] = mapped_column(BigInteger, default=500_000)
    daily_payment_limit: Mapped[int] = mapped_column(BigInteger, default=1_000_000)
    pin_hash: Mapped[str] = mapped_column(String(255))       # PIN simulé, haché Argon2id
    pin_failed_attempts: Mapped[int] = mapped_column(SmallInteger, default=0)
    blocked_reason: Mapped[str | None] = mapped_column(String(120))

    __table_args__ = (
        CheckConstraint("last4 ~ '^[0-9]{4}$'", name="last4_format"),
        CheckConstraint("expiry_month BETWEEN 1 AND 12", name="expiry_month_range"),
        CheckConstraint("daily_withdrawal_limit > 0 AND daily_payment_limit > 0", name="limits_positive"),
        CheckConstraint("pin_failed_attempts BETWEEN 0 AND 3", name="pin_attempts_range"),
    )


class CardPayment(UUIDPk, Timestamps, Base):
    __tablename__ = "card_payments"
    card_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("cards.id", ondelete="RESTRICT"), index=True)
    account_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("accounts.id", ondelete="RESTRICT"))
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), index=True)
    merchant_name: Mapped[str] = mapped_column(String(120))
    category: Mapped[MerchantCategory] = mapped_column(enum_col(MerchantCategory))
    country: Mapped[str] = mapped_column(String(2))
    city: Mapped[str] = mapped_column(String(80))
    amount: Mapped[int] = mapped_column(BigInteger)
    currency: Mapped[str] = mapped_column(String(3), default="XAF")
    status: Mapped[PaymentStatus] = mapped_column(enum_col(PaymentStatus))
    decline_reason: Mapped[str | None] = mapped_column(String(80))
    risk_score: Mapped[int | None] = mapped_column(SmallInteger)
    risk_level: Mapped[RiskLevel | None] = mapped_column(enum_col(RiskLevel))
    idempotency_key: Mapped[str | None] = mapped_column(String(100))
    occurred_at: Mapped[datetime] = mapped_column(tz(), server_default=text("now()"))

    __table_args__ = (
        CheckConstraint("amount > 0", name="amount_positive"),
        CheckConstraint("risk_score IS NULL OR risk_score BETWEEN 0 AND 100", name="risk_score_range"),
    )


class ATM(UUIDPk, Timestamps, Base):
    __tablename__ = "atms"
    atm_code: Mapped[str] = mapped_column(String(20), unique=True)      # ex. ATM-DLA-004
    name: Mapped[str] = mapped_column(String(120))
    city: Mapped[str] = mapped_column(String(80))
    country: Mapped[str] = mapped_column(String(2), default="CM")
    latitude: Mapped[float] = mapped_column(Numeric(8, 5))               # localisation simulée
    longitude: Mapped[float] = mapped_column(Numeric(8, 5))
    status: Mapped[AtmStatus] = mapped_column(enum_col(AtmStatus), default=AtmStatus.ONLINE)
    terminal_secret_hash: Mapped[str] = mapped_column(String(255))

    __table_args__ = (CheckConstraint("atm_code ~ '^ATM-[A-Z]{3}-[0-9]{3}$'", name="atm_code_format"),)


class Withdrawal(UUIDPk, Timestamps, Base):
    __tablename__ = "withdrawals"
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), index=True)
    account_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("accounts.id", ondelete="RESTRICT"))
    card_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("cards.id", ondelete="RESTRICT"))
    atm_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("atms.id", ondelete="RESTRICT"))
    withdrawal_type: Mapped[WithdrawalType] = mapped_column(enum_col(WithdrawalType))
    amount: Mapped[int] = mapped_column(BigInteger)
    currency: Mapped[str] = mapped_column(String(3), default="XAF")
    city: Mapped[str | None] = mapped_column(String(80))
    country: Mapped[str | None] = mapped_column(String(2))
    device_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("devices.id", ondelete="RESTRICT"))
    status: Mapped[WithdrawalStatus] = mapped_column(enum_col(WithdrawalStatus),
                                                     default=WithdrawalStatus.PENDING)
    risk_score: Mapped[int | None] = mapped_column(SmallInteger)
    risk_level: Mapped[RiskLevel | None] = mapped_column(enum_col(RiskLevel))
    authentication_method: Mapped[str | None] = mapped_column(String(32))
    # Événement de sécurité principal (le détail complet : security_events.withdrawal_id)
    security_event_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("security_events.id", ondelete="RESTRICT", use_alter=True,
                   name="fk_withdrawals_security_event_id_security_events"))
    decline_reason: Mapped[str | None] = mapped_column(String(80))
    idempotency_key: Mapped[str | None] = mapped_column(String(100))
    occurred_at: Mapped[datetime] = mapped_column(tz(), server_default=text("now()"))

    __table_args__ = (
        CheckConstraint("amount > 0", name="amount_positive"),
        CheckConstraint("risk_score IS NULL OR risk_score BETWEEN 0 AND 100", name="risk_score_range"),
        CheckConstraint("(withdrawal_type = 'CARD' AND card_id IS NOT NULL) OR "
                        "(withdrawal_type = 'CARDLESS' AND card_id IS NULL)", name="card_matches_type"),
        CheckConstraint("status <> 'APPROVED' OR atm_id IS NOT NULL", name="approved_has_atm"),
        Index("ix_withdrawals_account_created", "account_id", "created_at"),
    )


class CardlessCode(UUIDPk, Timestamps, Base):
    """Code de retrait sans carte. Jamais stocké ni journalisé en clair : HMAC-SHA256 avec clé serveur."""
    __tablename__ = "cardless_codes"
    withdrawal_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("withdrawals.id", ondelete="RESTRICT"),
                                                     unique=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    account_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("accounts.id", ondelete="RESTRICT"))
    hold_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("account_holds.id", ondelete="RESTRICT"))
    reference: Mapped[str] = mapped_column(String(12))
    code_hmac: Mapped[str] = mapped_column(String(64))
    amount: Mapped[int] = mapped_column(BigInteger)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[CardlessCodeStatus] = mapped_column(enum_col(CardlessCodeStatus),
                                                       default=CardlessCodeStatus.ACTIVE)
    expires_at: Mapped[datetime] = mapped_column(tz())
    used_at: Mapped[datetime | None] = mapped_column(tz())
    used_atm_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("atms.id", ondelete="RESTRICT"))

    __table_args__ = (
        CheckConstraint("amount > 0", name="amount_positive"),
        CheckConstraint("attempts BETWEEN 0 AND 3", name="attempts_range"),
        CheckConstraint("status <> 'USED' OR (used_at IS NOT NULL AND used_atm_id IS NOT NULL)",
                        name="used_has_trace"),
        Index("ix_cardless_codes_active_reference", "reference", unique=True,
              postgresql_where=text("status = 'ACTIVE'")),
    )
