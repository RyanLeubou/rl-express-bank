"""Authentification : appareils, sessions, MFA, passkeys, challenges step-up, idempotence."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.enums import (
    ChallengeStatus,
    DeviceStatus,
    IdempotencyStatus,
    RiskOperation,
    SessionStatus,
    StepUpMethod,
)
from app.models.mixins import CreatedAt, Timestamps, UUIDPk, enum_col, tz


class Device(UUIDPk, CreatedAt, Base):
    __tablename__ = "devices"
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), index=True)
    # Empreinte = hash SHA-256 d'un identifiant aléatoire côté client + User-Agent (pas d'empreinte invasive)
    fingerprint_hash: Mapped[str] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(120))
    os: Mapped[str | None] = mapped_column(String(60))
    browser: Mapped[str | None] = mapped_column(String(60))
    last_ip: Mapped[str | None] = mapped_column(INET)
    last_city: Mapped[str | None] = mapped_column(String(80))      # localisation simulée
    last_country: Mapped[str | None] = mapped_column(String(2))
    status: Mapped[DeviceStatus] = mapped_column(enum_col(DeviceStatus), default=DeviceStatus.NEW)
    first_seen: Mapped[datetime] = mapped_column(tz(), server_default=text("now()"))
    last_seen: Mapped[datetime] = mapped_column(tz(), server_default=text("now()"))
    trusted_at: Mapped[datetime | None] = mapped_column(tz())

    __table_args__ = (UniqueConstraint("user_id", "fingerprint_hash", name="uq_devices_user_fingerprint"),)


class Session(UUIDPk, CreatedAt, Base):
    __tablename__ = "sessions"
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    device_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("devices.id", ondelete="RESTRICT"))
    refresh_token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    family_id: Mapped[uuid.UUID] = mapped_column(index=True)   # détection de réutilisation du refresh
    aal: Mapped[int] = mapped_column(Integer, default=1)
    amr: Mapped[list[str]] = mapped_column(ARRAY(String(16)), default=list)
    ip: Mapped[str | None] = mapped_column(INET)
    user_agent: Mapped[str | None] = mapped_column(String(300))
    last_activity: Mapped[datetime] = mapped_column(tz(), server_default=text("now()"))
    expires_at: Mapped[datetime] = mapped_column(tz())
    status: Mapped[SessionStatus] = mapped_column(enum_col(SessionStatus), default=SessionStatus.ACTIVE)
    revoked_at: Mapped[datetime | None] = mapped_column(tz())
    revoked_reason: Mapped[str | None] = mapped_column(String(80))

    __table_args__ = (
        CheckConstraint("aal BETWEEN 1 AND 3", name="aal_range"),
        CheckConstraint("expires_at > created_at", name="expiry_after_creation"),
        Index("ix_sessions_user_status", "user_id", "status"),
    )


class MFAConfiguration(UUIDPk, Timestamps, Base):
    __tablename__ = "mfa_configurations"
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), unique=True)
    totp_secret_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary)  # AES-GCM, jamais en clair
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    confirmed_at: Mapped[datetime | None] = mapped_column(tz())
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(tz())
    last_used_step: Mapped[int | None] = mapped_column(Integer)  # anti-rejeu du même code TOTP

    __table_args__ = (CheckConstraint("NOT enabled OR totp_secret_encrypted IS NOT NULL",
                                      name="enabled_needs_secret"),)


class RecoveryCode(UUIDPk, CreatedAt, Base):
    __tablename__ = "recovery_codes"
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), index=True)
    code_hash: Mapped[str] = mapped_column(String(255))
    used_at: Mapped[datetime | None] = mapped_column(tz())


class PasskeyCredential(UUIDPk, CreatedAt, Base):
    __tablename__ = "passkey_credentials"
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), index=True)
    credential_id: Mapped[bytes] = mapped_column(LargeBinary, unique=True)
    public_key: Mapped[bytes] = mapped_column(LargeBinary)     # clé publique COSE : aucune donnée biométrique
    sign_count: Mapped[int] = mapped_column(Integer, default=0)
    transports: Mapped[list[str]] = mapped_column(ARRAY(String(16)), default=list)
    aaguid: Mapped[str | None] = mapped_column(String(36))
    name: Mapped[str] = mapped_column(String(80))
    last_used_at: Mapped[datetime | None] = mapped_column(tz())

    __table_args__ = (CheckConstraint("sign_count >= 0", name="sign_count_non_negative"),)


class StepUpChallenge(UUIDPk, CreatedAt, Base):
    """Challenge d'authentification renforcée lié à UNE opération et au hash de son contenu."""
    __tablename__ = "step_up_challenges"
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), index=True)
    session_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("sessions.id", ondelete="RESTRICT"))
    operation_type: Mapped[RiskOperation] = mapped_column(enum_col(RiskOperation))
    operation_id: Mapped[uuid.UUID | None] = mapped_column()
    payload_hash: Mapped[str] = mapped_column(String(64))
    required_method: Mapped[StepUpMethod] = mapped_column(enum_col(StepUpMethod))
    status: Mapped[ChallengeStatus] = mapped_column(enum_col(ChallengeStatus), default=ChallengeStatus.PENDING)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    expires_at: Mapped[datetime] = mapped_column(tz())
    verified_at: Mapped[datetime | None] = mapped_column(tz())

    __table_args__ = (CheckConstraint("attempts BETWEEN 0 AND 10", name="attempts_range"),)


class IdempotencyKey(UUIDPk, CreatedAt, Base):
    __tablename__ = "idempotency_keys"
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    key: Mapped[str] = mapped_column(String(100))
    endpoint: Mapped[str] = mapped_column(String(120))
    request_hash: Mapped[str] = mapped_column(String(64))
    status: Mapped[IdempotencyStatus] = mapped_column(enum_col(IdempotencyStatus),
                                                      default=IdempotencyStatus.IN_PROGRESS)
    response_code: Mapped[int | None] = mapped_column(Integer)
    response_body: Mapped[dict | None] = mapped_column(JSONB)
    expires_at: Mapped[datetime] = mapped_column(tz())

    __table_args__ = (UniqueConstraint("user_id", "key", name="uq_idempotency_user_key"),)
