"""Profils comportementaux, registre de modèles IA, notifications, exécutions de simulation."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, ForeignKey, Index, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.enums import NotificationChannel, Severity, SimulationStatus
from app.models.mixins import CreatedAt, Timestamps, UUIDPk, enum_col, tz


class BehaviorProfile(Timestamps, Base):
    __tablename__ = "behavior_profiles"
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), primary_key=True)
    sample_size: Mapped[int] = mapped_column(Integer, default=0)
    # Statistiques de montants par type d'opération : {withdrawal: {mean, p95, max, std}, ...}
    amount_stats: Mapped[dict] = mapped_column(JSONB, default=dict)
    usual_hours: Mapped[list] = mapped_column(JSONB, default=list)          # histogramme 24 cases
    usual_cities: Mapped[dict] = mapped_column(JSONB, default=dict)         # ville -> fréquence
    usual_atm_ids: Mapped[list] = mapped_column(JSONB, default=list)
    known_device_ids: Mapped[list] = mapped_column(JSONB, default=list)
    withdrawals_per_week: Mapped[float] = mapped_column(default=0.0)
    transfers_per_week: Mapped[float] = mapped_column(default=0.0)
    payment_categories: Mapped[dict] = mapped_column(JSONB, default=dict)
    usual_beneficiary_ids: Mapped[list] = mapped_column(JSONB, default=list)
    computed_at: Mapped[datetime] = mapped_column(tz(), server_default=text("now()"))

    __table_args__ = (CheckConstraint("sample_size >= 0", name="sample_size_non_negative"),)


class MLModel(UUIDPk, CreatedAt, Base):
    __tablename__ = "ml_models"
    version: Mapped[str] = mapped_column(String(40), unique=True)
    algorithm: Mapped[str] = mapped_column(String(40))
    params: Mapped[dict] = mapped_column(JSONB, default=dict)
    features: Mapped[list] = mapped_column(JSONB, default=list)
    metrics: Mapped[dict] = mapped_column(JSONB, default=dict)
    artifact_path: Mapped[str] = mapped_column(String(200))
    artifact_sha256: Mapped[str] = mapped_column(String(64))
    active: Mapped[bool] = mapped_column(Boolean, default=False)
    trained_at: Mapped[datetime] = mapped_column(tz())

    __table_args__ = (Index("uq_ml_models_single_active", "active", unique=True,
                            postgresql_where=text("active")),)


class Notification(UUIDPk, CreatedAt, Base):
    __tablename__ = "notifications"
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    type: Mapped[str] = mapped_column(String(48))
    title: Mapped[str] = mapped_column(String(120))
    body: Mapped[str] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(enum_col(Severity), default=Severity.INFO)
    channel: Mapped[NotificationChannel] = mapped_column(enum_col(NotificationChannel),
                                                         default=NotificationChannel.IN_APP)
    read_at: Mapped[datetime | None] = mapped_column(tz())

    __table_args__ = (Index("ix_notifications_user_unread", "user_id", "created_at",
                            postgresql_where=text("read_at IS NULL")),)


class SimulationRun(UUIDPk, Base):
    __tablename__ = "simulation_runs"
    scenario: Mapped[str] = mapped_column(String(64))
    launched_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    status: Mapped[SimulationStatus] = mapped_column(enum_col(SimulationStatus),
                                                     default=SimulationStatus.RUNNING)
    parameters: Mapped[dict] = mapped_column(JSONB, default=dict)
    summary: Mapped[dict] = mapped_column(JSONB, default=dict)
    started_at: Mapped[datetime] = mapped_column(tz(), server_default=text("now()"))
    ended_at: Mapped[datetime | None] = mapped_column(tz())
