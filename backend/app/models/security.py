"""Sécurité : événements, audit chaîné, outbox, risque, politiques, alertes SOC, investigations."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Float,
    ForeignKey,
    Identity,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base
from app.models.enums import (
    ActorType,
    AlertSource,
    AlertStatus,
    InvestigationStatus,
    OutboxStatus,
    PolicyDecision,
    RiskLevel,
    RiskOperation,
    SecurityActionStatus,
    SecurityActionType,
    Severity,
)
from app.models.mixins import CreatedAt, Timestamps, UUIDPk, enum_col, tz


class SecurityEvent(UUIDPk, Base):
    """Événement de détection (format JSON du cahier des charges). Ajout seul."""
    __tablename__ = "security_events"
    seq: Mapped[int] = mapped_column(BigInteger, Identity(always=True), unique=True)
    schema_version: Mapped[int] = mapped_column(SmallInteger, default=1)
    timestamp: Mapped[datetime] = mapped_column(tz(), server_default=text("now()"))
    event_type: Mapped[str] = mapped_column(String(64))
    category: Mapped[str] = mapped_column(String(32))
    severity: Mapped[Severity] = mapped_column(enum_col(Severity), default=Severity.INFO)
    actor_type: Mapped[ActorType] = mapped_column(enum_col(ActorType), default=ActorType.USER)
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    session_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("sessions.id", ondelete="RESTRICT"))
    device_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("devices.id", ondelete="RESTRICT"))
    request_id: Mapped[str | None] = mapped_column(String(64))
    ip_address: Mapped[str | None] = mapped_column(INET)
    device: Mapped[str | None] = mapped_column(String(120))
    os: Mapped[str | None] = mapped_column(String(60))
    browser: Mapped[str | None] = mapped_column(String(60))
    location: Mapped[str | None] = mapped_column(String(80))
    country: Mapped[str | None] = mapped_column(String(2))
    amount: Mapped[int | None] = mapped_column(BigInteger)
    currency: Mapped[str | None] = mapped_column(String(3))
    beneficiary_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("beneficiaries.id", ondelete="RESTRICT"))
    transfer_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("transfers.id", ondelete="RESTRICT"))
    card_payment_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("card_payments.id", ondelete="RESTRICT"))
    withdrawal_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("withdrawals.id", ondelete="RESTRICT"))
    atm_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("atms.id", ondelete="RESTRICT"))
    status: Mapped[str | None] = mapped_column(String(32))
    risk_score: Mapped[int | None] = mapped_column(SmallInteger)
    simulation_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("simulation_runs.id", ondelete="RESTRICT"))
    metadata_: Mapped[dict] = mapped_column("metadata", JSONB, default=dict)

    __table_args__ = (
        CheckConstraint("event_type ~ '^[A-Z][A-Z0-9_]+$'", name="event_type_format"),
        CheckConstraint("amount IS NULL OR amount >= 0", name="amount_non_negative"),
        Index("ix_security_events_user_ts", "user_id", "timestamp"),
        Index("ix_security_events_type_ts", "event_type", "timestamp"),
        Index("ix_security_events_simulation", "simulation_run_id"),
    )


class AuditLog(UUIDPk, Base):
    """Journal d'audit (qui, quoi, justification, avant/après). Ajout seul, chaîné par SHA-256."""
    __tablename__ = "audit_logs"
    seq: Mapped[int] = mapped_column(BigInteger, Identity(always=True), unique=True)
    timestamp: Mapped[datetime] = mapped_column(tz(), server_default=text("now()"))
    actor_type: Mapped[ActorType] = mapped_column(enum_col(ActorType))
    actor_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    actor_role: Mapped[str | None] = mapped_column(String(40))
    action: Mapped[str] = mapped_column(String(80))
    target_type: Mapped[str] = mapped_column(String(40))
    target_id: Mapped[str | None] = mapped_column(String(64))
    before: Mapped[dict | None] = mapped_column(JSONB)          # masqué avant écriture
    after: Mapped[dict | None] = mapped_column(JSONB)
    justification: Mapped[str | None] = mapped_column(Text)
    ip_address: Mapped[str | None] = mapped_column(INET)
    request_id: Mapped[str | None] = mapped_column(String(64))
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64), unique=True)

    __table_args__ = (Index("ix_audit_logs_actor_ts", "actor_id", "timestamp"),
                      Index("ix_audit_logs_target", "target_type", "target_id"))


class OutboxEvent(UUIDPk, CreatedAt, Base):
    """Transactional outbox : écrit dans la même transaction que l'opération, expédié par le worker."""
    __tablename__ = "outbox_events"
    seq: Mapped[int] = mapped_column(BigInteger, Identity(always=True), unique=True)
    security_event_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("security_events.id", ondelete="RESTRICT"))
    destination: Mapped[str] = mapped_column(String(32))      # wazuh_file | opensearch
    status: Mapped[OutboxStatus] = mapped_column(enum_col(OutboxStatus), default=OutboxStatus.PENDING)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(tz(), server_default=text("now()"))
    sent_at: Mapped[datetime | None] = mapped_column(tz())
    last_error: Mapped[str | None] = mapped_column(String(300))

    # Relation déclarée : garantit l'insertion de l'événement AVANT son entrée d'outbox
    security_event: Mapped[SecurityEvent] = relationship(lazy="raise")

    __table_args__ = (
        UniqueConstraint("security_event_id", "destination", name="uq_outbox_event_destination"),
        Index("ix_outbox_pending", "next_attempt_at", postgresql_where=text("status = 'PENDING'")),
    )


class RiskAssessment(UUIDPk, CreatedAt, Base):
    __tablename__ = "risk_assessments"
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), index=True)
    operation_type: Mapped[RiskOperation] = mapped_column(enum_col(RiskOperation))
    transfer_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("transfers.id", ondelete="RESTRICT"))
    card_payment_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("card_payments.id", ondelete="RESTRICT"))
    withdrawal_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("withdrawals.id", ondelete="RESTRICT"))
    score: Mapped[int] = mapped_column(SmallInteger)
    level: Mapped[RiskLevel] = mapped_column(enum_col(RiskLevel))
    reasons: Mapped[list] = mapped_column(JSONB, default=list)   # [{code, points, detail}]
    ai_score: Mapped[float | None] = mapped_column(Float)
    rules_version: Mapped[int] = mapped_column(Integer)
    model_version: Mapped[str | None] = mapped_column(String(40))
    decision: Mapped[PolicyDecision] = mapped_column(enum_col(PolicyDecision))
    degraded: Mapped[bool] = mapped_column(Boolean, default=False)   # IA indisponible : règles seules

    __table_args__ = (
        CheckConstraint("score BETWEEN 0 AND 100", name="score_range"),
        CheckConstraint("ai_score IS NULL OR ai_score BETWEEN 0 AND 1", name="ai_score_range"),
        CheckConstraint("num_nonnulls(transfer_id, card_payment_id, withdrawal_id) <= 1",
                        name="single_operation"),
    )


class RiskRule(UUIDPk, Timestamps, Base):
    __tablename__ = "risk_rules"
    code: Mapped[str] = mapped_column(String(48))
    description: Mapped[str] = mapped_column(Text)
    operation_types: Mapped[list] = mapped_column(JSONB)          # liste de RiskOperation
    weight: Mapped[int] = mapped_column(SmallInteger)
    params: Mapped[dict] = mapped_column(JSONB, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    version: Mapped[int] = mapped_column(Integer, default=1)

    __table_args__ = (UniqueConstraint("code", "version", name="uq_risk_rules_code_version"),
                      CheckConstraint("weight BETWEEN -50 AND 50", name="weight_range"))


class SecurityPolicy(UUIDPk, Timestamps, Base):
    __tablename__ = "security_policies"
    operation_type: Mapped[RiskOperation] = mapped_column(enum_col(RiskOperation))
    risk_level: Mapped[RiskLevel] = mapped_column(enum_col(RiskLevel))
    decision: Mapped[PolicyDecision] = mapped_column(enum_col(PolicyDecision))
    actions: Mapped[list] = mapped_column(JSONB, default=list)     # liste de SecurityActionType
    floor_decision: Mapped[PolicyDecision | None] = mapped_column(enum_col(PolicyDecision, "floordecision"))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    version: Mapped[int] = mapped_column(Integer, default=1)

    __table_args__ = (UniqueConstraint("operation_type", "risk_level", "version",
                                       name="uq_security_policies_op_level_version"),)


class Investigation(UUIDPk, Timestamps, Base):
    __tablename__ = "investigations"
    title: Mapped[str] = mapped_column(String(160))
    status: Mapped[InvestigationStatus] = mapped_column(enum_col(InvestigationStatus),
                                                        default=InvestigationStatus.OPEN)
    lead_analyst_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    summary: Mapped[str | None] = mapped_column(Text)
    closed_at: Mapped[datetime | None] = mapped_column(tz())


class SecurityAlert(UUIDPk, Timestamps, Base):
    __tablename__ = "security_alerts"
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), index=True)
    title: Mapped[str] = mapped_column(String(160))
    severity: Mapped[Severity] = mapped_column(enum_col(Severity))
    risk_score: Mapped[int | None] = mapped_column(SmallInteger)
    risk_level: Mapped[RiskLevel | None] = mapped_column(enum_col(RiskLevel))
    reasons: Mapped[list] = mapped_column(JSONB, default=list)
    status: Mapped[AlertStatus] = mapped_column(enum_col(AlertStatus), default=AlertStatus.NEW)
    source: Mapped[AlertSource] = mapped_column(enum_col(AlertSource))
    correlation_key: Mapped[str] = mapped_column(String(120))
    mitre_techniques: Mapped[list] = mapped_column(JSONB, default=list)
    assigned_to: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    investigation_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("investigations.id", ondelete="RESTRICT"))
    resolution_note: Mapped[str | None] = mapped_column(Text)
    resolved_at: Mapped[datetime | None] = mapped_column(tz())

    __table_args__ = (
        UniqueConstraint("correlation_key", name="uq_security_alerts_correlation_key"),
        CheckConstraint("status NOT IN ('RESOLVED','FALSE_POSITIVE') OR resolution_note IS NOT NULL",
                        name="closed_needs_note"),
        Index("ix_security_alerts_status_severity", "status", "severity", "created_at"),
    )


class AlertEvent(Base):
    __tablename__ = "alert_events"
    alert_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("security_alerts.id", ondelete="RESTRICT"),
                                                primary_key=True)
    security_event_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("security_events.id", ondelete="RESTRICT"),
                                                         primary_key=True)


class SecurityAction(UUIDPk, CreatedAt, Base):
    __tablename__ = "security_actions"
    alert_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("security_alerts.id", ondelete="RESTRICT"))
    action_type: Mapped[SecurityActionType] = mapped_column(enum_col(SecurityActionType))
    target_type: Mapped[str] = mapped_column(String(40))
    target_id: Mapped[uuid.UUID] = mapped_column()
    executed_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))  # NULL = SYSTEM
    status: Mapped[SecurityActionStatus] = mapped_column(enum_col(SecurityActionStatus))
    justification: Mapped[str | None] = mapped_column(Text)
    reverted_at: Mapped[datetime | None] = mapped_column(tz())
    reverted_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))


class InvestigationNote(UUIDPk, CreatedAt, Base):
    __tablename__ = "investigation_notes"
    investigation_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("investigations.id", ondelete="RESTRICT"),
                                                        index=True)
    author_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    note: Mapped[str] = mapped_column(Text)
