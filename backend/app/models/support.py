"""RL SOLUTION : conversations, messages masqués, appels d'outils, tickets, base de connaissances."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.enums import ConversationStatus, MessageAuthor, TicketPriority, TicketStatus, ToolCallDecision
from app.models.mixins import CreatedAt, Timestamps, UUIDPk, enum_col, tz


class SupportConversation(UUIDPk, Timestamps, Base):
    __tablename__ = "support_conversations"
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), index=True)
    status: Mapped[ConversationStatus] = mapped_column(enum_col(ConversationStatus),
                                                       default=ConversationStatus.BOT)
    topic: Mapped[str | None] = mapped_column(String(80))
    assigned_agent_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    scam_signal: Mapped[bool] = mapped_column(Boolean, default=False)
    closed_at: Mapped[datetime | None] = mapped_column(tz())


class SupportMessage(UUIDPk, CreatedAt, Base):
    __tablename__ = "support_messages"
    conversation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("support_conversations.id", ondelete="RESTRICT"), index=True)
    author: Mapped[MessageAuthor] = mapped_column(enum_col(MessageAuthor))
    author_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    content_redacted: Mapped[str] = mapped_column(Text)        # OTP, codes, PIN masqués AVANT stockage
    redactions: Mapped[int] = mapped_column(Integer, default=0)
    flags: Mapped[list] = mapped_column(JSONB, default=list)   # scam_signal, injection_suspected…


class SupportToolCall(UUIDPk, CreatedAt, Base):
    __tablename__ = "support_tool_calls"
    conversation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("support_conversations.id", ondelete="RESTRICT"), index=True)
    tool_name: Mapped[str] = mapped_column(String(48))
    arguments_redacted: Mapped[dict] = mapped_column(JSONB, default=dict)
    decision: Mapped[ToolCallDecision] = mapped_column(enum_col(ToolCallDecision))
    denial_reason: Mapped[str | None] = mapped_column(String(120))
    confirmed_at: Mapped[datetime | None] = mapped_column(tz())


class SupportTicket(UUIDPk, Timestamps, Base):
    __tablename__ = "support_tickets"
    conversation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("support_conversations.id", ondelete="RESTRICT"), unique=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    category: Mapped[str] = mapped_column(String(48))
    priority: Mapped[TicketPriority] = mapped_column(enum_col(TicketPriority), default=TicketPriority.NORMAL)
    status: Mapped[TicketStatus] = mapped_column(enum_col(TicketStatus), default=TicketStatus.OPEN)
    assigned_agent_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    # Accès du SUPPORT_AGENT aux données du client limité à cette fenêtre
    access_expires_at: Mapped[datetime | None] = mapped_column(tz())
    resolved_at: Mapped[datetime | None] = mapped_column(tz())


class BankContact(UUIDPk, CreatedAt, Base):
    """Contacts officiels sortants : alimente « Vérifier un appel » (anti-vishing)."""
    __tablename__ = "bank_contacts"
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), index=True)
    agent_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    channel: Mapped[str] = mapped_column(String(16))           # PHONE | IN_APP
    reason: Mapped[str] = mapped_column(String(160))
    active_until: Mapped[datetime] = mapped_column(tz())

    __table_args__ = (CheckConstraint("channel IN ('PHONE','IN_APP')", name="channel_values"),)


class KnowledgeDocument(UUIDPk, Timestamps, Base):
    __tablename__ = "knowledge_documents"
    title: Mapped[str] = mapped_column(String(160))
    slug: Mapped[str] = mapped_column(String(120), unique=True)
    body: Mapped[str] = mapped_column(Text)
    audience: Mapped[str] = mapped_column(String(16), default="CUSTOMER")
    published: Mapped[bool] = mapped_column(Boolean, default=True)
    version: Mapped[int] = mapped_column(Integer, default=1)

