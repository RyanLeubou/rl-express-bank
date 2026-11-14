"""RL SOLUTION : conversations client, escalade vers un conseiller, tickets, accès client borné par ticket."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, StringConstraints
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.api.v1.soc import customer_file
from app.core.database import get_db
from app.events.catalog import EventType as E
from app.events.logger import emit
from app.models import Card, SupportConversation, SupportMessage, SupportTicket, User
from app.models.enums import (
    ActorType,
    ConversationStatus,
    MessageAuthor,
    PolicyDecision,
    RiskLevel,
    SecurityActionType,
    TicketPriority,
    TicketStatus,
)
from app.risk import response as resp
from app.risk.engine import RiskResult
from app.security.auth.deps import AuthContext, check_origin, client_ip, require_permission
from app.security.auth.errors import AuthError
from app.services.soc.staff_access import has_ticket_access, record_staff_access
from app.services.support import assistant

router = APIRouter(prefix="/support", tags=["RL SOLUTION"], dependencies=[Depends(check_origin)])
Msg = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=1500)]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class NewConversation(Strict):
    topic: Annotated[str, StringConstraints(max_length=80)] = "Question générale"
    message: Msg


class MessageIn(Strict):
    message: Msg


class LockCardIn(Strict):
    card_id: uuid.UUID
    justification: Annotated[str, StringConstraints(min_length=5, max_length=500)]


def _msg(m: SupportMessage) -> dict[str, Any]:
    return {"id": m.id, "author": m.author, "content": m.content_redacted, "flags": m.flags, "at": m.created_at}


def _conv(c: SupportConversation) -> dict[str, Any]:
    return {"id": c.id, "topic": c.topic, "status": c.status, "scam_signal": c.scam_signal, "created_at": c.created_at,
            "assigned_agent_id": c.assigned_agent_id}


def _store(db: DbSession, conv: SupportConversation, author: MessageAuthor, author_id, text: str,
           flags: list[str] | None = None) -> SupportMessage:
    clean, count = assistant.scrub(text) if author == MessageAuthor.CUSTOMER else (text, 0)
    m = SupportMessage(conversation_id=conv.id, author=author, author_id=author_id, content_redacted=clean,
                       redactions=count, flags=flags or [])
    db.add(m)
    db.flush()
    return m


def _customer_turn(db: DbSession, conv: SupportConversation, user: User, text: str) -> None:
    flags: list[str] = []
    if assistant.scam_signal(text):
        flags.append("scam_signal")
        if not conv.scam_signal:
            conv.scam_signal = True
            ev = emit(db, E.SUPPORT_SCAM_SIGNAL_DETECTED, user_id=user.id,
                      metadata={"conversation_id": str(conv.id)})
            resp.raise_alert(db, user_id=user.id, title="Arnaque possible signalée à RL SOLUTION",
                             result=RiskResult(65, RiskLevel.HIGH, PolicyDecision.ALLOW_AND_MONITOR, [],
                                               [{"code": "SCAM_SIGNAL_REPORTED", "points": 65,
                                                 "detail": "Le client décrit une sollicitation suspecte"}]),
                             event=ev, source=resp.AlertSource.SUPPORT)
    m = _store(db, conv, MessageAuthor.CUSTOMER, user.id, text, flags)
    if m.redactions:
        emit(db, E.SUPPORT_SECRET_REDACTED, user_id=user.id, metadata={"count": m.redactions})
    emit(db, E.SUPPORT_MESSAGE_RECEIVED, user_id=user.id)
    if conv.status == ConversationStatus.HUMAN:
        return
    if "scam_signal" in flags:
        reply = ("Ne communiquez jamais vos codes, même à un conseiller. Si vous en avez donné, bloquez votre carte "
                 "dans l'application. Je transmets votre dossier à un conseiller sécurité.")
        _escalate(db, conv, user, TicketPriority.URGENT, "Arnaque")
    elif assistant.wants_human(text):
        reply = "Je vous mets en relation avec un conseiller."
        _escalate(db, conv, user, TicketPriority.NORMAL, conv.topic or "Demande")
    else:
        # Le LLM peut mettre plusieurs dizaines de secondes : on valide d'abord le message du client pour ne pas
        # garder une transaction ouverte (PostgreSQL coupe les transactions inactives trop longues).
        db.commit()
        reply = assistant.answer(db, text) or (
            "Je n'ai pas de réponse précise. Souhaitez-vous parler à un conseiller ? Écrivez « conseiller ».")
    _store(db, conv, MessageAuthor.BOT, None, reply)


def _escalate(db: DbSession, conv: SupportConversation, user: User, priority: TicketPriority, category: str) -> None:
    conv.status = ConversationStatus.WAITING_HUMAN
    if db.scalar(select(SupportTicket.id).where(SupportTicket.conversation_id == conv.id)) is None:
        db.add(SupportTicket(conversation_id=conv.id, user_id=user.id, category=category[:48], priority=priority))
    emit(db, E.SUPPORT_ESCALATED, user_id=user.id, metadata={"conversation_id": str(conv.id)})


# ---- côté client -------------------------------------------------------------------------------------
@router.post("/conversations", status_code=201, summary="Démarrer une conversation")
def start(body: NewConversation, ctx: AuthContext = Depends(require_permission("support_conversation:write:own")),
          db: DbSession = Depends(get_db)):
    conv = SupportConversation(user_id=ctx.user.id, topic=body.topic)
    db.add(conv)
    db.flush()
    emit(db, E.SUPPORT_CONVERSATION_STARTED, user_id=ctx.user.id)
    _customer_turn(db, conv, ctx.user, body.message)
    db.commit()
    return {**_conv(conv), "messages": [_msg(m) for m in _messages(db, conv.id)]}


def _messages(db: DbSession, conv_id: uuid.UUID):
    return db.scalars(select(SupportMessage).where(SupportMessage.conversation_id == conv_id)
                      .order_by(SupportMessage.created_at, SupportMessage.id))


@router.get("/conversations", summary="Mes conversations")
def mine(ctx: AuthContext = Depends(require_permission("support_conversation:read:own")),
         db: DbSession = Depends(get_db)):
    return [_conv(c) for c in db.scalars(select(SupportConversation).where(SupportConversation.user_id == ctx.user.id)
                                         .order_by(SupportConversation.created_at.desc()).limit(30))]


@router.get("/conversations/{conv_id}", summary="Une de mes conversations")
def mine_detail(conv_id: uuid.UUID, ctx: AuthContext = Depends(require_permission("support_conversation:read:own")),
                db: DbSession = Depends(get_db)):
    conv = db.get(SupportConversation, conv_id)
    if conv is None or conv.user_id != ctx.user.id:
        raise AuthError(404, "conversation_not_found", "Conversation introuvable.")
    return {**_conv(conv), "messages": [_msg(m) for m in _messages(db, conv.id)]}


@router.post("/conversations/{conv_id}/messages", summary="Écrire à RL SOLUTION")
def write(conv_id: uuid.UUID, body: MessageIn,
          ctx: AuthContext = Depends(require_permission("support_conversation:write:own")),
          db: DbSession = Depends(get_db)):
    conv = db.get(SupportConversation, conv_id)
    if conv is None or conv.user_id != ctx.user.id or conv.status == ConversationStatus.CLOSED:
        raise AuthError(404, "conversation_not_found", "Conversation introuvable.")
    _customer_turn(db, conv, ctx.user, body.message)
    db.commit()
    return {**_conv(conv), "messages": [_msg(m) for m in _messages(db, conv.id)]}


# ---- côté conseiller ---------------------------------------------------------------------------------
def _agent_ticket(db: DbSession, ctx: AuthContext, ticket_id: uuid.UUID) -> SupportTicket:
    t = db.get(SupportTicket, ticket_id)
    if t is None or t.assigned_agent_id != ctx.user.id:
        raise AuthError(404, "ticket_not_found", "Ticket introuvable ou non assigné.")
    return t


@router.get("/queue", summary="File des tickets")
def queue(ctx: AuthContext = Depends(require_permission("support_conversation:read:assigned")),
          db: DbSession = Depends(get_db)):
    rows = db.scalars(select(SupportTicket).where(
        (SupportTicket.assigned_agent_id == ctx.user.id) | (SupportTicket.assigned_agent_id.is_(None)),
        SupportTicket.status.in_([TicketStatus.OPEN, TicketStatus.IN_PROGRESS]))
        .order_by(SupportTicket.priority, SupportTicket.created_at))
    out = []
    for t in rows:
        conv = db.get(SupportConversation, t.conversation_id)
        # un ticket non assigné n'expose ni le nom ni le dossier du client
        out.append({"id": t.id, "category": t.category, "priority": t.priority, "status": t.status,
                    "assigned_to_me": t.assigned_agent_id == ctx.user.id, "scam_signal": conv.scam_signal,
                    "conversation_id": conv.id, "created_at": t.created_at})
    return out


@router.post("/tickets/{ticket_id}/accept", summary="Prendre un ticket")
def accept(ticket_id: uuid.UUID, ctx: AuthContext = Depends(require_permission("support_conversation:write:assigned")),
           db: DbSession = Depends(get_db)):
    t = db.scalar(select(SupportTicket).where(SupportTicket.id == ticket_id).with_for_update())
    if t is None or (t.assigned_agent_id not in (None, ctx.user.id)):
        raise AuthError(404, "ticket_not_found", "Ticket indisponible.")
    t.assigned_agent_id, t.status = ctx.user.id, TicketStatus.IN_PROGRESS
    t.access_expires_at = datetime.now(UTC) + timedelta(hours=2)      # fenêtre d'accès limitée
    conv = db.get(SupportConversation, t.conversation_id)
    conv.assigned_agent_id, conv.status = ctx.user.id, ConversationStatus.HUMAN
    _store(db, conv, MessageAuthor.SYSTEM, None, "Un conseiller a pris en charge votre demande.")
    emit(db, E.SUPPORT_HANDOFF_ACCEPTED, user_id=ctx.user.id, metadata={"ticket_id": str(t.id)})
    db.commit()
    return {"id": t.id, "status": t.status, "access_expires_at": t.access_expires_at}


@router.get("/tickets/{ticket_id}", summary="Ticket assigné : conversation")
def ticket(ticket_id: uuid.UUID, ctx: AuthContext = Depends(require_permission("support_conversation:read:assigned")),
           db: DbSession = Depends(get_db)):
    t = _agent_ticket(db, ctx, ticket_id)
    conv = db.get(SupportConversation, t.conversation_id)
    return {"id": t.id, "category": t.category, "priority": t.priority, "status": t.status,
            "access_expires_at": t.access_expires_at, "conversation": _conv(conv),
            "messages": [_msg(m) for m in _messages(db, conv.id)]}


@router.post("/tickets/{ticket_id}/reply", summary="Répondre au client")
def reply(ticket_id: uuid.UUID, body: MessageIn,
          ctx: AuthContext = Depends(require_permission("support_conversation:write:assigned")),
          db: DbSession = Depends(get_db)):
    t = _agent_ticket(db, ctx, ticket_id)
    conv = db.get(SupportConversation, t.conversation_id)
    _store(db, conv, MessageAuthor.AGENT, ctx.user.id, body.message)
    db.commit()
    return {"ok": True}


@router.get("/tickets/{ticket_id}/customer", summary="Dossier du client du ticket (consultation tracée)")
def ticket_customer(ticket_id: uuid.UUID, request: Request,
                    ctx: AuthContext = Depends(require_permission("transfer:read:assigned")),
                    db: DbSession = Depends(get_db)):
    t = _agent_ticket(db, ctx, ticket_id)
    record_staff_access(db, ctx.user, ctx.session, t.user_id, purpose="support_ticket", ip=client_ip(request))
    db.commit()
    file = customer_file(db, db.get(User, t.user_id))
    file.pop("accounts")                        # le conseiller ne voit ni soldes ni IBAN
    file["user"].pop("email")
    return file


@router.post("/tickets/{ticket_id}/lock-card", summary="Verrouiller la carte du client (à sa demande)")
def lock_card(ticket_id: uuid.UUID, body: LockCardIn,
              ctx: AuthContext = Depends(require_permission("card:lock:assigned")), db: DbSession = Depends(get_db)):
    t = _agent_ticket(db, ctx, ticket_id)
    card = db.get(Card, body.card_id)
    if card is None or card.user_id != t.user_id or not has_ticket_access(db, ctx.user.id, t.user_id):
        raise AuthError(403, "no_assigned_ticket", "Aucun ticket assigné ne vous donne accès à cette carte.")
    row = resp.execute_action(db, SecurityActionType.LOCK_CARD, target_id=card.id, user=db.get(User, t.user_id),
                              by=ctx.user, justification=body.justification)
    resp.notify(db, t.user_id, "CARD_LOCKED", "Votre carte a été verrouillée",
                "À votre demande, un conseiller a verrouillé votre carte.")
    db.commit()
    return {"action_id": row.id, "status": row.status}


@router.post("/tickets/{ticket_id}/close", summary="Clôturer le ticket")
def close(ticket_id: uuid.UUID, ctx: AuthContext = Depends(require_permission("support_conversation:write:assigned")),
          db: DbSession = Depends(get_db)):
    t = _agent_ticket(db, ctx, ticket_id)
    t.status, t.resolved_at, t.access_expires_at = TicketStatus.RESOLVED, datetime.now(UTC), datetime.now(UTC)
    conv = db.get(SupportConversation, t.conversation_id)
    conv.status, conv.closed_at = ConversationStatus.CLOSED, datetime.now(UTC)
    emit(db, E.SUPPORT_CONVERSATION_CLOSED, user_id=ctx.user.id, actor_type=ActorType.USER)
    db.commit()
    return {"id": t.id, "status": t.status}


@router.get("/conversations-all", summary="Toutes les conversations (audit / sécurité)")
def all_conversations(ctx: AuthContext = Depends(require_permission("support_conversation:read_security:any")),
                      db: DbSession = Depends(get_db)):
    return [_conv(c) for c in db.scalars(select(SupportConversation).where(SupportConversation.scam_signal.is_(True))
                                         .order_by(SupportConversation.created_at.desc()).limit(50))]
