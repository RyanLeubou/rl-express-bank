"""Journal d'audit chaîné : chaque entrée contient le hash de la précédente.

Toute modification ou suppression a posteriori (déjà interdite par droits et trigger)
serait de plus détectée par verify_audit_chain(). Les contenus avant/après sont masqués.
"""
from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import orjson
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.core.logging import request_id_ctx
from app.core.redaction import redact
from app.models.enums import ActorType
from app.models.security import AuditLog

GENESIS_HASH = "0" * 64
_CHAIN_LOCK_KEY = 7_430_001  # verrou consultatif : sérialise l'écriture de la chaîne


def _digest(fields: dict[str, Any]) -> str:
    return hashlib.sha256(orjson.dumps(fields, option=orjson.OPT_SORT_KEYS, default=str)).hexdigest()


def _hashed_fields(entry: AuditLog) -> dict[str, Any]:
    return {
        "id": str(entry.id), "timestamp": entry.timestamp.astimezone(UTC).isoformat(),
        "actor_type": str(entry.actor_type), "actor_id": str(entry.actor_id) if entry.actor_id else None,
        "actor_role": entry.actor_role, "action": entry.action, "target_type": entry.target_type,
        "target_id": entry.target_id, "before": entry.before, "after": entry.after,
        "justification": entry.justification, "prev_hash": entry.prev_hash,
    }


def record_audit(db: Session, *, action: str, target_type: str, target_id: str | uuid.UUID | None = None,
                 actor_id: uuid.UUID | None = None, actor_type: ActorType = ActorType.USER,
                 actor_role: str | None = None, before: dict | None = None, after: dict | None = None,
                 justification: str | None = None, ip_address: str | None = None) -> AuditLog:
    db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _CHAIN_LOCK_KEY})
    prev = db.scalar(select(AuditLog.hash).order_by(AuditLog.seq.desc()).limit(1)) or GENESIS_HASH
    entry = AuditLog(
        id=uuid.uuid4(), timestamp=datetime.now(UTC), actor_type=actor_type, actor_id=actor_id,
        actor_role=actor_role, action=action, target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        before=redact(before) if before is not None else None,
        after=redact(after) if after is not None else None,
        justification=justification, ip_address=ip_address, request_id=request_id_ctx.get(),
        prev_hash=prev,
    )
    entry.hash = _digest(_hashed_fields(entry))
    db.add(entry)
    db.flush()  # le suivant dans la même transaction doit voir ce hash
    return entry


@dataclass
class ChainReport:
    valid: bool
    entries: int
    broken_at_seq: int | None = None


def verify_entries(entries) -> ChainReport:
    """Vérifie une suite d'entrées ordonnée par seq : chaînage ET contenu de chaque entrée."""
    prev = GENESIS_HASH
    count = 0
    for entry in entries:
        count += 1
        if entry.prev_hash != prev or _digest(_hashed_fields(entry)) != entry.hash:
            return ChainReport(False, count, entry.seq)
        prev = entry.hash
    return ChainReport(True, count)


def verify_audit_chain(db: Session) -> ChainReport:
    return verify_entries(db.scalars(select(AuditLog).order_by(AuditLog.seq)).yield_per(500))
