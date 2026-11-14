"""Event Logger centralisé (socle phase 3, enrichi en phase 10).

emit() écrit l'événement ET ses entrées d'outbox dans la session courante, sans commit :
l'événement est donc validé ou annulé avec l'opération métier (Transactional Outbox).
Les métadonnées passent systématiquement par le masquage.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from app.core.logging import request_id_ctx
from app.core.redaction import redact
from app.events.catalog import CATALOG, EventType
from app.models.enums import ActorType, Severity
from app.models.security import OutboxEvent, SecurityEvent

OUTBOX_DESTINATIONS = ("wazuh_file", "opensearch")
_ALLOWED_FIELDS = {
    "user_id", "session_id", "device_id", "ip_address", "device", "os", "browser", "location", "country",
    "amount", "currency", "beneficiary_id", "transfer_id", "card_payment_id", "withdrawal_id", "atm_id",
    "status", "risk_score", "simulation_run_id",
}


def emit(db: Session, event_type: EventType | str, *, actor_type: ActorType = ActorType.USER,
         severity: Severity | None = None, occurred_at: datetime | None = None,
         metadata: dict[str, Any] | None = None, enqueue: bool = True, **fields: Any) -> SecurityEvent:
    event_type = EventType(event_type)                       # type inconnu -> ValueError
    unknown = set(fields) - _ALLOWED_FIELDS
    if unknown:
        raise ValueError(f"Champs d'événement inconnus : {sorted(unknown)}")
    category, default_severity = CATALOG[event_type]
    if fields.get("amount") is not None and fields.get("currency") is None:
        fields["currency"] = "XAF"
    event = SecurityEvent(
        id=uuid.uuid4(),
        event_type=event_type.value,
        category=category,
        severity=severity or default_severity,
        actor_type=actor_type,
        timestamp=occurred_at or datetime.now(UTC),
        request_id=request_id_ctx.get(),
        metadata_=redact(metadata or {}),
        **fields,
    )
    db.add(event)
    if enqueue:
        for destination in OUTBOX_DESTINATIONS:
            db.add(OutboxEvent(security_event=event, destination=destination))
    return event


def to_document(event: SecurityEvent) -> dict[str, Any]:
    """Format JSON structuré du cahier des charges (utilisé pour Wazuh et OpenSearch)."""
    return {
        "event_id": str(event.id),
        "timestamp": event.timestamp.isoformat(),
        "user_id": str(event.user_id) if event.user_id else None,
        "event_type": event.event_type,
        "category": event.category,
        "severity": str(event.severity),
        "ip_address": str(event.ip_address) if event.ip_address else None,
        "device": event.device,
        "os": event.os,
        "browser": event.browser,
        "location": event.location,
        "amount": event.amount,
        "currency": event.currency or "XAF",
        "beneficiary_id": str(event.beneficiary_id) if event.beneficiary_id else None,
        "transaction_id": str(event.transfer_id or event.card_payment_id or "") or None,
        "withdrawal_id": str(event.withdrawal_id) if event.withdrawal_id else None,
        "status": event.status,
        "metadata": event.metadata_,
        "source": "rl-express-bank",
    }
