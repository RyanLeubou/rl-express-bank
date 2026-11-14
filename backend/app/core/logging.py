"""Journalisation JSON structurée, avec identifiant de requête et masquage systématique."""
from __future__ import annotations

import logging
import sys
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

import orjson

from app.core.redaction import redact, redact_text

request_id_ctx: ContextVar[str | None] = ContextVar("request_id", default=None)

_STANDARD_ATTRS = frozenset(vars(logging.LogRecord("", 0, "", 0, "", None, None))) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    def __init__(self, service: str) -> None:
        super().__init__()
        self.service = service

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "service": self.service,
            "logger": record.name,
            "message": redact_text(record.getMessage()),
        }
        request_id = request_id_ctx.get()
        if request_id:
            payload["request_id"] = request_id
        extras = {k: v for k, v in record.__dict__.items()
                  if k not in _STANDARD_ATTRS and not k.startswith("_")}
        if extras:
            payload["extra"] = redact(extras)
        if record.exc_info:
            payload["exception"] = redact_text(self.formatException(record.exc_info))
        return orjson.dumps(payload, default=str).decode("utf-8")


def configure_logging(level: str = "INFO", service: str = "rlbank-api") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter(service))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    # Les journaux d'accès d'uvicorn sont remplacés par notre middleware (masqué et corrélé)
    for name in ("uvicorn", "uvicorn.error"):
        logging.getLogger(name).handlers[:] = []
        logging.getLogger(name).propagate = True
    logging.getLogger("uvicorn.access").disabled = True
