"""Middlewares ASGI : identifiant de requête, en-têtes de sécurité, journal d'accès masqué."""
from __future__ import annotations

import logging
import re
import time
import uuid

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.logging import request_id_ctx

access_logger = logging.getLogger("rlbank.access")
_VALID_REQUEST_ID = re.compile(r"^[A-Za-z0-9\-]{8,64}$")

API_SECURITY_HEADERS: list[tuple[bytes, bytes]] = [
    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'; base-uri 'none'"),
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"cache-control", b"no-store"),
    (b"cross-origin-resource-policy", b"same-origin"),
]
# La documentation Swagger (servie localement) a besoin de ses propres scripts et styles
DOCS_CSP = (b"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
            b"img-src 'self' data:; frame-ancestors 'none'")


class RequestContextMiddleware:
    """Attribue un identifiant de requête, pose les en-têtes et journalise l'accès."""

    def __init__(self, app: ASGIApp, docs_prefix: str = "/api/docs") -> None:
        self.app = app
        self.docs_prefix = docs_prefix

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        incoming = dict(scope.get("headers") or []).get(b"x-request-id", b"").decode("latin-1")
        request_id = incoming if _VALID_REQUEST_ID.match(incoming) else str(uuid.uuid4())
        token = request_id_ctx.set(request_id)
        path: str = scope.get("path", "")
        is_docs = path.startswith(self.docs_prefix) or path.endswith("/openapi.json")
        started = time.perf_counter()
        status_holder = {"status": 500}

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
                managed = {h for h, _ in API_SECURITY_HEADERS} | {b"server"}
                headers = [(k, v) for k, v in message.get("headers", []) if k.lower() not in managed]
                for name, value in API_SECURITY_HEADERS:
                    if is_docs and name == b"content-security-policy":
                        value = DOCS_CSP
                    headers.append((name, value))
                headers.append((b"x-request-id", request_id.encode("latin-1")))
                message["headers"] = headers
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            # Ni query string ni corps : ils peuvent contenir des données sensibles
            access_logger.info(
                "%s %s %s", scope.get("method"), path, status_holder["status"],
                extra={
                    "http_method": scope.get("method"),
                    "path": path,
                    "status_code": status_holder["status"],
                    "duration_ms": round((time.perf_counter() - started) * 1000, 1),
                    "client_ip": (scope.get("client") or ("", 0))[0],
                },
            )
            request_id_ctx.reset(token)
