"""Réponses d'erreur au format RFC 9457 (application/problem+json).

Aucune trace technique n'est renvoyée au client : l'identifiant de requête
permet de retrouver le détail dans les journaux.
"""
from __future__ import annotations

import logging
from http import HTTPStatus

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.logging import request_id_ctx
from app.security.auth.errors import AuthError

logger = logging.getLogger("rlbank.errors")
PROBLEM = "application/problem+json"


def problem(status: int, detail: str | None = None, *, code: str | None = None,
            errors: list[dict] | None = None, headers: dict | None = None) -> JSONResponse:
    body: dict[str, object] = {
        "type": f"https://bank.localhost/problems/{code or status}",
        "title": HTTPStatus(status).phrase,
        "status": status,
    }
    if detail:
        body["detail"] = detail
    if code:
        body["code"] = code
    if errors:
        body["errors"] = errors
    if rid := request_id_ctx.get():
        body["request_id"] = rid
    return JSONResponse(body, status_code=status, media_type=PROBLEM, headers=headers)


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AuthError)
    async def auth_error(_: Request, exc: AuthError) -> JSONResponse:
        from app.security.auth import cookies  # import tardif : évite un cycle au chargement

        resp = problem(exc.status, exc.detail, code=exc.code, headers=exc.headers)
        if exc.clear_session:
            cookies.clear_session_cookies(resp)
        if exc.clear_mfa:
            cookies.clear_mfa_cookie(resp)
        return resp

    @app.exception_handler(StarletteHTTPException)
    async def http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        detail = exc.detail if isinstance(exc.detail, str) else None
        return problem(exc.status_code, detail, headers=getattr(exc, "headers", None))

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        # On ne renvoie jamais la valeur saisie (elle peut contenir un secret)
        errors = [{"field": ".".join(str(p) for p in e.get("loc", [])), "message": e.get("msg", "")}
                  for e in exc.errors()]
        return problem(422, "Les données envoyées sont invalides.", code="validation_error", errors=errors)

    @app.exception_handler(Exception)
    async def unexpected_error(_: Request, exc: Exception) -> JSONResponse:
        logger.exception("Erreur non gérée", exc_info=exc)
        return problem(500, "Erreur interne. Communiquez l'identifiant de requête au support.",
                       code="internal_error")
