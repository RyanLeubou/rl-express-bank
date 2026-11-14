"""Fabrique du service bancaire pour une requête authentifiée."""
from __future__ import annotations

import redis
from fastapi import Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session as DbSession

from app.core.cache import get_valkey
from app.core.config import Settings, get_settings
from app.core.database import get_db
from app.security.auth.deps import AuthContext, client_ip, device_of, get_auth_context
from app.services.banking.operations import BankingService, Caller, Outcome


def get_banking(request: Request, ctx: AuthContext = Depends(get_auth_context), db: DbSession = Depends(get_db),
                settings: Settings = Depends(get_settings),
                valkey: redis.Redis = Depends(get_valkey)) -> BankingService:
    caller = Caller(user=ctx.user, session=ctx.session, device=device_of(db, ctx), ip=client_ip(request),
                    ua=request.headers.get("user-agent"))
    return BankingService(db, settings, valkey, caller)


def outcome_response(out: Outcome) -> JSONResponse:
    body = {("state" if k == "status" else k): v for k, v in out.data.items()}
    body["status"] = out.status
    if out.challenge_id:
        body["challenge_id"] = str(out.challenge_id)
        body["method"] = "TOTP"
    return JSONResponse(body, status_code=202 if out.status == "step_up_required" else 200)
