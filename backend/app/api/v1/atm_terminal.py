"""Terminal ATM simulé : authentifié par code + secret de terminal (jamais par cookie utilisateur)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Header, Request
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.core.cache import get_valkey
from app.core.config import Settings, get_settings
from app.core.database import get_db
from app.models import ATM
from app.schemas.banking import AtmRedeemIn
from app.security.auth.deps import client_ip
from app.security.auth.errors import AuthError
from app.security.auth.passwords import DUMMY_HASH, verify_secret
from app.security.ratelimit.throttle import Bucket, ProgressiveThrottle, _h
from app.services.banking.operations import redeem_cardless

router = APIRouter(prefix="/atm-terminal", tags=["Terminal ATM"])


def authenticated_atm(request: Request, db: DbSession = Depends(get_db), settings: Settings = Depends(get_settings),
                      code: str = Header(alias="X-ATM-Code", max_length=20),
                      secret: str = Header(alias="X-ATM-Secret", max_length=128)) -> ATM:
    throttle = ProgressiveThrottle(get_valkey(), settings)
    buckets = [Bucket("atm", _h(code, client_ip(request) or "?"), 5)]
    wait, _ = throttle.check(buckets)
    if wait:
        raise AuthError(429, "too_many_attempts", "Trop de tentatives.", headers={"Retry-After": str(wait)})
    atm = db.scalar(select(ATM).where(ATM.atm_code == code))
    ok = verify_secret(atm.terminal_secret_hash if atm else DUMMY_HASH, secret)
    if not atm or not ok:
        throttle.fail(buckets)
        raise AuthError(401, "terminal_unauthorized", "Terminal non autorisé.")
    return atm


@router.get("/status", summary="Identité et état du terminal")
def status(atm: ATM = Depends(authenticated_atm)):
    return {"code": atm.atm_code, "name": atm.name, "city": atm.city, "status": atm.status}


@router.post("/cardless/redeem", summary="Retirer avec un code sans carte")
def redeem(body: AtmRedeemIn, request: Request, atm: ATM = Depends(authenticated_atm),
           db: DbSession = Depends(get_db), settings: Settings = Depends(get_settings)):
    return redeem_cardless(db, settings, atm=atm, reference=body.reference, code=body.code, ip=client_ip(request))
