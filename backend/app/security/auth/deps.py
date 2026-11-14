"""Dépendances FastAPI : identité courante, protection CSRF / Origin, contrôle des droits.

Chaque requête authentifiée vérifie la signature du JWT ET l'état de la session en base :
une session révoquée cesse de fonctionner immédiatement, sans attendre l'expiration du jeton.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

import redis
from fastapi import Depends, Request
from sqlalchemy.orm import Session as DbSession

from app.core.cache import get_valkey
from app.core.config import Settings, get_settings
from app.core.database import get_db
from app.models.auth import Device
from app.models.auth import Session as AuthSession
from app.models.enums import DeviceStatus, SessionStatus, UserStatus
from app.models.identity import User
from app.security.auth import cookies
from app.security.auth.errors import AuthError
from app.security.auth.service import AuthService, user_permissions
from app.security.auth.tokens import AccessClaims, TokenError, TokenService, get_token_service, verify_csrf

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
ACTIVITY_REFRESH = timedelta(seconds=60)      # on n'écrit last_activity qu'une fois par minute


@dataclass
class AuthContext:
    user: User
    session: AuthSession
    claims: AccessClaims
    permissions: set[str]

    @property
    def aal(self) -> int:
        return self.session.aal


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def get_auth_service(db: DbSession = Depends(get_db), settings: Settings = Depends(get_settings),
                     valkey: redis.Redis = Depends(get_valkey),
                     tokens: TokenService = Depends(get_token_service)) -> AuthService:
    return AuthService(db, settings, valkey, tokens)


def check_origin(request: Request, settings: Settings = Depends(get_settings)) -> None:
    """Refuse toute requête modifiante venant d'une autre origine (défense en profondeur avec SameSite)."""
    if request.method in SAFE_METHODS:
        return
    origin = request.headers.get("origin")
    if origin:
        allowed = {_origin(settings.public_base_url), *(_origin(o) for o in settings.cors_origins)}
        if _origin(origin) not in allowed:
            raise AuthError(403, "origin_not_allowed", "Origine non autorisée.")
    elif request.headers.get("sec-fetch-site", "").lower() == "cross-site":
        raise AuthError(403, "origin_not_allowed", "Origine non autorisée.")


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}".lower()


def get_auth_context(request: Request, db: DbSession = Depends(get_db),
                     settings: Settings = Depends(get_settings),
                     tokens: TokenService = Depends(get_token_service)) -> AuthContext:
    unauthenticated = AuthError(401, "not_authenticated", "Authentification requise.")
    token = request.cookies.get(cookies.ACCESS)
    if not token:
        raise unauthenticated
    try:
        claims = tokens.decode_access(token)
    except TokenError as exc:
        raise unauthenticated from exc

    session = db.get(AuthSession, claims.session_id)
    now = datetime.now(UTC)
    if (session is None or session.user_id != claims.user_id or session.status != SessionStatus.ACTIVE
            or session.expires_at <= now):
        raise unauthenticated
    user = db.get(User, claims.user_id)
    if user is None or user.status != UserStatus.ACTIVE:
        raise unauthenticated

    if request.method not in SAFE_METHODS:
        csrf_ok = verify_csrf(settings.app_secret_key.get_secret_value(), session.id,
                              request.cookies.get(cookies.CSRF), request.headers.get("x-csrf-token"))
        if not csrf_ok:
            raise AuthError(403, "csrf_failed", "Requête refusée (jeton CSRF invalide).")

    if now - session.last_activity > ACTIVITY_REFRESH:
        session.last_activity = now
        db.commit()
    return AuthContext(user=user, session=session, claims=claims, permissions=user_permissions(user))


def require_permission(code: str):
    """Exige une permission du catalogue RBAC (ex. « session:read:own »)."""
    def dependency(ctx: AuthContext = Depends(get_auth_context)) -> AuthContext:
        if code not in ctx.permissions:
            raise AuthError(403, "forbidden", "Action non autorisée pour votre profil.")
        return ctx
    return dependency


def require_aal(level: int):
    """Exige un niveau d'assurance d'authentification minimal (2 = second facteur validé)."""
    def dependency(ctx: AuthContext = Depends(get_auth_context)) -> AuthContext:
        if ctx.aal < level:
            raise AuthError(403, "step_up_required", "Une vérification supplémentaire est requise.")
        return ctx
    return dependency


def device_of(db: DbSession, ctx: AuthContext) -> Device | None:
    return db.get(Device, ctx.session.device_id) if ctx.session.device_id else None


def is_device_trusted(db: DbSession, ctx: AuthContext) -> bool:
    device = device_of(db, ctx)
    return bool(device and device.status == DeviceStatus.TRUSTED)
