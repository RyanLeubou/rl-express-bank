"""Routes d'authentification : /api/v1/auth/*

Le navigateur ne manipule jamais de jeton : tout transite par des cookies HttpOnly.
Les réponses d'échec sont génériques (RFC 9457) ; le détail est dans les événements de sécurité.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session as DbSession

from app.core.config import Settings, get_settings
from app.core.database import get_db
from app.models.auth import Device
from app.models.identity import User
from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    MeResponse,
    MfaEnrollConfirmRequest,
    MfaEnrollConfirmResponse,
    MfaEnrollStartRequest,
    MfaEnrollStartResponse,
    MfaVerifyRequest,
    MfaVerifyResponse,
    RegisterRequest,
    RegisterResponse,
    SessionOut,
    UserOut,
)
from app.security.auth import cookies
from app.security.auth.deps import (
    AuthContext,
    check_origin,
    client_ip,
    get_auth_context,
    get_auth_service,
    is_device_trusted,
    require_permission,
)
from app.security.auth.service import AuthService, SessionBundle, user_permissions
from app.security.mfa import totp
from app.services.banking.rib import BRANCHES, CITY_AGENCY, format_iban

_SESSION_READ = require_permission("session:read:own")
_SESSION_REVOKE = require_permission("session:revoke:own")

router = APIRouter(prefix="/auth", tags=["Authentification"], dependencies=[Depends(check_origin)])


def _user_out(user: User, mfa_enabled: bool) -> UserOut:
    return UserOut(
        id=user.id, email=user.email, first_name=user.first_name, last_name=user.last_name,
        user_type=str(user.user_type), roles=sorted(r.code for r in user.roles),
        permissions=sorted(user_permissions(user)), mfa_enabled=mfa_enabled,
    )


def _apply_session(response: Response, settings: Settings, bundle: SessionBundle) -> None:
    cookies.set_session_cookies(response, settings, access=bundle.access, access_expires=bundle.access_expires,
                                refresh=bundle.refresh, refresh_max_age=bundle.refresh_max_age, csrf=bundle.csrf)
    cookies.clear_mfa_cookie(response)


@router.post("/login", response_model=LoginResponse, summary="Connexion (étape mot de passe)")
def login(body: LoginRequest, request: Request, response: Response,
          service: AuthService = Depends(get_auth_service), settings: Settings = Depends(get_settings)):
    outcome = service.login(
        email=body.email, password=body.password, ip=client_ip(request),
        ua=request.headers.get("user-agent"), device_cookie=request.cookies.get(cookies.DEVICE))
    cookies.set_device_cookie(response, settings, outcome.device.cookie_value)
    if outcome.bundle is not None:
        _apply_session(response, settings, outcome.bundle)
        return LoginResponse(status="authenticated", user=_user_out(outcome.user, service.mfa_enabled(outcome.user.id)),
                             new_device=outcome.device.is_new)
    cookies.set_mfa_cookie(response, settings, outcome.pending_token or "")
    return LoginResponse(status=outcome.status, new_device=outcome.device.is_new)  # type: ignore[arg-type]


@router.get("/register/cities", summary="Villes desservies et agence attribuée")
def register_cities():
    return [{"city": city, "agency": agency, "branch_code": BRANCHES[agency]}
            for city, agency in sorted(CITY_AGENCY.items())]


@router.post("/register", response_model=RegisterResponse, status_code=201, summary="Ouverture de compte en ligne")
def register(body: RegisterRequest, request: Request, response: Response,
             service: AuthService = Depends(get_auth_service), settings: Settings = Depends(get_settings)):
    ip, ua = client_ip(request), request.headers.get("user-agent")
    done = service.register(**body.model_dump(), ip=ip, ua=ua)
    # Connexion immédiate par la voie normale (appareil, session, événements)
    session = login(LoginRequest(email=body.email, password=body.password), request, response, service, settings)
    return RegisterResponse(**session.model_dump(), card_pin=done.card_pin, iban=format_iban(done.iban),
                            agency=done.agency, branch_code=done.branch_code)


@router.post("/mfa/verify", response_model=MfaVerifyResponse, summary="Connexion (second facteur)")
def mfa_verify(body: MfaVerifyRequest, request: Request, response: Response,
               service: AuthService = Depends(get_auth_service), settings: Settings = Depends(get_settings)):
    outcome, left = service.verify_mfa(
        pending_token=request.cookies.get(cookies.MFA), code=body.code, trust_device=body.trust_device,
        ip=client_ip(request), ua=request.headers.get("user-agent"))
    assert outcome.bundle is not None  # noqa: S101 - verify_mfa renvoie toujours une session ou lève
    _apply_session(response, settings, outcome.bundle)
    return MfaVerifyResponse(status="authenticated", user=_user_out(outcome.user, True), recovery_codes_left=left)


# ---- activation du TOTP : défi « enroll » (personnel, 1re connexion) ou session ouverte (client) ----
def _enroll_actor(request: Request, service: AuthService, db: DbSession,
                  settings: Settings) -> tuple[User, Device | None, object | None, object | None]:
    """Retourne (utilisateur, appareil, claims du défi, contexte de session) selon l'appelant."""
    pending_token = request.cookies.get(cookies.MFA)
    if pending_token:
        claims, user, device = service.read_pending(pending_token, purpose="enroll")
        return user, device, claims, None
    ctx = get_auth_context(request, db, settings, service.tokens)
    device = db.get(Device, ctx.session.device_id) if ctx.session.device_id else None
    return ctx.user, device, None, ctx


@router.post("/mfa/enroll/start", response_model=MfaEnrollStartResponse, summary="Démarrer l'activation du TOTP")
def mfa_enroll_start(body: MfaEnrollStartRequest, request: Request, db: DbSession = Depends(get_db),
                     service: AuthService = Depends(get_auth_service), settings: Settings = Depends(get_settings)):
    user, _, claims, _ctx = _enroll_actor(request, service, db, settings)
    secret, uri = service.enroll_start(user, password=body.current_password, pending=claims is not None,
                                       ip=client_ip(request), ua=request.headers.get("user-agent"))
    return MfaEnrollStartResponse(secret=secret, otpauth_uri=uri, qr_code=totp.qr_data_uri(uri))


@router.post("/mfa/enroll/confirm", response_model=MfaEnrollConfirmResponse, summary="Confirmer l'activation du TOTP")
def mfa_enroll_confirm(body: MfaEnrollConfirmRequest, request: Request, response: Response,
                       db: DbSession = Depends(get_db), service: AuthService = Depends(get_auth_service),
                       settings: Settings = Depends(get_settings)):
    user, device, claims, _ctx = _enroll_actor(request, service, db, settings)
    ip, ua = client_ip(request), request.headers.get("user-agent")
    recovery = service.enroll_confirm(user, code=body.code, ip=ip, ua=ua, device=device)
    if claims is not None and device is not None:
        bundle = service.finish_enrollment_login(claims, user, device, ip, ua)  # type: ignore[arg-type]
        db.commit()
        _apply_session(response, settings, bundle)
        return MfaEnrollConfirmResponse(status="authenticated", recovery_codes=recovery,
                                        user=_user_out(user, True))
    db.commit()
    return MfaEnrollConfirmResponse(status="mfa_enabled", recovery_codes=recovery, user=_user_out(user, True))


# ---- session ----
@router.post("/refresh", response_model=MeResponse, summary="Renouveler la session (rotation du jeton)")
def refresh(request: Request, response: Response, service: AuthService = Depends(get_auth_service),
            settings: Settings = Depends(get_settings), db: DbSession = Depends(get_db)):
    bundle, user = service.refresh(request.cookies.get(cookies.REFRESH), client_ip(request),
                                   request.headers.get("user-agent"))
    _apply_session(response, settings, bundle)
    device = db.get(Device, bundle.session.device_id) if bundle.session.device_id else None
    return MeResponse(user=_user_out(user, service.mfa_enabled(user.id)), aal=bundle.session.aal,
                      amr=list(bundle.session.amr), device_trusted=bool(device and device.status == "TRUSTED"),
                      session_expires_at=bundle.session.expires_at)


@router.post("/logout", status_code=204, summary="Déconnexion")
def logout(request: Request, response: Response, ctx: AuthContext = Depends(get_auth_context),
           service: AuthService = Depends(get_auth_service)):
    service.logout(ctx.session, ctx.user, client_ip(request), request.headers.get("user-agent"))
    cookies.clear_session_cookies(response)
    response.status_code = 204
    return response


@router.get("/me", response_model=MeResponse, summary="Identité et niveau d'assurance de la session")
def me(ctx: AuthContext = Depends(get_auth_context), service: AuthService = Depends(get_auth_service),
       db: DbSession = Depends(get_db)):
    return MeResponse(user=_user_out(ctx.user, service.mfa_enabled(ctx.user.id)), aal=ctx.aal,
                      amr=list(ctx.session.amr), device_trusted=is_device_trusted(db, ctx),
                      session_expires_at=ctx.session.expires_at)


@router.get("/sessions", response_model=list[SessionOut], summary="Mes sessions actives")
def list_sessions(ctx: AuthContext = Depends(_SESSION_READ),
                  service: AuthService = Depends(get_auth_service)):
    return [SessionOut(id=s.id, device=name, ip=str(s.ip) if s.ip else None, created_at=s.created_at,
                       last_activity=s.last_activity, current=s.id == ctx.session.id)
            for s, name in service.list_sessions(ctx.user)]


@router.delete("/sessions/{session_id}", status_code=204, summary="Révoquer une de mes sessions")
def revoke_session(session_id: uuid.UUID, request: Request, response: Response,
                   ctx: AuthContext = Depends(_SESSION_REVOKE),
                   service: AuthService = Depends(get_auth_service)):
    service.revoke_own_session(ctx.user, session_id, client_ip(request), request.headers.get("user-agent"))
    if session_id == ctx.session.id:
        cookies.clear_session_cookies(response)
    response.status_code = 204
    return response

