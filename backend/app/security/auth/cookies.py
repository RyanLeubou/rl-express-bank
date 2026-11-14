"""Cookies d'authentification : tous Secure, SameSite=Strict, préfixes __Host-/__Secure-.

  access   HttpOnly  Path=/                (JWT court)
  refresh  HttpOnly  Path=/api/v1/auth     (envoyé uniquement aux routes d'authentification)
  csrf     lisible par le script (double soumission) — lié à la session par HMAC
  device   HttpOnly  Path=/                (identifiant d'appareil aléatoire, 1 an)
  mfa      HttpOnly  Path=/                (défi MFA en attente, quelques minutes)
Aucun jeton n'est jamais accessible au JavaScript (XSS) sauf le jeton CSRF, inutilisable seul.
"""
from __future__ import annotations

from datetime import datetime

from fastapi import Response

from app.core.config import Settings

ACCESS = "__Host-rlb_at"
CSRF = "__Host-rlb_csrf"
DEVICE = "__Host-rlb_did"
MFA = "__Host-rlb_mfa"
REFRESH = "__Secure-rlb_rt"
REFRESH_PATH = "/api/v1/auth"


def _set(response: Response, name: str, value: str, *, max_age: int, path: str = "/",
         http_only: bool = True) -> None:
    response.set_cookie(name, value, max_age=max(max_age, 0), path=path, secure=True, httponly=http_only,
                        samesite="strict")


def _delete(response: Response, name: str, path: str = "/") -> None:
    response.delete_cookie(name, path=path, secure=True, httponly=name != CSRF, samesite="strict")


def set_session_cookies(response: Response, settings: Settings, *, access: str, access_expires: datetime,
                        refresh: str, refresh_max_age: int, csrf: str) -> None:
    access_age = int((access_expires - datetime.now(access_expires.tzinfo)).total_seconds())
    _set(response, ACCESS, access, max_age=access_age)
    _set(response, REFRESH, refresh, max_age=refresh_max_age, path=REFRESH_PATH)
    _set(response, CSRF, csrf, max_age=refresh_max_age, http_only=False)


def clear_session_cookies(response: Response) -> None:
    _delete(response, ACCESS)
    _delete(response, REFRESH, REFRESH_PATH)
    _delete(response, CSRF)


def set_device_cookie(response: Response, settings: Settings, value: str) -> None:
    _set(response, DEVICE, value, max_age=settings.device_cookie_ttl_days * 86400)


def set_mfa_cookie(response: Response, settings: Settings, value: str) -> None:
    _set(response, MFA, value, max_age=settings.mfa_pending_ttl_seconds)


def clear_mfa_cookie(response: Response) -> None:
    _delete(response, MFA)
