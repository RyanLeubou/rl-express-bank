"""Jetons.

- Jeton d'accès : JWT signé Ed25519 (EdDSA), courte durée, porté par un cookie HttpOnly.
- Défi MFA en attente : JWT signé, très court, lié à l'utilisateur et à l'appareil.
- Jetons opaques (rafraîchissement, identifiant d'appareil) : aléatoires, seul leur SHA-256 est stocké.
- CSRF : jeton signé HMAC lié à la session (double soumission de cookie renforcée).
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization

from app.core.config import Settings, get_settings

ISSUER = "rlbank"
AUDIENCE = "rlbank-api"
ALGORITHM = "EdDSA"


class TokenError(Exception):
    """Jeton absent, expiré, mal signé ou d'un mauvais type (aucun détail renvoyé au client)."""


@dataclass(frozen=True)
class AccessClaims:
    user_id: uuid.UUID
    session_id: uuid.UUID
    aal: int
    amr: tuple[str, ...]
    expires_at: datetime


@dataclass(frozen=True)
class MfaPendingClaims:
    user_id: uuid.UUID
    device_id: uuid.UUID
    purpose: str          # "login" (second facteur) ou "enroll" (première activation du personnel)
    jti: str


class TokenService:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._private = serialization.load_pem_private_key(
            Path(settings.jwt_private_key_path).read_bytes(), password=None)
        self._public = serialization.load_pem_public_key(Path(settings.jwt_public_key_path).read_bytes())

    # ---- émission ----
    def _encode(self, claims: dict) -> str:
        return jwt.encode(claims, self._private, algorithm=ALGORITHM)

    def issue_access(self, user_id: uuid.UUID, session_id: uuid.UUID, aal: int,
                     amr: list[str]) -> tuple[str, datetime]:
        now = datetime.now(UTC)
        exp = now + timedelta(seconds=self._settings.jwt_access_ttl_seconds)
        token = self._encode({
            "iss": ISSUER, "aud": AUDIENCE, "typ": "access", "sub": str(user_id), "sid": str(session_id),
            "aal": aal, "amr": amr, "iat": now, "nbf": now, "exp": exp, "jti": uuid.uuid4().hex,
        })
        return token, exp

    def issue_mfa_pending(self, user_id: uuid.UUID, device_id: uuid.UUID, purpose: str) -> tuple[str, str]:
        now = datetime.now(UTC)
        jti = uuid.uuid4().hex
        token = self._encode({
            "iss": ISSUER, "aud": AUDIENCE, "typ": "mfa_pending", "sub": str(user_id), "did": str(device_id),
            "purpose": purpose, "iat": now, "nbf": now,
            "exp": now + timedelta(seconds=self._settings.mfa_pending_ttl_seconds), "jti": jti,
        })
        return token, jti

    # ---- vérification ----
    def _decode(self, token: str, expected_type: str) -> dict:
        try:
            claims = jwt.decode(
                token, self._public, algorithms=[ALGORITHM], audience=AUDIENCE, issuer=ISSUER,
                options={"require": ["exp", "iat", "nbf", "iss", "aud", "sub", "jti", "typ"]},
            )
        except jwt.PyJWTError as exc:
            raise TokenError("jeton invalide") from exc
        if claims.get("typ") != expected_type:
            raise TokenError("type de jeton inattendu")
        return claims

    def decode_access(self, token: str) -> AccessClaims:
        claims = self._decode(token, "access")
        try:
            return AccessClaims(
                user_id=uuid.UUID(claims["sub"]), session_id=uuid.UUID(claims["sid"]),
                aal=int(claims["aal"]), amr=tuple(claims.get("amr", [])),
                expires_at=datetime.fromtimestamp(claims["exp"], UTC),
            )
        except (KeyError, ValueError) as exc:
            raise TokenError("revendications invalides") from exc

    def decode_mfa_pending(self, token: str) -> MfaPendingClaims:
        claims = self._decode(token, "mfa_pending")
        try:
            return MfaPendingClaims(user_id=uuid.UUID(claims["sub"]), device_id=uuid.UUID(claims["did"]),
                                    purpose=str(claims["purpose"]), jti=str(claims["jti"]))
        except (KeyError, ValueError) as exc:
            raise TokenError("revendications invalides") from exc


@lru_cache
def get_token_service() -> TokenService:
    return TokenService(get_settings())


# ---- jetons opaques ----
def new_opaque_token() -> str:
    """256 bits d'aléa, encodés en base64url (43 caractères)."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """SHA-256 : suffisant pour un secret à forte entropie (pas de mot de passe humain ici)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ---- CSRF lié à la session ----
def make_csrf(secret: str, session_id: uuid.UUID) -> str:
    nonce = secrets.token_urlsafe(16)
    mac = hmac.new(secret.encode(), f"csrf:{session_id}:{nonce}".encode(), hashlib.sha256).hexdigest()[:32]
    return f"{nonce}.{mac}"


def verify_csrf(secret: str, session_id: uuid.UUID, cookie_value: str | None, header_value: str | None) -> bool:
    if not cookie_value or not header_value or not hmac.compare_digest(cookie_value, header_value):
        return False
    nonce, _, mac = cookie_value.partition(".")
    if not nonce or not mac:
        return False
    expected = hmac.new(secret.encode(), f"csrf:{session_id}:{nonce}".encode(), hashlib.sha256).hexdigest()[:32]
    return hmac.compare_digest(mac, expected)
