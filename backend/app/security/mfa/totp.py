"""MFA TOTP (RFC 6238) : secret chiffré au repos, anti-rejeu, codes de secours.

- Le secret TOTP est chiffré en AES-256-GCM (clé DATA_ENCRYPTION_KEY), lié à l'utilisateur
  par les données authentifiées associées (AAD) : un blob copié vers un autre compte est inutilisable.
- Un code TOTP n'est accepté qu'une fois (suivi du pas de temps déjà consommé).
- Les codes de secours (50 bits d'entropie) ne sont stockés que sous forme d'HMAC-SHA256 avec une clé serveur.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import time
import uuid

import pyotp
import segno
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import Settings

TOTP_STEP_SECONDS = 30
TOTP_DIGITS = 6
TOTP_WINDOW = 1                      # tolérance : un pas avant / après (dérive d'horloge)
RECOVERY_CODE_COUNT = 10
_RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"    # sans I, O, 0, 1 (lisibilité)
_TOTP_RE = re.compile(r"^\d{6}$")
_RECOVERY_RE = re.compile(r"^[A-HJ-NP-Z2-9]{10}$")


def _aes(settings: Settings) -> AESGCM:
    try:
        key = base64.b64decode(settings.data_encryption_key.get_secret_value(), validate=True)
    except ValueError as exc:
        raise RuntimeError("DATA_ENCRYPTION_KEY doit être une chaîne base64 valide") from exc
    if len(key) != 32:
        raise RuntimeError("DATA_ENCRYPTION_KEY doit décoder exactement 32 octets (AES-256)")
    return AESGCM(key)


def encrypt_secret(settings: Settings, secret_b32: str, user_id: uuid.UUID) -> bytes:
    nonce = secrets.token_bytes(12)
    return nonce + _aes(settings).encrypt(nonce, secret_b32.encode(), user_id.bytes)


def decrypt_secret(settings: Settings, blob: bytes, user_id: uuid.UUID) -> str:
    return _aes(settings).decrypt(blob[:12], blob[12:], user_id.bytes).decode()


def generate_secret() -> str:
    return pyotp.random_base32(32)       # 160 bits


def provisioning_uri(secret_b32: str, account: str, issuer: str) -> str:
    return pyotp.TOTP(secret_b32, digits=TOTP_DIGITS, interval=TOTP_STEP_SECONDS).provisioning_uri(
        name=account, issuer_name=issuer)


def qr_data_uri(uri: str) -> str:
    """QR code (image SVG en data: URI) de l'URI otpauth://, à scanner avec l'application du téléphone."""
    return segno.make(uri, error="m").svg_data_uri(scale=6, border=2, dark="#0b2a33", light="#ffffff")


def is_totp_format(code: str) -> bool:
    return bool(_TOTP_RE.match(code))


def verify_totp(secret_b32: str, code: str, last_used_step: int | None, now: float | None = None) -> int | None:
    """Retourne le pas de temps validé (à mémoriser), ou None. Un pas déjà consommé est refusé."""
    if not is_totp_format(code):
        return None
    totp = pyotp.TOTP(secret_b32, digits=TOTP_DIGITS, interval=TOTP_STEP_SECONDS)
    current = int((now if now is not None else time.time()) // TOTP_STEP_SECONDS)
    matched: int | None = None
    for step in range(current - TOTP_WINDOW, current + TOTP_WINDOW + 1):
        # on teste TOUS les pas (pas de sortie anticipée) : temps de réponse indépendant du résultat
        if hmac.compare_digest(totp.at(step * TOTP_STEP_SECONDS), code) and (
                last_used_step is None or step > last_used_step):
            matched = step
    return matched


# ---- codes de secours ----
def generate_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> list[str]:
    return ["".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(10)) for _ in range(count)]


def normalize_recovery_code(code: str) -> str:
    return re.sub(r"[\s-]", "", code).upper()


def is_recovery_format(code: str) -> bool:
    return bool(_RECOVERY_RE.match(normalize_recovery_code(code)))


def format_recovery_code(code: str) -> str:
    return f"{code[:5]}-{code[5:]}"


def hash_recovery_code(settings: Settings, code: str) -> str:
    key = settings.app_secret_key.get_secret_value().encode()
    return hmac.new(key, b"recovery:" + normalize_recovery_code(code).encode(), hashlib.sha256).hexdigest()
