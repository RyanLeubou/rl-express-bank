"""Masquage des données sensibles avant toute écriture dans les journaux.

Principe : on ne journalise jamais mot de passe, jeton, secret TOTP, code OTP,
code de retrait sans carte, PIN, CVV ou en-tête d'authentification.
Deux mécanismes : par nom de clé (structures) et par motif (texte libre).
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

MASK = "[MASQUÉ]"

SENSITIVE_KEYS = frozenset({
    "password", "new_password", "current_password", "password_hash", "passwd",
    "token", "access_token", "refresh_token", "id_token", "jwt",
    "secret", "totp_secret", "client_secret", "api_key", "apikey",
    "otp", "totp", "code", "mfa_code", "otp_code", "cardless_code", "recovery_code",
    "verification_code", "auth_code", "authorization_code",
    "pin", "cvv", "cvc", "pan", "card_number",
    "authorization", "cookie", "set-cookie", "x-api-key",
    "private_key", "credential", "assertion",
})

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Jetons Bearer et JWT
    (re.compile(r"(?i)\bbearer\s+[a-z0-9\-_\.=]+"), f"Bearer {MASK}"),
    (re.compile(r"\beyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+"), MASK),
    # paires clé=valeur ou clé: valeur sur des clés sensibles
    (re.compile(
        r"(?i)\b(password|passwd|token|secret|otp|totp|pin|cvv|code)\b(\s*[:=]\s*)(\"?)[^\s\",;&]+"
    ), rf"\1\2\3{MASK}"),
    # Numéros de carte (13 à 19 chiffres, séparateurs possibles)
    (re.compile(r"\b(?:\d[ -]?){12,18}\d\b"), MASK),
]


def is_sensitive_key(key: str) -> bool:
    k = key.lower()
    # Pas de règle générique « _code » : status_code, currency_code, atm_code doivent rester lisibles
    return k in SENSITIVE_KEYS or k.endswith(("_password", "_token", "_secret", "_pin"))


def redact_text(text: str) -> str:
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact(value: Any, _depth: int = 0) -> Any:
    """Masque récursivement une structure (dict, liste, texte)."""
    if _depth > 8:
        return MASK
    if isinstance(value, Mapping):
        return {
            k: (MASK if isinstance(k, str) and is_sensitive_key(k) else redact(v, _depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        return type(value)(redact(v, _depth + 1) for v in value) if not isinstance(value, set) else [
            redact(v, _depth + 1) for v in value
        ]
    if isinstance(value, str):
        return redact_text(value)
    return value
