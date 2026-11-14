"""Secrets des terminaux ATM simulés : dérivés de APP_SECRET_KEY (HMAC), jamais stockés en clair.
Le kiosque ATM (phase 8) s'authentifie avec ce secret ; la base n'en garde qu'un hash Argon2id."""
from __future__ import annotations

import hashlib
import hmac

from app.core.config import get_settings


def derive_terminal_secret(atm_code: str) -> str:
    key = get_settings().app_secret_key.get_secret_value().encode()
    return hmac.new(key, f"atm-terminal:{atm_code}".encode(), hashlib.sha256).hexdigest()
