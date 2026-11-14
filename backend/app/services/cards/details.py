"""Numéro complet et CVV des cartes fictives, recalculés à la demande (jamais stockés).

Comme un HSM qui dérive le CVV à partir d'une clé (CVK), on dérive ici PAN et CVV du jeton de carte par
HMAC-SHA256 avec une sous-clé de DATA_ENCRYPTION_KEY. Le PAN conserve les 4 derniers chiffres en base et
respecte l'algorithme de Luhn ; le BIN 999990 est fictif (même préfixe que le code banque 99990).
"""
from __future__ import annotations

import base64
import hashlib
import hmac

from app.core.config import Settings
from app.models.cards import Card

FICTIONAL_BIN = "999990"


def _key(settings: Settings) -> bytes:
    master = base64.b64decode(settings.data_encryption_key.get_secret_value(), validate=True)
    return hmac.new(master, b"rlbank:card-details:v1", hashlib.sha256).digest()   # séparation de domaine


def _digits(key: bytes, label: str, count: int) -> str:
    value = int.from_bytes(hmac.new(key, label.encode(), hashlib.sha256).digest(), "big")
    return f"{value % 10**count:0{count}d}"


def _luhn_sum(digits: str) -> int:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total


def full_pan(settings: Settings, card: Card) -> str:
    """16 chiffres : BIN (6) + 5 chiffres dérivés + 1 chiffre d'ajustement Luhn + last4."""
    body = FICTIONAL_BIN + _digits(_key(settings), f"pan|{card.card_token}", 5)
    # Le chiffre d'ajustement est en 5e position depuis la droite (rang impair) : il n'est pas doublé
    adjust = (10 - _luhn_sum(body + "0" + card.last4) % 10) % 10
    return f"{body}{adjust}{card.last4}"


def cvv(settings: Settings, card: Card) -> str:
    pan = full_pan(settings, card)
    return _digits(_key(settings), f"cvv|{pan}|{card.expiry_month:02d}{card.expiry_year % 100:02d}", 3)


def luhn_ok(pan: str) -> bool:
    return pan.isdigit() and _luhn_sum(pan) % 10 == 0
