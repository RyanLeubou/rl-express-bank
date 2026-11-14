"""Hachage Argon2id (mots de passe, PIN simulés, secrets de terminal ATM).

Paramètres au-dessus du minimum OWASP (m=19 Mio, t=2) : m=64 Mio, t=3, p=2.
Aucun mot de passe en clair n'est jamais stocké ni journalisé.
"""
from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)
# Hash factice : vérifié quand l'utilisateur n'existe pas, pour un temps de réponse constant (phase 4)
DUMMY_HASH = _hasher.hash("rl-express-bank-dummy-password")


def hash_secret(secret: str) -> str:
    return _hasher.hash(secret)


def verify_secret(secret_hash: str, secret: str) -> bool:
    try:
        return _hasher.verify(secret_hash, secret)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(secret_hash: str) -> bool:
    return _hasher.check_needs_rehash(secret_hash)
