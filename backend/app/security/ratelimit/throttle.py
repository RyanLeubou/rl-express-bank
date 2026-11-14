"""Ralentissement progressif des échecs (Valkey), jamais de verrouillage définitif.

Après `free` échecs, chaque nouvel échec impose un délai 1 s, 2 s, 4 s… plafonné. Les tentatives
refusées pendant un délai ne sont PAS comptées (un attaquant ne peut pas prolonger indéfiniment le délai
d'un utilisateur légitime en insistant). Plusieurs « seaux » indépendants se combinent :
  - paire compte + IP : un attaquant seul ne peut pas bloquer la victime depuis une autre adresse ;
  - IP seule         : credential stuffing sur plusieurs comptes ;
  - compte seul      : attaque distribuée (seuil volontairement élevé).
Si Valkey est indisponible, on refuse (fail closed) : une banque ne désactive pas ses protections en panne.
"""
from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass

import redis

from app.core.config import Settings
from app.security.auth.errors import AuthError

PREFIX = "rlbank:thr"


@dataclass(frozen=True)
class Bucket:
    name: str          # portée (pair, ip, account, mfa-user…)
    ident: str         # identifiant déjà haché
    free: int          # échecs tolérés avant le premier délai


def _h(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]


def login_buckets(settings: Settings, email: str, ip: str | None) -> list[Bucket]:
    email = email.strip().lower()
    ip = ip or "unknown"
    return [
        Bucket("pair", _h(email, ip), settings.throttle_free_pair),
        Bucket("ip", _h(ip), settings.throttle_free_ip),
        Bucket("account", _h(email), settings.throttle_free_account),
    ]


def register_buckets(settings: Settings, ip: str | None) -> list[Bucket]:
    # Chaque ouverture de compte compte comme un « échec » : limite la création en masse depuis une IP
    return [Bucket("register-ip", _h("register", ip or "unknown"), settings.throttle_free_pair)]


def mfa_buckets(settings: Settings, user_id: str, ip: str | None) -> list[Bucket]:
    ip = ip or "unknown"
    return [
        Bucket("mfa-user", _h("mfa", user_id), settings.throttle_free_pair),
        Bucket("mfa-ip", _h("mfa", ip), settings.throttle_free_ip),
    ]


class ProgressiveThrottle:
    def __init__(self, client: redis.Redis, settings: Settings) -> None:
        self._r = client
        self._window = settings.throttle_window_seconds
        self._max_delay = settings.throttle_max_delay_seconds

    @staticmethod
    def _counter(b: Bucket) -> str:
        return f"{PREFIX}:{b.name}:{b.ident}:n"

    @staticmethod
    def _until(b: Bucket) -> str:
        return f"{PREFIX}:{b.name}:{b.ident}:until"

    def check(self, buckets: list[Bucket]) -> tuple[int, str | None]:
        """Retourne (secondes à attendre, portée bloquante). (0, None) si la voie est libre."""
        try:
            worst, scope = 0, None
            for b in buckets:
                ttl_ms = int(self._r.pttl(self._until(b)))
                if ttl_ms > 0 and math.ceil(ttl_ms / 1000) > worst:
                    worst, scope = math.ceil(ttl_ms / 1000), b.name
            return worst, scope
        except redis.RedisError as exc:
            raise self._unavailable() from exc

    def fail(self, buckets: list[Bucket]) -> int:
        """Enregistre un échec ; retourne le délai (s) désormais imposé (0 si aucun)."""
        try:
            worst = 0
            for b in buckets:
                pipe = self._r.pipeline()
                pipe.incr(self._counter(b))
                pipe.expire(self._counter(b), self._window)
                count = int(pipe.execute()[0])
                if count > b.free:
                    delay = min(2 ** (count - b.free - 1), self._max_delay)
                    self._r.set(self._until(b), "1", ex=delay)
                    worst = max(worst, delay)
            return worst
        except redis.RedisError as exc:
            raise self._unavailable() from exc

    def reset(self, buckets: list[Bucket]) -> None:
        try:
            for b in buckets:
                self._r.delete(self._counter(b), self._until(b))
        except redis.RedisError as exc:
            raise self._unavailable() from exc

    @staticmethod
    def _unavailable() -> AuthError:
        return AuthError(503, "service_unavailable", "Service temporairement indisponible. Réessayez plus tard.")
