"""Briques cryptographiques de l'authentification : jetons, TOTP, CSRF, limitation, appareils.

Aucun service externe : la limitation progressive utilise un faux Valkey en mémoire.
"""
from __future__ import annotations

import base64
import time
import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest

from app.core.config import Settings
from app.security.auth.errors import AuthError
from app.security.auth.tokens import (
    ALGORITHM,
    AUDIENCE,
    ISSUER,
    TokenError,
    TokenService,
    hash_token,
    make_csrf,
    new_opaque_token,
    verify_csrf,
)
from app.security.devices.service import fingerprint, parse_user_agent, sanitize_ip
from app.security.mfa import totp
from app.security.ratelimit.throttle import Bucket, ProgressiveThrottle, login_buckets


@pytest.fixture
def cfg(jwt_key_files) -> Settings:
    private, public = jwt_key_files
    return Settings(
        app_env="test", jwt_private_key_path=str(private), jwt_public_key_path=str(public),
        data_encryption_key=base64.b64encode(bytes(range(32))).decode(),
        app_secret_key="s3cr3t-App-Key-0123456789abcdef0123456789ab",
    )


@pytest.fixture
def tokens(cfg) -> TokenService:
    return TokenService(cfg)


# ---------------------------------------------------------------- JWT
def test_access_token_roundtrip(tokens):
    uid, sid = uuid.uuid4(), uuid.uuid4()
    token, exp = tokens.issue_access(uid, sid, 2, ["pwd", "otp"])
    claims = tokens.decode_access(token)
    assert (claims.user_id, claims.session_id, claims.aal, claims.amr) == (uid, sid, 2, ("pwd", "otp"))
    assert exp > datetime.now(UTC)


def test_access_token_tampered_or_garbage_is_rejected(tokens):
    token, _ = tokens.issue_access(uuid.uuid4(), uuid.uuid4(), 1, ["pwd"])
    head, payload, sig = token.split(".")
    flipped = payload[:-2] + ("AA" if payload[-2:] != "AA" else "BB")
    for bad in (f"{head}.{flipped}.{sig}", token[:-4] + "AAAA", "", "pas.un.jwt", "x"):
        with pytest.raises(TokenError):
            tokens.decode_access(bad)


def test_unsigned_and_wrong_algorithm_tokens_are_rejected(tokens, cfg):
    now = datetime.now(UTC)
    claims = {"iss": ISSUER, "aud": AUDIENCE, "typ": "access", "sub": str(uuid.uuid4()), "sid": str(uuid.uuid4()),
              "aal": 2, "amr": [], "iat": now, "nbf": now, "exp": now + timedelta(minutes=5), "jti": "x"}
    unsigned = jwt.encode(claims, key=None, algorithm="none")
    hs256 = jwt.encode(claims, key=b"k" * 32, algorithm="HS256")        # confusion d'algorithme
    for forged in (unsigned, hs256):
        with pytest.raises(TokenError):
            tokens.decode_access(forged)


def test_expired_wrong_issuer_and_wrong_type_are_rejected(tokens, cfg):
    from pathlib import Path

    from cryptography.hazmat.primitives import serialization

    private = serialization.load_pem_private_key(Path(cfg.jwt_private_key_path).read_bytes(), password=None)
    now = datetime.now(UTC)
    base = {"iss": ISSUER, "aud": AUDIENCE, "typ": "access", "sub": str(uuid.uuid4()), "sid": str(uuid.uuid4()),
            "aal": 1, "amr": ["pwd"], "iat": now, "nbf": now, "exp": now + timedelta(minutes=5), "jti": "x"}
    cases = {
        "expiré": {**base, "exp": now - timedelta(seconds=5)},
        "mauvais émetteur": {**base, "iss": "autre"},
        "mauvaise audience": {**base, "aud": "autre"},
        "mauvais type": {**base, "typ": "mfa_pending"},
    }
    for name, claims in cases.items():
        with pytest.raises(TokenError):
            tokens.decode_access(jwt.encode(claims, private, algorithm=ALGORITHM))
        assert name


def test_mfa_pending_token_cannot_be_used_as_access_token(tokens):
    pending, _ = tokens.issue_mfa_pending(uuid.uuid4(), uuid.uuid4(), "login")
    with pytest.raises(TokenError):
        tokens.decode_access(pending)
    access, _ = tokens.issue_access(uuid.uuid4(), uuid.uuid4(), 1, ["pwd"])
    with pytest.raises(TokenError):
        tokens.decode_mfa_pending(access)


def test_opaque_tokens_are_random_and_only_hash_is_comparable():
    a, b = new_opaque_token(), new_opaque_token()
    assert a != b and len(a) == 43
    assert hash_token(a) != a and len(hash_token(a)) == 64


# ---------------------------------------------------------------- CSRF
def test_csrf_is_bound_to_session():
    secret, sid = "k" * 40, uuid.uuid4()
    token = make_csrf(secret, sid)
    assert verify_csrf(secret, sid, token, token)
    assert not verify_csrf(secret, uuid.uuid4(), token, token)       # autre session
    assert not verify_csrf(secret, sid, token, token + "x")           # en-tête différent
    assert not verify_csrf(secret, sid, None, token)
    assert not verify_csrf("autre" * 8, sid, token, token)            # autre secret serveur
    forged = "abc.def"
    assert not verify_csrf(secret, sid, forged, forged)


# ---------------------------------------------------------------- TOTP
def test_totp_secret_encryption_is_bound_to_user(cfg):
    uid, other = uuid.uuid4(), uuid.uuid4()
    secret = totp.generate_secret()
    blob = totp.encrypt_secret(cfg, secret, uid)
    assert secret.encode() not in blob
    assert totp.decrypt_secret(cfg, blob, uid) == secret
    with pytest.raises(Exception):  # noqa: B017 - InvalidTag : blob copié vers un autre compte
        totp.decrypt_secret(cfg, blob, other)
    assert totp.encrypt_secret(cfg, secret, uid) != blob               # nonce aléatoire


def test_totp_accepts_window_and_rejects_replay():
    import pyotp

    secret = totp.generate_secret()
    gen = pyotp.TOTP(secret)
    now = time.time()
    code = gen.at(now)
    step = totp.verify_totp(secret, code, None, now)
    assert step == int(now // 30)
    assert totp.verify_totp(secret, code, step, now) is None                       # rejeu du même pas
    assert totp.verify_totp(secret, gen.at(now - 30), None, now) is not None        # dérive d'un pas
    assert totp.verify_totp(secret, gen.at(now - 90), None, now) is None            # trop ancien
    assert totp.verify_totp(secret, gen.at(now + 90), None, now) is None            # trop dans le futur
    assert totp.verify_totp(secret, "12345", None, now) is None
    assert totp.verify_totp(secret, "abcdef", None, now) is None


def test_recovery_codes_format_hash_and_normalization(cfg):
    codes = totp.generate_recovery_codes()
    assert len(codes) == len(set(codes)) == 10
    shown = totp.format_recovery_code(codes[0])
    assert totp.is_recovery_format(shown) and totp.is_recovery_format(shown.lower().replace("-", " "))
    assert not totp.is_recovery_format("123456")                    # un code TOTP n'est pas un code de secours
    assert totp.hash_recovery_code(cfg, shown) == totp.hash_recovery_code(cfg, codes[0])
    assert totp.hash_recovery_code(cfg, codes[0]) != totp.hash_recovery_code(cfg, codes[1])
    assert codes[0] not in totp.hash_recovery_code(cfg, codes[0])


# ---------------------------------------------------------------- appareils
def test_user_agent_parsing_is_coarse_and_stable():
    chrome_a = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/130.0 Safari/537.36"
    chrome_b = chrome_a.replace("130.0", "131.0")
    assert parse_user_agent(chrome_a) == ("Chrome", "macOS") == parse_user_agent(chrome_b)
    assert parse_user_agent("Mozilla/5.0 (iPhone; CPU iPhone OS 17) AppleWebKit Safari/605") == ("Safari", "iOS")
    assert parse_user_agent(None) == ("Inconnu", "Inconnu")
    assert fingerprint("c", "Chrome", "macOS") == fingerprint("c", "Chrome", "macOS")
    assert fingerprint("c", "Chrome", "macOS") != fingerprint("c", "Firefox", "macOS")


def test_sanitize_ip():
    assert sanitize_ip("203.0.113.9") == "203.0.113.9"
    assert sanitize_ip("2001:db8::1") == "2001:db8::1"
    assert sanitize_ip("testclient") is None and sanitize_ip("") is None and sanitize_ip(None) is None


# ---------------------------------------------------------------- limitation progressive
class FakeValkey:
    """Sous-ensemble de redis.Redis, avec une horloge manuelle."""

    def __init__(self):
        self.store: dict[str, tuple[str, float | None]] = {}
        self.now = 1000.0

    def _alive(self, key):
        item = self.store.get(key)
        if item and item[1] is not None and item[1] <= self.now:
            del self.store[key]
            return None
        return item

    def incr(self, key):
        item = self._alive(key)
        value = int(item[0]) + 1 if item else 1
        self.store[key] = (str(value), item[1] if item else None)
        return value

    def expire(self, key, seconds):
        item = self._alive(key)
        if item:
            self.store[key] = (item[0], self.now + seconds)

    def set(self, key, value, ex=None):
        self.store[key] = (value, self.now + ex if ex else None)

    def pttl(self, key):
        item = self._alive(key)
        if not item:
            return -2
        return -1 if item[1] is None else int((item[1] - self.now) * 1000)

    def delete(self, *keys):
        for key in keys:
            self.store.pop(key, None)

    def pipeline(self):
        outer = self

        class Pipe:
            def __init__(self):
                self.ops = []

            def incr(self, k):
                self.ops.append(("incr", k))

            def expire(self, k, s):
                self.ops.append(("expire", k, s))

            def execute(self):
                out = []
                for op in self.ops:
                    out.append(outer.incr(op[1]) if op[0] == "incr" else outer.expire(op[1], op[2]))
                return out

        return Pipe()


def test_throttle_delays_grow_then_cap_and_expire(cfg):
    fake = FakeValkey()
    throttle = ProgressiveThrottle(fake, cfg)
    buckets = [Bucket("pair", "x", free=3)]
    for _ in range(3):
        assert throttle.fail(buckets) == 0                      # échecs tolérés
    assert throttle.check(buckets) == (0, None)
    assert throttle.fail(buckets) == 1                          # 4e échec : 1 s
    assert throttle.check(buckets)[0] == 1
    fake.now += 2
    assert throttle.check(buckets) == (0, None)                 # le délai a expiré
    delays = [throttle.fail(buckets) for _ in range(12)]
    assert delays[:4] == [2, 4, 8, 16] and max(delays) == cfg.throttle_max_delay_seconds
    throttle.reset(buckets)
    assert throttle.check(buckets) == (0, None) and throttle.fail(buckets) == 0


def test_throttle_buckets_are_independent(cfg):
    fake = FakeValkey()
    throttle = ProgressiveThrottle(fake, cfg)
    mine = login_buckets(cfg, "victime@x.test", "10.0.0.1")
    attacker = login_buckets(cfg, "victime@x.test", "203.0.113.50")
    for _ in range(cfg.throttle_free_pair + 3):
        throttle.fail(attacker)
    assert throttle.check(attacker)[0] > 0
    # La victime, depuis SON adresse, n'est pas bloquée par l'attaquant (seuil par compte plus élevé)
    assert throttle.check(mine) == (0, None)
    # Une même IP qui essaie beaucoup de comptes différents finit par être ralentie (credential stuffing)
    for i in range(cfg.throttle_free_ip + 2):
        throttle.fail(login_buckets(cfg, f"user{i}@x.test", "198.51.100.7"))
    assert throttle.check(login_buckets(cfg, "nouveau@x.test", "198.51.100.7"))[1] == "ip"


def test_throttle_fails_closed_when_valkey_is_down(cfg):
    import redis

    class Down:
        def pttl(self, *_):
            raise redis.ConnectionError("down")

    with pytest.raises(AuthError) as exc:
        ProgressiveThrottle(Down(), cfg).check([Bucket("pair", "x", 3)])
    assert exc.value.status == 503
