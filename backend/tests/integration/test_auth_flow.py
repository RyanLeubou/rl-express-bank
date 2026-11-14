"""Authentification de bout en bout : vrai PostgreSQL, vrai Valkey, vraie pile HTTP (TestClient).

Les scénarios reprennent les menaces visées : mots de passe devinés, rejeu de code TOTP, vol de jeton de
rafraîchissement, CSRF, énumération de comptes, force brute du second facteur.
"""
from __future__ import annotations

import hashlib
import os
import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text

ORIGIN = "https://bank.localhost"
UA_MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/130.0 Safari/537.36"
UA_PHONE = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1 Safari/604.1"
ACCESS, REFRESH, CSRF, DEVICE, MFA = ("__Host-rlb_at", "__Secure-rlb_rt", "__Host-rlb_csrf", "__Host-rlb_did",
                                      "__Host-rlb_mfa")
DOMAIN = "demo.rl-express-bank.test"
CLIENT_PW, STAFF_PW = "Client!Demo2026", "Analyst!Demo2026"


@pytest.fixture(scope="module", autouse=True)
def auth_env(seeded, jwt_key_files):
    from app.core.cache import get_valkey
    from app.core.config import get_settings
    from app.core.database import get_engine, get_session_factory
    from app.security.auth.tokens import get_token_service

    os.environ["JWT_PRIVATE_KEY_PATH"], os.environ["JWT_PUBLIC_KEY_PATH"] = map(str, jwt_key_files)
    for cached in (get_settings, get_token_service, get_valkey, get_engine, get_session_factory):
        cached.cache_clear()
    yield


@pytest.fixture(autouse=True)
def clean_throttle():
    from app.core.cache import get_valkey

    def wipe():
        r = get_valkey()
        for pattern in ("rlbank:thr:*", "rlbank:mfa:*"):
            for key in r.scan_iter(pattern):
                r.delete(key)
    wipe()
    yield
    wipe()


@pytest.fixture(scope="module")
def new_client():
    from app.main import create_app

    app = create_app()

    def _make(ua: str = UA_MAC, ip: str = "203.0.113.10") -> TestClient:
        return TestClient(app, base_url=ORIGIN, headers={"Origin": ORIGIN, "User-Agent": ua}, client=(ip, 50000))
    return _make


def login(client, who="jean.dupont", password=CLIENT_PW, domain=DOMAIN):
    return client.post("/api/v1/auth/login", json={"email": f"{who}@{domain}", "password": password})


def post(client, path, json=None):
    return client.post(f"/api/v1/auth{path}", json=json, headers={"X-CSRF-Token": client.cookies.get(CSRF) or ""})


def events(db, user_email=None, event_type=None, limit=50):
    from app.models.identity import User
    from app.models.security import SecurityEvent

    stmt = select(SecurityEvent).order_by(SecurityEvent.seq.desc()).limit(limit)
    if user_email:
        stmt = stmt.where(SecurityEvent.user_id == select(User.id).where(User.email == user_email).scalar_subquery())
    if event_type:
        stmt = stmt.where(SecurityEvent.event_type == event_type)
    return list(db.scalars(stmt))


class Clock:
    """Horloge TOTP pilotable : chaque code généré tombe sur un nouveau pas de 30 s."""

    def __init__(self, monkeypatch):
        from app.security.mfa import totp

        self.t = time.time()
        monkeypatch.setattr(totp, "time", SimpleNamespace(time=lambda: self.t))

    def code(self, secret: str) -> str:
        self.t += 60
        return pyotp.TOTP(secret).at(self.t)


def enroll_staff(client, who, clock):
    """Première connexion du personnel : activation obligatoire du TOTP. Retourne (secret, codes de secours)."""
    r = login(client, who, STAFF_PW)
    assert r.json()["status"] == "mfa_enrollment_required"
    secret = post(client, "/mfa/enroll/start", {}).json()["secret"]
    r = post(client, "/mfa/enroll/confirm", {"code": clock.code(secret)})
    assert r.status_code == 200 and r.json()["status"] == "authenticated", r.text
    return secret, r.json()["recovery_codes"]


@pytest.fixture(scope="module")
def analyste1(seeded, new_client):
    clock_holder = pytest.MonkeyPatch()
    clock = Clock(clock_holder)
    client = new_client()
    secret, codes = enroll_staff(client, "analyste1", clock)
    yield SimpleNamespace(secret=secret, codes=codes, clock=clock)
    clock_holder.undo()


# ================================================================== client : mot de passe
def test_customer_login_sets_hardened_cookies_and_no_token_in_body(new_client, db):
    c = new_client()
    r = login(c)
    assert r.status_code == 200 and r.json()["status"] == "authenticated"
    body = r.text.lower()
    assert "eyj" not in body and "access" not in body and "refresh" not in body        # aucun jeton dans le JSON
    assert r.headers["cache-control"] == "no-store"
    cookies = {h.split("=")[0]: h for h in r.headers.get_list("set-cookie")}
    for name in (ACCESS, REFRESH, DEVICE):
        flags = cookies[name].lower()
        assert "httponly" in flags and "secure" in flags and "samesite=strict" in flags
    assert "httponly" not in cookies[CSRF].lower() and "secure" in cookies[CSRF].lower()
    assert "path=/api/v1/auth" in cookies[REFRESH].lower()                  # le refresh ne circule que vers /auth
    assert "path=/;" in cookies[ACCESS].lower() or cookies[ACCESS].lower().rstrip().endswith("path=/")
    me = c.get("/api/v1/auth/me").json()
    assert me["user"]["email"] == f"jean.dupont@{DOMAIN}" and me["aal"] == 1 and me["amr"] == ["pwd"]
    assert "session:read:own" in me["user"]["permissions"]


def test_new_device_is_detected_once(new_client, db):
    c = new_client(UA_PHONE)
    first = login(c).json()
    assert first["new_device"] is True
    assert {e.event_type for e in events(db, f"jean.dupont@{DOMAIN}", limit=10)} >= {"USER_LOGIN", "NEW_DEVICE_LOGIN"}
    post(c, "/logout")
    again = login(c).json()                    # même navigateur, cookie d'appareil conservé
    assert again["new_device"] is False


def test_wrong_password_and_unknown_account_are_indistinguishable(new_client, db):
    c = new_client()
    bad_pw = login(c, "jean.dupont", "Mauvais!Pass2026")
    ghost = login(c, "fantome", "Mauvais!Pass2026")
    assert bad_pw.status_code == ghost.status_code == 401
    strip = lambda r: {k: v for k, v in r.json().items() if k != "request_id"}  # noqa: E731
    assert strip(bad_pw) == strip(ghost)
    reasons = {e.metadata_.get("reason") for e in events(db, event_type="LOGIN_FAILED", limit=5)}
    assert {"bad_password", "unknown_account"} <= reasons               # le détail n'existe que côté SOC
    dump = " ".join(str(e.metadata_) for e in events(db, event_type="LOGIN_FAILED", limit=5))
    assert "Mauvais!Pass2026" not in dump                                # jamais de mot de passe dans les journaux


def test_password_guessing_is_slowed_down_even_with_the_right_password(new_client, db):
    c = new_client()
    for _ in range(3):
        assert login(c, "grace.eyenga", "Faux!Pass2026").status_code == 401
    assert login(c, "grace.eyenga", "Faux!Pass2026").status_code == 401            # 4e échec : délai imposé
    blocked = login(c, "grace.eyenga", CLIENT_PW)                                    # bon mot de passe, trop tôt
    assert blocked.status_code == 429 and int(blocked.headers["retry-after"]) >= 1
    assert any(e.metadata_.get("reason") == "throttled" for e in events(db, event_type="LOGIN_FAILED", limit=5))
    # L'attaquant ne bloque pas la victime qui se connecte depuis une autre adresse : portée « paire compte+IP »
    victim = new_client(ip="198.51.100.77")
    assert login(victim, "grace.eyenga", CLIENT_PW).status_code == 200


def test_disabled_and_locked_accounts_get_the_generic_error(new_client, db):
    from app.core.database import get_session_factory
    from app.models.enums import UserStatus
    from app.models.identity import User
    from app.security.auth.passwords import hash_secret

    with get_session_factory()() as s:
        for name, status, lock in (("desactive", UserStatus.DISABLED, None),
                                   ("verrouille", UserStatus.ACTIVE, datetime.now(UTC) + timedelta(hours=1))):
            s.add(User(email=f"{name}@{DOMAIN}", password_hash=hash_secret("Test!Pass2026x"), first_name="T",
                       last_name=name, user_type="CUSTOMER", status=status, locked_until=lock))
        s.commit()
    c = new_client()
    for name in ("desactive", "verrouille"):
        r = login(c, name, "Test!Pass2026x")                          # mot de passe CORRECT
        assert r.status_code == 401 and r.json()["code"] == "invalid_credentials"
    reasons = {e.metadata_.get("reason") for e in events(db, event_type="LOGIN_FAILED", limit=6)}
    assert {"account_inactive", "account_locked"} <= reasons


# ================================================================== CSRF, origine, jetons
def test_state_changing_calls_need_csrf_token_and_trusted_origin(new_client):
    c = new_client()
    login(c, "paul.mbarga")
    assert c.post("/api/v1/auth/logout").status_code == 403                              # pas d'en-tête
    assert c.post("/api/v1/auth/logout", headers={"X-CSRF-Token": "x.y"}).status_code == 403
    evil_headers = {"Origin": "https://evil.test", "X-CSRF-Token": c.cookies.get(CSRF)}
    evil = c.post("/api/v1/auth/logout", headers=evil_headers)
    assert evil.status_code == 403 and evil.json()["code"] == "origin_not_allowed"
    assert login(new_client(), "paul.mbarga").status_code == 200
    assert post(c, "/logout").status_code == 204
    assert c.get("/api/v1/auth/me").status_code == 401                                   # cookies effacés


def test_login_from_foreign_origin_is_refused(new_client):
    c = new_client()
    r = c.post("/api/v1/auth/login", json={"email": f"jean.dupont@{DOMAIN}", "password": CLIENT_PW},
               headers={"Origin": "https://evil.test"})
    assert r.status_code == 403
    r = c.post("/api/v1/auth/login", json={"email": f"jean.dupont@{DOMAIN}", "password": CLIENT_PW},
               headers={"Sec-Fetch-Site": "cross-site", "Origin": ""})
    assert r.status_code == 403


def test_forged_and_missing_access_cookies_are_rejected(new_client):
    c = new_client()
    assert c.get("/api/v1/auth/me").status_code == 401
    c.cookies.set(ACCESS, "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.", domain="bank.localhost")
    assert c.get("/api/v1/auth/me").status_code == 401


def test_strict_input_validation(new_client):
    c = new_client()
    assert c.post("/api/v1/auth/login", json={"email": "a@b.test", "password": "x", "admin": True}).status_code == 422
    assert c.post("/api/v1/auth/login", json={"email": "a@b.test", "password": "x" * 300}).status_code == 422
    r = c.post("/api/v1/auth/login", content=b"{pas du json", headers={"Content-Type": "application/json"})
    assert r.status_code == 422 and "x" * 5 not in r.text


# ================================================================== rafraîchissement
def test_refresh_rotates_and_token_reuse_revokes_the_whole_family(new_client, db):
    from app.core.database import get_session_factory

    c = new_client()
    login(c, "samuel.tchoupo")
    old_refresh = c.cookies.get(REFRESH)
    old_access = c.cookies.get(ACCESS)
    r = c.post("/api/v1/auth/refresh")
    assert r.status_code == 200 and c.cookies.get(REFRESH) != old_refresh and c.cookies.get(ACCESS) != old_access
    assert c.get("/api/v1/auth/me").status_code == 200

    thief = new_client()
    thief.cookies.set(REFRESH, old_refresh, domain="bank.localhost", path="/api/v1/auth")
    race = thief.post("/api/v1/auth/refresh")                     # rejeu immédiat : toléré (course entre onglets)
    assert race.status_code == 401 and race.json()["code"] == "refresh_race"
    assert c.get("/api/v1/auth/me").status_code == 200            # la vraie session n'est pas touchée

    with get_session_factory()() as s:                            # on vieillit la rotation au-delà de la tolérance
        s.execute(text("UPDATE sessions SET revoked_at = now() - interval '5 minutes' "
                       "WHERE refresh_token_hash = :h"), {"h": hashlib.sha256(old_refresh.encode()).hexdigest()})
        s.commit()
    replay = thief.post("/api/v1/auth/refresh")
    assert replay.status_code == 401 and replay.json()["code"] == "session_revoked"
    assert c.get("/api/v1/auth/me").status_code == 401            # la victime est déconnectée par précaution
    assert c.post("/api/v1/auth/refresh").status_code == 401      # même son nouveau refresh est mort
    reuse = [e for e in events(db, f"samuel.tchoupo@{DOMAIN}", "SESSION_REVOKED") if
             e.metadata_.get("reason") == "refresh_token_reuse"]
    assert reuse and str(reuse[0].severity) == "HIGH"


def test_refresh_without_cookie_is_rejected(new_client):
    r = new_client().post("/api/v1/auth/refresh")
    assert r.status_code == 401 and r.json()["code"] == "not_authenticated"


# ================================================================== sessions
def test_user_can_list_and_revoke_own_sessions(new_client):
    a, b = new_client(), new_client(UA_PHONE)
    login(a, "marie.nguema")
    login(b, "marie.nguema")
    listing = a.get("/api/v1/auth/sessions").json()
    assert len(listing) >= 2 and sum(1 for s in listing if s["current"]) == 1
    other = next(s for s in listing if not s["current"])
    assert b.get("/api/v1/auth/me").status_code == 200
    # Révoquer une session qui n'est pas la mienne est impossible (404, pas 403 : on ne confirme rien)
    stranger = new_client()
    login(stranger, "ibrahim.moussa")
    assert post(stranger, f"/sessions/{other['id']}").status_code in (404, 405)
    assert stranger.delete(f"/api/v1/auth/sessions/{other['id']}",
                           headers={"X-CSRF-Token": stranger.cookies.get(CSRF)}).status_code == 404
    assert a.delete(f"/api/v1/auth/sessions/{other['id']}", headers={"X-CSRF-Token": a.cookies.get(CSRF)}
                    ).status_code == 204


# ================================================================== personnel : MFA obligatoire
def test_staff_first_login_forces_totp_enrollment(new_client, db, monkeypatch):
    from app.models.auth import MFAConfiguration
    from app.models.identity import User

    clock = Clock(monkeypatch)
    c = new_client()
    r = login(c, "admin", "Admin!Demo2026")
    assert r.json()["status"] == "mfa_enrollment_required"
    assert ACCESS not in c.cookies and c.get("/api/v1/auth/me").status_code == 401         # aucune session sans MFA
    secret = post(c, "/mfa/enroll/start", {}).json()["secret"]
    assert post(c, "/mfa/enroll/confirm", {"code": "000000"}).status_code == 401
    ok = post(c, "/mfa/enroll/confirm", {"code": clock.code(secret)})
    assert ok.status_code == 200 and len(ok.json()["recovery_codes"]) == 10
    me = c.get("/api/v1/auth/me").json()
    assert me["aal"] == 2 and me["amr"] == ["pwd", "otp"] and me["user"]["mfa_enabled"] is True
    uid = db.scalar(select(User.id).where(User.email == f"admin@{DOMAIN}"))
    cfg = db.scalar(select(MFAConfiguration).where(MFAConfiguration.user_id == uid))
    assert cfg.enabled and secret.encode() not in cfg.totp_secret_encrypted          # secret chiffré au repos
    from app.events.audit import verify_audit_chain
    assert verify_audit_chain(db).valid                                                # chaîne d'audit intacte


def test_staff_login_requires_a_valid_second_factor(new_client, analyste1, db):
    c = new_client()
    r = login(c, "analyste1", STAFF_PW)
    assert r.json()["status"] == "mfa_required" and ACCESS not in c.cookies
    wrong = post(c, "/mfa/verify", {"code": "123456"})
    assert wrong.status_code == 401 and wrong.json()["code"] == "invalid_code"
    good = post(c, "/mfa/verify", {"code": analyste1.clock.code(analyste1.secret)})
    assert good.status_code == 200
    assert c.get("/api/v1/auth/me").json()["aal"] == 2
    assert {"MFA_FAILURE", "MFA_SUCCESS"} <= {e.event_type for e in events(db, f"analyste1@{DOMAIN}", limit=12)}


def test_totp_code_cannot_be_replayed(new_client, analyste1):
    c1, c2 = new_client(), new_client()
    login(c1, "analyste1", STAFF_PW)
    login(c2, "analyste1", STAFF_PW)
    code = analyste1.clock.code(analyste1.secret)
    assert post(c1, "/mfa/verify", {"code": code}).status_code == 200
    replay = post(c2, "/mfa/verify", {"code": code})                    # même code, même pas de temps
    assert replay.status_code in (401, 429)
    assert c2.get("/api/v1/auth/me").status_code == 401


def test_recovery_code_works_once(new_client, analyste1, db):
    code = analyste1.codes[0]
    c = new_client()
    login(c, "analyste1", STAFF_PW)
    r = post(c, "/mfa/verify", {"code": code})
    assert r.status_code == 200 and r.json()["recovery_codes_left"] == 9
    c2 = new_client()
    login(c2, "analyste1", STAFF_PW)
    assert post(c2, "/mfa/verify", {"code": code.lower()}).status_code == 401           # usage unique
    assert any(e.event_type == "RECOVERY_CODE_USED" for e in events(db, f"analyste1@{DOMAIN}", limit=15))
    # Un code de secours ne peut pas servir à « faire confiance » à un appareil
    c3 = new_client()
    login(c3, "analyste1", STAFF_PW)
    assert post(c3, "/mfa/verify", {"code": analyste1.codes[1], "trust_device": True}).status_code == 200
    assert c3.get("/api/v1/auth/me").json()["device_trusted"] is False


def test_second_factor_brute_force_is_throttled(new_client, analyste1, db):
    c = new_client()
    login(c, "analyste1", STAFF_PW)
    statuses = [post(c, "/mfa/verify", {"code": f"{i:06d}"}).status_code for i in (111111, 222222, 333333, 444444)]
    assert statuses[:3] == [401, 401, 401] and statuses[3] == 401
    after = post(c, "/mfa/verify", {"code": analyste1.clock.code(analyste1.secret)})
    assert after.status_code in (429, 401)          # même le bon code est refusé pendant le délai
    assert after.status_code != 200


def test_challenge_cookie_is_single_purpose(new_client, analyste1):
    c = new_client()
    login(c, "analyste1", STAFF_PW)                                         # défi « login »
    assert post(c, "/mfa/enroll/start", {}).status_code in (401, 409)       # inutilisable pour une activation
    assert post(new_client(), "/mfa/verify", {"code": "123456"}).status_code == 401   # pas de défi du tout


# ================================================================== client : MFA volontaire + appareil de confiance
def test_customer_mfa_and_trusted_device_flow(new_client, db, monkeypatch):
    clock = Clock(monkeypatch)
    laptop = new_client()
    login(laptop, "fatima.bello")
    assert post(laptop, "/mfa/enroll/start", {}).status_code == 401                              # mot de passe exigé
    assert post(laptop, "/mfa/enroll/start", {"current_password": "Faux!Pass2026"}).status_code == 401
    secret = post(laptop, "/mfa/enroll/start", {"current_password": CLIENT_PW}).json()["secret"]
    done = post(laptop, "/mfa/enroll/confirm", {"code": clock.code(secret)})
    assert done.json()["status"] == "mfa_enabled" and len(done.json()["recovery_codes"]) == 10
    assert post(laptop, "/mfa/enroll/start", {"current_password": CLIENT_PW}).status_code == 409   # déjà actif

    phone = new_client(UA_PHONE)                         # appareil inconnu : second facteur exigé
    assert login(phone, "fatima.bello").json()["status"] == "mfa_required"
    assert post(phone, "/mfa/verify", {"code": clock.code(secret), "trust_device": True}).status_code == 200
    assert phone.get("/api/v1/auth/me").json()["device_trusted"] is True
    post(phone, "/logout")
    again = login(phone, "fatima.bello").json()          # appareil de confiance : mot de passe suffisant
    assert again["status"] == "authenticated"
    assert phone.get("/api/v1/auth/me").json()["aal"] == 1        # niveau 1 : step-up aux opérations sensibles
    intruder = new_client(UA_PHONE)                      # même navigateur mais SANS le cookie d'appareil
    assert login(intruder, "fatima.bello").json()["status"] == "mfa_required"


def test_rbac_dependency_refuses_missing_permission():
    from app.security.auth.deps import require_permission
    from app.security.auth.errors import AuthError

    check = require_permission("alert:update:any")
    ctx = SimpleNamespace(permissions={"session:read:own"})
    with pytest.raises(AuthError) as exc:
        check(ctx)
    assert exc.value.status == 403
    assert check(SimpleNamespace(permissions={"alert:update:any"})).permissions


# ================================================================== ouverture de compte en ligne
FORM = {"first_name": "Aïcha", "last_name": "Ngono", "address": "12 rue des Manguiers, Bastos", "city": "Mbalmayo",
        "phone": "+237 690 00 00 00", "profession": "Infirmière", "password": "Nouveau!Client2026"}


def test_new_customer_gets_current_account_rib_and_card_then_opens_savings(new_client, db):
    import uuid

    from app.models.banking import Account
    from app.models.cards import Card
    from app.models.identity import User
    from app.security.auth.passwords import verify_secret
    from app.services.banking.rib import iban_is_valid

    email = f"nouveau.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    c = new_client(ip="203.0.113.77")
    r = c.post("/api/v1/auth/register", json={**FORM, "email": email})
    assert r.status_code == 201 and r.json()["status"] == "authenticated", r.text
    body = r.json()
    assert body["user"]["roles"] == ["CLIENT"] and body["agency"] == "Yaoundé" and body["branch_code"] == "00201"
    assert iban_is_valid(body["iban"]) and len(body["card_pin"]) == 4
    assert c.get("/api/v1/auth/me").status_code == 200

    user = db.scalar(select(User).where(User.email == email))
    assert (user.profession, user.city, user.address) == ("Infirmière", "Mbalmayo", FORM["address"])
    [account] = db.scalars(select(Account).where(Account.user_id == user.id))
    assert (account.account_type, account.balance, account.branch_code) == ("CURRENT", 0, "00201")
    [card] = db.scalars(select(Card).where(Card.user_id == user.id))
    assert card.account_id == account.id and card.status == "ACTIVE" and card.holder_name == "AÏCHA NGONO"
    assert verify_secret(card.pin_hash, body["card_pin"]) and body["card_pin"] not in card.pin_hash
    assert events(db, email, "USER_REGISTERED")

    csrf = {"X-CSRF-Token": c.cookies.get(CSRF)}
    r = c.post("/api/v1/accounts/savings", headers=csrf)
    assert r.status_code == 201 and r.json()["type"] == "SAVINGS" and r.json()["balance"] == 0, r.text
    assert c.post("/api/v1/accounts/savings", headers=csrf).status_code == 409          # un seul livret
    assert sorted(a["type"] for a in c.get("/api/v1/accounts").json()) == ["CURRENT", "SAVINGS"]
    savings = db.scalar(select(Account).where(Account.user_id == user.id, Account.account_type == "SAVINGS"))
    assert savings.branch_code == "00201" and savings.label == "Livret épargne"
    assert events(db, email, "ACCOUNT_OPENED")

    again = new_client(ip="203.0.113.78").post("/api/v1/auth/register", json={**FORM, "email": email})
    assert again.status_code == 409


def test_registration_refuses_weak_passwords_unknown_cities_and_staff_fields(new_client):
    c = new_client(ip="203.0.113.79")
    base = {**FORM, "email": f"faible@{DOMAIN}"}
    assert c.post("/api/v1/auth/register", json={**base, "password": "court"}).status_code == 422
    r = c.post("/api/v1/auth/register", json={**base, "password": "toutenminuscule123"})
    assert r.status_code == 422 and r.json()["type"].endswith("/weak_password")
    r = c.post("/api/v1/auth/register", json={**base, "city": "Paris"})
    assert r.status_code == 422 and r.json()["type"].endswith("/unknown_city")
    assert c.post("/api/v1/auth/register", json={**base, "account_type": "SAVINGS"}).status_code == 422
    assert c.post("/api/v1/auth/register", json={**base, "user_type": "STAFF"}).status_code == 422


def test_registration_city_list_maps_each_city_to_an_agency(new_client):
    cities = {row["city"]: row for row in new_client().get("/api/v1/auth/register/cities").json()}
    assert cities["Limbé"]["agency"] == "Douala" and cities["Bamenda"]["branch_code"] == "00401"
