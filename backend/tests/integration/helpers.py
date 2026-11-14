"""Utilitaires partagés des tests d'intégration HTTP."""
from __future__ import annotations

import time
from types import SimpleNamespace

import pyotp
from sqlalchemy import select

ORIGIN = "https://bank.localhost"
UA_MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/130.0 Safari/537.36"
UA_PHONE = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1 Safari/604.1"
ACCESS, REFRESH, CSRF, DEVICE, MFA = ("__Host-rlb_at", "__Secure-rlb_rt", "__Host-rlb_csrf", "__Host-rlb_did",
                                      "__Host-rlb_mfa")
DOMAIN = "demo.rl-express-bank.test"
CLIENT_PW, STAFF_PW = "Client!Demo2026", "Analyst!Demo2026"


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




def reset_accounts(*logins: str) -> None:
    """Remet des comptes de démonstration dans leur état initial (sans MFA, sans session) : les modules de
    test partagent la même base et chacun doit pouvoir activer le TOTP à sa façon."""
    from sqlalchemy import delete, text

    from app.core.database import get_session_factory
    from app.models import MFAConfiguration, RecoveryCode, User

    with get_session_factory()() as db:
        ids = [u for (u,) in db.execute(select(User.id).where(
            User.email.in_([f"{x}@{DOMAIN}" for x in logins])))]
        db.execute(delete(MFAConfiguration).where(MFAConfiguration.user_id.in_(ids)))
        db.execute(delete(RecoveryCode).where(RecoveryCode.user_id.in_(ids)))
        db.execute(text("UPDATE sessions SET status='REVOKED' WHERE user_id = ANY(:ids)"), {"ids": ids})
        db.execute(text("UPDATE users SET failed_login_count=0, locked_until=NULL WHERE id = ANY(:ids)"),
                   {"ids": ids})
        db.commit()
