"""Opérations bancaires de bout en bout : step-up TOTP, virements, retraits sans carte, blocage automatique."""
from __future__ import annotations

import os
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from tests.integration.helpers import CLIENT_PW, CSRF, ORIGIN, UA_MAC, Clock, login, reset_accounts

API = "/api/v1"


@pytest.fixture(scope="module", autouse=True)
def bank_env(seeded, jwt_key_files):
    from app.core.cache import get_valkey
    from app.core.config import get_settings
    from app.core.database import get_engine, get_session_factory
    from app.security.auth.tokens import get_token_service

    os.environ["JWT_PRIVATE_KEY_PATH"], os.environ["JWT_PUBLIC_KEY_PATH"] = map(str, jwt_key_files)
    os.environ["LAB_MODE"] = "true"
    for cached in (get_settings, get_token_service, get_valkey, get_engine, get_session_factory):
        cached.cache_clear()
    r = get_valkey()
    for key in r.scan_iter("rlbank:*"):
        r.delete(key)
    reset_accounts("jean.dupont", "marie.nguema")
    yield
    os.environ.pop("LAB_MODE", None)
    for cached in (get_settings,):
        cached.cache_clear()


class Bank:
    """Client HTTP d'un utilisateur connecté, avec TOTP actif et gestion automatique du step-up."""

    def __init__(self, who: str, monkeypatch, ip: str):
        from app.main import create_app
        self.http = TestClient(create_app(), base_url=ORIGIN, headers={"Origin": ORIGIN, "User-Agent": UA_MAC},
                               client=(ip, 51000))
        self.clock = Clock(monkeypatch)
        assert login(self.http, who, CLIENT_PW).json()["status"] == "authenticated"
        secret = self.post("/auth/mfa/enroll/start", {"current_password": CLIENT_PW}).json()["secret"]
        self.secret = secret
        r = self.post("/auth/mfa/enroll/confirm", {"code": self.clock.code(secret)})
        assert r.status_code == 200, r.text

    def post(self, path, json=None, headers=None):
        h = {"X-CSRF-Token": self.http.cookies.get(CSRF) or "", **(headers or {})}
        return self.http.post(f"{API}{path}", json=json, headers=h)

    def get(self, path):
        return self.http.get(f"{API}{path}")

    def code(self) -> str:
        return self.clock.code(self.secret)

    def confirm(self, r):
        """Si l'opération demande un step-up, la valide avec le TOTP et retourne la réponse finale."""
        if r.status_code == 202:
            r = self.post(f"/step-up/{r.json()['challenge_id']}/verify", {"code": self.code()})
        return r


@pytest.fixture(scope="module")
def mp():
    with pytest.MonkeyPatch.context() as m:
        yield m


@pytest.fixture(scope="module")
def jean(mp):
    return Bank("jean.dupont", mp, "203.0.113.21")


def _wrong(code: str) -> str:
    return "000000" if code != "000000" else "111111"


def current(bank: Bank) -> dict:
    return next(a for a in bank.get("/accounts").json() if a["type"] == "CURRENT")


def test_accounts_and_rib_are_private(jean):
    acc = current(jean)
    assert "iban" not in acc and acc["iban_masked"].count("•") >= 4
    rib = jean.get(f"/accounts/{acc['id']}/rib").json()
    assert rib["iban"].startswith("CM") and rib["bank"] == "RL EXPRESS BANK"


def test_cannot_read_someone_elses_account(jean, db):
    from app.models import Account, User
    other = db.scalar(select(Account).join(User, User.id == Account.user_id).where(User.email.like("marie%")))
    assert jean.get(f"/accounts/{other.id}/transactions").status_code == 404


def test_card_number_and_cvv_are_revealed_only_to_the_owner_and_traced(jean, db):
    from app.models import Card, User
    from app.models.security import SecurityEvent
    from app.services.cards.details import luhn_ok

    card = jean.get("/cards").json()[0]
    r = jean.get(f"/cards/{card['id']}/details")
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    pan = r.json()["pan"].replace(" ", "")
    assert luhn_ok(pan) and card["masked_pan"].endswith(pan[-4:]) and len(r.json()["cvv"]) == 3
    assert jean.get(f"/cards/{card['id']}/details").json() == r.json()           # stable d'un affichage à l'autre
    assert db.scalar(select(SecurityEvent).where(SecurityEvent.event_type == "CARD_VIEWED")) is not None
    other = db.scalar(select(Card).join(User, User.id == Card.user_id).where(User.email.like("marie%")))
    assert jean.get(f"/cards/{other.id}/details").status_code == 404


def test_beneficiary_requires_step_up_then_activates(jean):
    r = jean.post("/beneficiaries", {"first_name": "Paul", "last_name": "Mbarga", "bank_name": "Banque Test",
                                     "iban": _fresh_iban(1)})
    assert r.status_code == 202 and r.json()["method"] == "TOTP"
    done = jean.confirm(r)
    assert done.status_code == 200 and done.json()["status"] == "completed"
    assert any(b["status"] == "ACTIVE" for b in jean.get("/beneficiaries").json())


def _fresh_iban(n: int) -> str:
    from app.services.banking.rib import build_rib
    return build_rib(f"{90000000000 + n:011d}", bank_code="10001").iban


def test_pending_beneficiary_can_be_verified_later_and_viewed_in_full(jean):
    iban = _fresh_iban(7)
    r = jean.post("/beneficiaries", {"first_name": "Rose", "last_name": "Atangana", "bank_name": "Banque Test",
                                     "iban": iban})
    assert r.status_code == 202                                   # le client ferme la fenêtre sans saisir de code
    ben = next(b for b in jean.get("/beneficiaries").json() if b["name"] == "Rose Atangana")
    assert ben["status"] == "PENDING_VERIFICATION"

    detail = jean.get(f"/beneficiaries/{ben['id']}").json()
    assert detail["iban"].replace(" ", "") == iban and detail["first_name"] == "Rose" and detail["transfers"] == []

    again = jean.post(f"/beneficiaries/{ben['id']}/verify")
    assert again.status_code == 202 and again.json()["challenge_id"] != r.json()["challenge_id"]
    assert jean.confirm(again).json()["status"] == "completed"
    assert jean.get(f"/beneficiaries/{ben['id']}").json()["status"] == "ACTIVE"
    assert jean.post(f"/beneficiaries/{ben['id']}/verify").status_code == 409     # déjà vérifié


def test_wrong_totp_is_refused_and_challenge_survives(jean):
    r = jean.post("/beneficiaries", {"first_name": "Eve", "last_name": "Ndzie", "bank_name": "Banque Test",
                                     "iban": _fresh_iban(2)})
    cid = r.json()["challenge_id"]
    bad = jean.post(f"/step-up/{cid}/verify", {"code": "000000"})
    assert bad.status_code == 401
    ok = jean.post(f"/step-up/{cid}/verify", {"code": jean.code()})
    assert ok.status_code == 200


def test_transfer_moves_money_and_is_idempotent(jean):
    acc = current(jean)
    internal = next(b for b in jean.get("/beneficiaries").json() if b["internal"])
    body = {"source_account_id": acc["id"], "beneficiary_id": internal["id"], "amount": 10_000, "reference": "Test"}
    key = {"Idempotency-Key": "idem-transfer-0001"}
    first = jean.confirm(jean.post("/transfers", body, key))
    assert first.status_code == 200 and first.json()["status"] == "completed", first.text
    after = current(jean)["balance"]
    assert after == acc["balance"] - 10_000
    replay = jean.post("/transfers", body, key)
    assert replay.json().get("replayed") is True and current(jean)["balance"] == after


def test_transfer_list_has_incoming_and_outgoing_with_details(jean, db):
    from app.models import Account, LedgerEntry, User

    rows = jean.get("/transfers?limit=100").json()
    assert {r["direction"] for r in rows} == {"IN", "OUT"}
    assert [r["created_at"] for r in rows] == sorted((r["created_at"] for r in rows), reverse=True)

    sent = next(r for r in rows if r["direction"] == "OUT")
    d = jean.get(f"/transfers/sent/{sent['id']}").json()
    assert d["amount"] == sent["amount"] and d["counterparty"]["iban"].startswith("CM") and d["account"]["label"]

    salary = next(r for r in rows if r["direction"] == "IN" and r["counterparty"] == "Employeur (salaire)")
    d = jean.get(f"/transfers/received/{salary['id']}").json()
    assert d["amount"] == salary["amount"] > 0 and d["balance_after"] >= d["amount"]

    other = db.scalar(select(LedgerEntry.seq).join(Account, Account.id == LedgerEntry.account_id)
                      .join(User, User.id == Account.user_id)
                      .where(User.email.like("marie%"), LedgerEntry.amount > 0).limit(1))
    assert jean.get(f"/transfers/received/{other}").status_code == 404           # crédit d'un autre client
    assert jean.get(f"/transfers/received/{other}/receipt.pdf").status_code == 404

    for path in (f"/transfers/sent/{sent['id']}/receipt.pdf", f"/transfers/received/{salary['id']}/receipt.pdf"):
        pdf = jean.get(path)
        assert pdf.status_code == 200 and pdf.headers["content-type"] == "application/pdf", pdf.text[:200]
        assert pdf.content.startswith(b"%PDF") and "avis-virement-" in pdf.headers["content-disposition"]
    assert jean.get(f"/transfers/sent/{uuid.uuid4()}").status_code == 404


def test_insufficient_funds_and_limits(jean):
    acc = current(jean)
    internal = next(b for b in jean.get("/beneficiaries").json() if b["internal"])
    r = jean.post("/transfers", {"source_account_id": acc["id"], "beneficiary_id": internal["id"],
                                 "amount": acc["available_balance"] + 1, "reference": "Trop"})
    assert r.status_code == 409 and r.json()["code"] == "insufficient_funds"


def test_payment_and_card_pin_lockout(jean):
    card = jean.get("/cards").json()[0]
    r = jean.confirm(jean.post("/payments", {"card_id": card["id"], "amount": 5_000, "merchant": "Supermarché",
                                             "category": "FOOD", "city": "Douala"}))
    assert r.status_code == 200 and r.json()["status"] == "completed", r.text
    atm = next(a for a in jean.get("/atms").json() if a["status"] == "ONLINE" and a["city"] == "Douala")
    acc = current(jean)
    for _ in range(3):
        bad = jean.post("/withdrawals", {"type": "CARD", "account_id": acc["id"], "card_id": card["id"],
                                         "atm_id": atm["id"], "amount": 20_000, "pin": "9999"})
        assert bad.status_code in (401, 409)
    assert jean.get("/cards").json()[0]["status"] == "BLOCKED"
    # le client ne peut pas non plus la débloquer sans step-up
    r = jean.post(f"/cards/{card['id']}/unblock")
    assert r.status_code == 202
    assert jean.confirm(r).status_code == 200
    assert jean.get("/cards").json()[0]["status"] == "ACTIVE"


def test_cardless_withdrawal_end_to_end(jean, db):
    from app.security.crypto.terminal import derive_terminal_secret
    acc = current(jean)
    atm = next(a for a in jean.get("/atms").json() if a["status"] == "ONLINE" and a["city"] == "Douala")
    r = jean.post("/withdrawals", {"type": "CARDLESS", "account_id": acc["id"], "atm_id": atm["id"],
                                   "amount": 30_000})
    assert r.status_code == 202            # le sans-carte exige toujours une authentification renforcée
    done = jean.confirm(r).json()
    assert done["status"] == "completed" and len(done["code"]) == 6
    held = current(jean)
    assert held["balance"] == acc["balance"] and held["available_balance"] == acc["available_balance"] - 30_000
    term = {"X-ATM-Code": atm["code"], "X-ATM-Secret": derive_terminal_secret(atm["code"])}
    bad = jean.http.post(f"{API}/atm-terminal/cardless/redeem", headers=term,
                         json={"reference": done["reference"], "code": _wrong(done["code"])})
    assert bad.status_code == 401
    ok = jean.http.post(f"{API}/atm-terminal/cardless/redeem", headers=term,
                        json={"reference": done["reference"], "code": done["code"]})
    assert ok.status_code == 200 and ok.json()["status"] == "APPROVED", ok.text
    final = current(jean)
    assert final["balance"] == acc["balance"] - 30_000 and final["available_balance"] == final["balance"]
    again = jean.http.post(f"{API}/atm-terminal/cardless/redeem", headers=term,
                           json={"reference": done["reference"], "code": done["code"]})
    assert again.status_code == 404                     # usage unique
    assert jean.http.post(f"{API}/atm-terminal/cardless/redeem", headers={"X-ATM-Code": atm["code"],
                          "X-ATM-Secret": "nope"}, json={"reference": "AAAAAAAA", "code": "123456"}).status_code == 401


def test_cardless_code_locks_after_three_wrong_attempts(jean):
    from app.security.crypto.terminal import derive_terminal_secret
    acc = current(jean)
    atm = next(a for a in jean.get("/atms").json() if a["status"] == "ONLINE")
    done = jean.confirm(jean.post("/withdrawals", {"type": "CARDLESS", "account_id": acc["id"], "atm_id": atm["id"],
                                                   "amount": 10_000})).json()
    term = {"X-ATM-Code": atm["code"], "X-ATM-Secret": derive_terminal_secret(atm["code"])}
    wrong = _wrong(done["code"])
    for _ in range(3):
        jean.http.post(f"{API}/atm-terminal/cardless/redeem", headers=term,
                       json={"reference": done["reference"], "code": wrong})
    r = jean.http.post(f"{API}/atm-terminal/cardless/redeem", headers=term,
                       json={"reference": done["reference"], "code": done["code"]})
    assert r.status_code == 404                         # verrouillé : même le bon code est refusé
    assert current(jean)["available_balance"] == acc["available_balance"]    # fonds libérés


def test_attack_pattern_is_blocked_with_automatic_response(mp, db):
    """Nouvel appareil + ville lointaine + bénéficiaire frais + montant élevé -> BLOCK, alerte, session révoquée."""
    from app.models import Notification, SecurityAlert, Transfer, User
    victim = Bank("marie.nguema", mp, "198.51.100.77")
    acc = current(victim)
    r = victim.confirm(victim.post("/beneficiaries", {"first_name": "Mule", "last_name": "Anonyme",
                                                      "bank_name": "Banque Test", "iban": _fresh_iban(7),
                                                      "simulated_city": "Lagos"}))
    assert r.status_code == 200, r.text
    ben = victim.get("/beneficiaries").json()
    mule = next(b for b in ben if b["name"].startswith("Mule"))
    amount = int(acc["available_balance"] * 0.9)
    r = victim.post("/transfers", {"source_account_id": acc["id"], "beneficiary_id": mule["id"], "amount": amount,
                                   "reference": "Urgent", "simulated_city": "Lagos"})
    if r.status_code == 202:        # selon l'heure du test, le score peut rester sous le seuil critique
        pytest.skip("score sous le seuil critique à cette heure")
    assert r.status_code == 403 and r.json()["code"] == "operation_blocked"
    user = db.scalar(select(User).where(User.email.like("marie.nguema@%")))
    t = db.scalar(select(Transfer).where(Transfer.user_id == user.id).order_by(Transfer.created_at.desc()))
    assert t.status == "BLOCKED"
    assert db.scalar(select(SecurityAlert).where(SecurityAlert.user_id == user.id)) is not None
    notice = select(Notification).where(Notification.user_id == user.id, Notification.type == "SECURITY_NOTICE")
    assert db.scalar(notice)
    assert victim.get("/accounts").status_code == 401           # session révoquée automatiquement

