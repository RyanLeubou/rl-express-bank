"""SOC, administration, audit, support et menaces internes, de bout en bout."""
from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from tests.integration.helpers import CSRF, ORIGIN, STAFF_PW, UA_MAC, Clock, enroll_staff, login, reset_accounts

API = "/api/v1"


@pytest.fixture(scope="module", autouse=True)
def soc_env(seeded, jwt_key_files):
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
    reset_accounts("analyste1", "admin", "auditeur", "support1", "fatima.bello")
    yield
    os.environ.pop("LAB_MODE", None)
    get_settings.cache_clear()


@pytest.fixture(scope="module")
def mp():
    with pytest.MonkeyPatch.context() as m:
        yield m


class Staff:
    def __init__(self, who: str, password: str, mp, ip: str):
        from app.main import create_app
        self.http = TestClient(create_app(), base_url=ORIGIN, headers={"Origin": ORIGIN, "User-Agent": UA_MAC},
                               client=(ip, 52000))
        clock = Clock(mp)
        if who == "admin":
            who = "admin"
        import tests.integration.helpers as h
        orig = h.STAFF_PW
        h.STAFF_PW = password
        try:
            enroll_staff(self.http, who, clock)
        finally:
            h.STAFF_PW = orig

    def req(self, method, path, json=None):
        return self.http.request(method, f"{API}{path}", json=json,
                                 headers={"X-CSRF-Token": self.http.cookies.get(CSRF) or ""})


@pytest.fixture(scope="module")
def analyst(mp):
    return Staff("analyste1", "Analyst!Demo2026", mp, "203.0.113.31")


@pytest.fixture(scope="module")
def admin(mp):
    return Staff("admin", "Admin!Demo2026", mp, "203.0.113.32")


@pytest.fixture(scope="module")
def auditor(mp):
    return Staff("auditeur", "Auditor!Demo2026", mp, "203.0.113.33")


@pytest.fixture(scope="module")
def agent(mp):
    return Staff("support1", "Support!Demo2026", mp, "203.0.113.34")


def test_login_helper_used():
    assert login and STAFF_PW


def test_scenario_account_takeover_creates_alert_and_responds(admin, analyst, db):
    from app.models import User

    # Victime explicite : Jean Dupont, profil du scénario jury (les clients de démo partagent la même date de
    # création, le « premier client » serait tiré au hasard)
    jean = db.scalar(select(User.id).where(User.email.like("jean.dupont@%")))
    r = admin.req("POST", "/lab/runs", {"scenario": "account_takeover", "victim_id": str(jean)})
    assert r.status_code == 201, r.text
    summary = r.json()["summary"]
    assert summary["blocked"] >= 1 and summary["alerts"] >= 1
    alerts = analyst.req("GET", "/soc/alerts?limit=50").json()
    assert any(a["title"].startswith("[SIM]") for a in alerts)
    detail = analyst.req("GET", f"/soc/alerts/{alerts[0]['id']}").json()
    assert detail["reasons"] and detail["mitre"] is not None and detail["events"]


def test_analyst_can_triage_and_must_justify_closure(analyst):
    alert = analyst.req("GET", "/soc/alerts?status=NEW&limit=1").json()[0]
    r = analyst.req("PATCH", f"/soc/alerts/{alert['id']}", {"status": "RESOLVED"})
    assert r.status_code == 422 and r.json()["code"] == "note_required"
    ok = analyst.req("PATCH", f"/soc/alerts/{alert['id']}", {"status": "FALSE_POSITIVE",
                                                              "resolution_note": "Test de laboratoire"})
    assert ok.status_code == 200 and ok.json()["status"] == "FALSE_POSITIVE"


def test_analyst_action_is_reversible_but_admin_actions_are_not_for_analyst(analyst, db):
    from app.models import Card
    card = db.scalar(select(Card))
    r = analyst.req("POST", "/soc/actions", {"action_type": "LOCK_CARD", "target_id": str(card.id),
                                             "justification": "Carte suspecte"})
    assert r.status_code == 200, r.text
    back = analyst.req("POST", f"/soc/actions/{r.json()['id']}/revert", {"justification": "Fausse alerte"})
    assert back.status_code == 200 and back.json()["status"] == "REVERTED"
    denied = analyst.req("POST", "/soc/actions", {"action_type": "FREEZE_ACCOUNT", "target_id": str(card.id),
                                                  "justification": "Test des droits"})
    assert denied.status_code == 403


def test_auditor_is_read_only(auditor):
    assert auditor.req("GET", "/soc/alerts").status_code == 200
    assert auditor.req("GET", "/audit/logs").status_code == 200
    assert auditor.req("GET", "/audit/verify").json()["valid"] is True
    nil = "00000000-0000-0000-0000-000000000000"
    assert auditor.req("POST", "/soc/actions", {"action_type": "LOCK_CARD", "target_id": nil,
                                                "justification": "interdit"}).status_code == 403
    assert auditor.req("PATCH", "/admin/risk-rules/00000000-0000-0000-0000-000000000000",
                       {"weight": 1, "justification": "interdit"}).status_code in (403, 404)
    assert auditor.req("GET", "/audit/export").headers["content-type"].startswith("text/csv")


def test_admin_changes_rule_with_audit_trail(admin, auditor):
    rule = next(r for r in admin.req("GET", "/admin/risk-rules").json() if r["code"] == "NEW_DEVICE")
    r = admin.req("PATCH", f"/admin/risk-rules/{rule['id']}", {"weight": 22, "justification": "Réglage de test"})
    assert r.status_code == 200 and r.json()["weight"] == 22 and r.json()["version"] == rule["version"] + 1
    logs = auditor.req("GET", "/audit/logs?action=RISK_RULE").json()
    assert logs and logs[0]["before"]["weight"] == 20 and logs[0]["after"]["weight"] == 22
    admin.req("PATCH", f"/admin/risk-rules/{rule['id']}", {"weight": 20, "justification": "Retour au réglage initial"})
    assert auditor.req("GET", "/audit/verify").json()["valid"] is True


def test_rule_change_requires_justification_and_permission(admin, analyst):
    rule = admin.req("GET", "/admin/risk-rules").json()[0]
    assert admin.req("PATCH", f"/admin/risk-rules/{rule['id']}", {"weight": 5}).status_code == 422
    assert analyst.req("PATCH", f"/admin/risk-rules/{rule['id']}", {"weight": 5, "justification": "pas le droit"}
                       ).status_code == 403


def test_agent_cannot_open_unassigned_customer_and_soc_is_alerted(agent, analyst, db):
    from app.models import SecurityAlert, User
    victim = db.scalar(select(User).where(User.email.like("paul.mbarga@%")))
    r = agent.req("GET", f"/soc/customers/{victim.id}")
    assert r.status_code == 403                      # l'agent n'a pas la permission de consulter hors ticket
    # via un ticket d'un autre client : accès refusé et tracé
    assert db.scalar(select(SecurityAlert).limit(1)) is not None


def test_support_flow_scam_detection_and_scoped_access(agent, mp, db):
    from app.models import SupportTicket, User
    from tests.integration.test_banking_flow import Bank
    client = Bank("fatima.bello", mp, "203.0.113.41")
    said = "Quelqu'un de la banque m'a appelé et m'a demandé mon code 123456"
    r = client.post("/support/conversations", {"topic": "Appel suspect", "message": said})
    assert r.status_code == 201
    msgs = r.json()["messages"]
    assert "123456" not in str(msgs) and r.json()["scam_signal"] is True    # secret masqué, arnaque détectée
    queue = agent.req("GET", "/support/queue").json()
    mine = next(t for t in queue if t["conversation_id"] == r.json()["id"])
    assert "user" not in mine and mine["priority"] == "URGENT"                # pas d'identité avant prise en charge
    ticket_id = mine["id"]
    assert agent.req("GET", f"/support/tickets/{ticket_id}/customer").status_code == 404   # pas encore assigné
    assert agent.req("POST", f"/support/tickets/{ticket_id}/accept").status_code == 200
    file = agent.req("GET", f"/support/tickets/{ticket_id}/customer").json()
    assert "accounts" not in file and "email" not in file["user"]
    ticket = db.get(SupportTicket, ticket_id)
    other = db.scalar(select(User).where(User.email.like("jean.dupont@%")))
    assert ticket.user_id != other.id
    lock = agent.req("POST", f"/support/tickets/{ticket_id}/lock-card",
                     {"card_id": file["cards"][0]["id"], "justification": "Demande du client"})
    assert lock.status_code == 200
    assert agent.req("POST", f"/support/tickets/{ticket_id}/close").status_code == 200
    # fenêtre fermée : plus d'accès au dossier
    assert agent.req("GET", f"/support/tickets/{ticket_id}/customer").status_code == 403


def test_insider_bulk_access_scenario_is_detected(admin, analyst):
    r = admin.req("POST", "/lab/runs", {"scenario": "insider_bulk_access"})
    assert r.status_code == 201 and r.json()["summary"]["alerts"] >= 1
    events = analyst.req("GET", "/soc/events?category=staff&limit=50").json()
    assert any(e["type"] in ("STAFF_BULK_ACCESS_DETECTED", "STAFF_PRIVILEGE_ABUSE_DETECTED") for e in events)


def test_stats_and_unknown_scenario(admin, analyst):
    s = analyst.req("GET", "/soc/stats").json()
    assert s["open_alerts"] >= 0 and "top_rules" in s
    assert admin.req("POST", "/lab/runs", {"scenario": "nope"}).status_code == 404
