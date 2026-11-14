"""RL SOLUTION + LLM hébergé : garde-fous et repli, avec un faux service compatible OpenAI (sans réseau ni base)."""
import io
import urllib.error
from contextlib import nullcontext

import pytest
from pydantic import SecretStr

from app.ai import assistant_llm


@pytest.fixture
def llm(monkeypatch):
    sent: list[tuple[str, dict]] = []
    state = {"reply": "Vous pouvez bloquer votre carte dans Cartes et paiements.", "fail": None}

    def fake_post(path, payload, timeout):
        sent.append((path, payload))
        if state["fail"]:
            raise state["fail"]
        return {"choices": [{"message": {"role": "assistant", "content": state["reply"]}}]}

    monkeypatch.setattr(assistant_llm, "enabled", lambda: True)
    monkeypatch.setattr(assistant_llm, "_post", fake_post)
    monkeypatch.setattr(assistant_llm, "_fiches", lambda db, q: ["Bloquer sa carte : menu Cartes et paiements."])
    monkeypatch.setattr(assistant_llm, "get_session_factory", lambda: lambda: nullcontext(None))
    return sent, state


def test_answer_uses_knowledge_and_frames_the_customer_message(llm):
    sent, _ = llm
    assert assistant_llm.answer("Comment bloquer ma carte ?").startswith("Vous pouvez bloquer")
    path, payload = sent[0]
    assert path == "/chat/completions"
    user_turn = payload["messages"][1]["content"]
    assert "[Fiche 1] Bloquer sa carte" in user_turn
    assert "<message_client>\nComment bloquer ma carte ?\n</message_client>" in user_turn


def test_reply_asking_for_a_secret_is_discarded(llm):
    _, state = llm
    state["reply"] = "Pour vérifier, donnez-moi le code reçu par SMS."
    assert assistant_llm.answer("j'ai un souci") is None


@pytest.mark.parametrize("error", [
    TimeoutError("trop lent"),
    urllib.error.HTTPError("https://x", 429, "quota gratuit atteint", {}, io.BytesIO(b"")),
    urllib.error.HTTPError("https://x", 401, "clé invalide", {}, io.BytesIO(b"")),
])
def test_unavailable_model_or_quota_falls_back(llm, error):
    _, state = llm
    state["fail"] = error
    assert assistant_llm.answer("bonjour") is None


def test_disabled_without_api_key(monkeypatch):
    monkeypatch.setattr(assistant_llm, "get_settings",
                        lambda: type("S", (), {"llm_api_key": SecretStr(""), "app_env": "dev"})())
    assert assistant_llm.answer("bonjour") is None


def test_api_key_never_sent_over_plain_http(monkeypatch):
    monkeypatch.setattr(assistant_llm, "get_settings", lambda: type("S", (), {
        "llm_base_url": "http://api.example.test/v1", "llm_api_key": SecretStr("gsk_test")})())
    with pytest.raises(ValueError, match="https"):
        assistant_llm._post("/chat/completions", {}, 1)


def test_public_facts_list_agencies_and_live_atm_status_only():
    from types import SimpleNamespace

    from app.models.enums import AtmStatus

    atm = SimpleNamespace(name="RL Akwa", city="Douala", status=AtmStatus.MAINTENANCE,
                          atm_code="ATM-DLA-001", terminal_secret_hash="secret-hash", latitude=4.05, longitude=9.7)
    db = SimpleNamespace(scalars=lambda q: SimpleNamespace(all=lambda: [atm]))
    facts = " ".join(assistant_llm._public_facts(db))
    assert "Douala (code guichet 00101)" in facts and "Bafoussam" in facts
    assert "RL Akwa (Douala, en maintenance)" in facts
    assert "secret-hash" not in facts and "ATM-DLA-001" not in facts


class _Rows(list):
    def all(self):
        return list(self)


def _fake_db():
    """Base factice : les vraies fiches du seed pour la base de connaissances, un distributeur pour les ATM."""
    from types import SimpleNamespace

    from app.models.enums import AtmStatus
    from app.seed.reference import KNOWLEDGE

    docs = _Rows(SimpleNamespace(slug=s, title=t, body=b) for s, t, b in KNOWLEDGE)
    atms = _Rows([SimpleNamespace(name="RL Bastos", city="Yaoundé", status=AtmStatus.SUSPICIOUS)])
    return SimpleNamespace(scalars=lambda q: docs if "knowledge_documents" in str(q) else atms)


@pytest.mark.parametrize(("question", "expected"), [
    ("Quel est mon IBAN ?", "Trouver et partager mon RIB / IBAN"),
    ("Quelles sont les bonnes pratiques de cybersécurité ?", "Bonnes pratiques de cybersécurité"),
    ("Comment sécuriser mon compte ?", "Bonnes pratiques de cybersécurité"),
    ("Ma carte est bloquée", "Bloquer ou débloquer ma carte"),
])
def test_only_relevant_fiches_are_sent(question, expected):
    fiches = assistant_llm._fiches(_fake_db(), question)
    titles = [f.split(" : ")[0] for f in fiches]
    assert titles[0] == "À propos de RL EXPRESS BANK"                 # toujours là : les vrais noms de menus
    assert expected in titles
    assert len(fiches) <= 1 + assistant_llm.TOP_K                       # pas de données ATM hors sujet
    assert not any(f.startswith("Distributeurs") for f in fiches)


def test_atm_questions_get_live_atm_list_and_hide_soc_marking():
    fiches = " ".join(assistant_llm._fiches(_fake_db(), "Où trouver un distributeur à Yaoundé ?"))
    assert "RL Bastos (Yaoundé, en service)" in fiches                  # marquage SOC « suspect » jamais exposé
    assert "pas de menu Distributeurs" in fiches
    assert "Distributeurs" in " ".join(assistant_llm._fiches(_fake_db(), "Un GAB près de chez moi ?"))


def test_vague_question_gets_every_fiche():
    from app.seed.reference import KNOWLEDGE

    assert len(assistant_llm._fiches(_fake_db(), "Bonjour !")) == len(KNOWLEDGE)


def test_knowledge_covers_iban_and_security_without_internal_thresholds():
    from app.seed.reference import KNOWLEDGE, RISK_RULES

    slugs = {slug for slug, _, _ in KNOWLEDGE}
    assert {"rib-iban", "bonnes-pratiques-securite"} <= slugs
    text = " ".join(body for _, _, body in KNOWLEDGE)
    assert "Vérifier un appel" not in text                       # fonction inexistante dans l'application
    assert not any(code in text for code, *_ in RISK_RULES)       # aucune règle anti-fraude exposée


def test_secrets_are_masked_before_reaching_the_model(monkeypatch):
    from app.services.support import assistant

    seen = []
    monkeypatch.setattr(assistant_llm, "answer", lambda q: seen.append(q) or "ok")
    assert assistant.answer(None, "mon code est 482913") == "ok"
    assert "482913" not in seen[0] and "[MASQUÉ]" in seen[0]


def test_safety_reminder_is_not_mistaken_for_a_request():
    assert not assistant_llm.asks_for_secret("Ne communiquez jamais votre code, même à un conseiller.")
    assert not assistant_llm.asks_for_secret("Ne donnez pas votre code PIN par téléphone.")
    assert assistant_llm.asks_for_secret("Merci. Envoyez-moi votre code PIN pour vérifier.")
    assert assistant_llm.asks_for_secret("N'hésitez pas à me donner votre code reçu par SMS.")
