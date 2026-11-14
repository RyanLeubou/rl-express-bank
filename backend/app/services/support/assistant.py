"""RL SOLUTION : détection d'arnaque par règles, masquage des secrets avant stockage, et réponse.

`answer()` confie d'abord la question (masquée) au LLM hébergé (app/ai/assistant_llm.py, Groq) ; s'il est
désactivé ou indisponible, la meilleure fiche de la base de connaissances par mots-clés répond."""
from __future__ import annotations

import re
import unicodedata

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.redaction import redact_text
from app.models import KnowledgeDocument

SCAM_PATTERNS = [
    r"\b(code|otp|pin|mot de passe)\b.*\b(demande|demand[eé]|dit|appel|conseiller|banque)\b",
    r"\b(on|quelqu.un|conseiller|banque)\b.*\b(m.a|ont)\b.*\b(demand|appel|dit|envoy)",
    r"\b(urgent|imm[eé]diatement|compte (bloqu|pirat|compromis))",
    r"\b(lien|sms|whatsapp)\b.*\b(banque|compte|cliqu)",
]
HUMAN_WORDS = ("conseiller", "humain", "agent", "parler a quelqu", "reclamation", "fraude", "vol")


def _norm(text: str) -> str:
    return unicodedata.normalize("NFKD", text.lower()).encode("ascii", "ignore").decode()


def scrub(text: str) -> tuple[str, int]:
    """Masque OTP, codes et PIN dans le texte (avant tout stockage)."""
    cleaned = redact_text(text)
    cleaned = re.sub(r"\b\d{4,8}\b", "[MASQUÉ]", cleaned)
    return cleaned, cleaned.count("[MASQUÉ]") - text.count("[MASQUÉ]")


def scam_signal(text: str) -> bool:
    t = _norm(text)
    return any(re.search(p, t) for p in SCAM_PATTERNS)


def wants_human(text: str) -> bool:
    t = _norm(text)
    return any(w in t for w in HUMAN_WORDS)


def answer(db: Session, text: str) -> str | None:
    """Réponse du LLM local si disponible, sinon meilleure fiche par mots-clés, sinon None."""
    from app.ai import assistant_llm

    if (reply := assistant_llm.answer(scrub(text)[0])) is not None:
        return reply
    return keyword_answer(db, text)


def keyword_answer(db: Session, text: str) -> str | None:
    """Meilleure fiche de la base de connaissances (recouvrement de mots, titre compté double), ou None."""
    words = {w for w in re.findall(r"[a-z]{4,}", _norm(text))}
    best, best_score = None, 0
    for doc in db.scalars(select(KnowledgeDocument).where(KnowledgeDocument.published.is_(True))):
        score = (len(words & set(re.findall(r"[a-z]{4,}", _norm(doc.title + " " + doc.body))))
                 + len(words & set(re.findall(r"[a-z]{4,}", _norm(doc.title)))))
        if score > best_score:
            best, best_score = doc, score
    return f"{best.title} : {best.body}" if best and best_score >= 2 else None
