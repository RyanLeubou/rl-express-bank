"""Le point d'extension de l'IA comportementale : un scorer externe s'ajoute aux règles sans les remplacer."""
from __future__ import annotations

import pytest
from sqlalchemy import select


class Always:
    version = "test-1"

    def __init__(self, value):
        self.value = value

    def score(self, ctx, baseline):
        return self.value


class Broken:
    version = "broken"

    def score(self, ctx, baseline):
        raise RuntimeError("modèle indisponible")


@pytest.fixture
def evaluate_for(db):
    from app.models import User
    from app.models.enums import RiskOperation
    from app.risk.context import OperationContext
    from app.risk.engine import evaluate
    from app.risk.scorer import NullScorer, set_scorer

    user = db.scalar(select(User).where(User.email.like("jean.dupont@%")))

    def run(scorer):
        set_scorer(scorer)
        return evaluate(db, OperationContext(user=user, op=RiskOperation.TRANSFER, amount=1000))
    yield run
    set_scorer(NullScorer())


def test_scorer_adds_up_to_its_maximum(evaluate_for):
    base = evaluate_for(Always(None))
    scored = evaluate_for(Always(1.0))
    assert scored.score - base.score == 15 and scored.model_version == "test-1" and scored.ai_score == 1.0
    assert any(r["code"] == "BEHAVIORAL_ANOMALY" for r in scored.reasons)


def test_failing_scorer_degrades_to_rules_only(evaluate_for):
    base = evaluate_for(Always(None))
    broken = evaluate_for(Broken())
    assert broken.degraded is True and broken.score == base.score
