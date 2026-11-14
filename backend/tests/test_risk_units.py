"""Briques du moteur de risque qui ne demandent aucune base de données."""
from __future__ import annotations

from app.core.config import Settings
from app.models.enums import PolicyDecision as D
from app.models.enums import RiskLevel
from app.risk.geo import distance_km
from app.risk.policy import level_for, needs_step_up, stricter
from app.risk.scorer import NullScorer, get_scorer, set_scorer


def test_levels_follow_thresholds():
    s = Settings(app_env="test")
    assert [level_for(x, s) for x in (0, 29, 30, 59, 60, 79, 80, 100)] == [
        RiskLevel.LOW, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.HIGH,
        RiskLevel.CRITICAL, RiskLevel.CRITICAL]


def test_floor_never_weakens_a_decision():
    assert stricter(D.ALLOW, D.STEP_UP_TOTP) == D.STEP_UP_TOTP
    assert stricter(D.BLOCK, D.STEP_UP_PASSKEY) == D.BLOCK
    assert needs_step_up(D.STEP_UP_PASSKEY) and not needs_step_up(D.ALLOW_AND_MONITOR)


def test_distance_douala_paris_is_realistic():
    assert 5000 < distance_km("Douala", "Paris") < 5300
    assert distance_km("Douala", "Inconnue") is None


def test_default_scorer_gives_no_opinion():
    assert isinstance(get_scorer(), NullScorer) and get_scorer().score(None, None) is None  # type: ignore[arg-type]
    custom = NullScorer()
    set_scorer(custom)
    assert get_scorer() is custom
