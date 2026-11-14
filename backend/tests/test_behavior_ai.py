"""IA comportementale : entraînement sur un historique synthétique, calibration, artefact vérifié."""
import random
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from app.ai.behavior import FEATURES, MODEL_FILE, IsolationForestScorer, features, train
from app.risk.state import Baseline, PastOp

NOW = datetime(2026, 11, 1, 12, tzinfo=UTC)


def _history(rng: random.Random, device: uuid.UUID) -> list[PastOp]:
    """Client régulier : retraits de 20 à 50 k à Douala, en journée, toujours le même appareil."""
    ops = []
    for i in range(110):
        at = NOW - timedelta(days=90) + timedelta(hours=i * 18 + rng.randint(0, 3))  # noqa: S311
        ops.append(PastOp(at, "withdrawal", rng.randint(20, 50) * 1000, "Douala", device, None))  # noqa: S311
    return ops


@pytest.fixture(scope="module")
def scorer(tmp_path_factory):
    rng = random.Random(1)  # noqa: S311 - données synthétiques
    users = {f"u{i}": _history(rng, uuid.uuid4()) for i in range(6)}
    directory = tmp_path_factory.mktemp("model")
    meta = train(users, directory)
    assert meta["samples"] > 100 and meta["features"] == list(FEATURES)
    return IsolationForestScorer.load(directory), users


def _ctx(amount, city, hour, device=None):
    return SimpleNamespace(kind="withdrawal", occurred_at=NOW.replace(hour=hour), amount=amount, city=city,
                           device=device)


def test_unusual_operation_scores_higher_than_a_habit(scorer):
    model, users = scorer
    ops = users["u0"]
    base = Baseline(ops=ops, habit_ops=ops, known_devices={ops[0].device_id}, cold_start=False)
    usual = model.score(_ctx(30_000, "Douala", 13, SimpleNamespace(id=ops[0].device_id)), base)
    odd = model.score(_ctx(900_000, "Lagos", 2, SimpleNamespace(id=uuid.uuid4())), base)
    assert 0 <= usual < 0.5 < odd <= 1


def test_cold_start_gives_no_opinion(scorer):
    model, _ = scorer
    assert model.score(_ctx(30_000, "Douala", 13), Baseline(cold_start=True)) is None


def test_tampered_artifact_is_refused(scorer, tmp_path):
    model, users = scorer
    train(users, tmp_path)
    (tmp_path / MODEL_FILE).write_bytes((tmp_path / MODEL_FILE).read_bytes() + b"x")
    with pytest.raises(RuntimeError):
        IsolationForestScorer.load(tmp_path)


def test_feature_vector_shape_and_novelty():
    ops = _history(random.Random(2), uuid.uuid4())  # noqa: S311
    v = features("withdrawal", NOW, 30_000, "Lagos", False, ops)
    assert len(v) == len(FEATURES) and v[FEATURES.index("city_novelty")] == 1.0
    assert v[FEATURES.index("unknown_device")] == 1.0
