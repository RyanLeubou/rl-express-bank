"""IA comportementale : Isolation Forest sur des variables relatives aux habitudes de chaque client.

Le modèle n'apprend pas « ce qu'est un gros montant » dans l'absolu mais l'écart d'une opération aux habitudes
du client qui la fait (montant / médiane habituelle, heure rare, ville nouvelle, appareil inconnu, rafale…).
Un seul modèle sert donc tous les clients, et un nouveau client (démarrage à froid) n'est pas noté.

Entraînement : `python -m app.ai.behavior train` rejoue l'historique (hors simulations) : chaque opération est
décrite par rapport aux opérations qui la précèdent. Le score brut est calibré sur la distribution
d'entraînement : percentile 50 -> 0, percentile 99,5 -> 1.

Artefact : `<AI_MODEL_DIR>/behavior_iforest.joblib` + `.json` (métadonnées et empreinte SHA-256, vérifiée avant
tout chargement : un fichier joblib modifié pourrait exécuter du code).
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import sys
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from app.core.config import get_settings
from app.risk.context import OperationContext
from app.risk.state import LOCAL_OFFSET, MIN_HISTORY, Baseline, PastOp

logger = logging.getLogger("rlbank.ai")
KINDS = ("transfer", "payment", "withdrawal", "beneficiary", "login")
FEATURES = ("amount_ratio", "hour_rarity", "city_novelty", "unknown_device", "ops_24h", "gap_minutes", "night",
            *(f"kind_{k}" for k in KINDS))
MODEL_FILE, META_FILE = "behavior_iforest.joblib", "behavior_iforest.json"


# ---------------------------------------------------------------------- variables
def features(kind: str, at: datetime, amount: int | None, city: str | None, device_known: bool | None,
             history: list[PastOp]) -> list[float]:
    """Vecteur d'une opération décrite par rapport à `history` (opérations antérieures du même client)."""
    hour = (at + LOCAL_OFFSET).hour
    hours = Counter((o.at + LOCAL_OFFSET).hour for o in history)
    near = sum(hours[(hour + d) % 24] for d in (-1, 0, 1))
    hour_rarity = 1 - near / max(len(history), 1)

    same = sorted(o.amount for o in history if o.kind == kind and o.amount)
    if amount and same:
        median = same[len(same) // 2]
        amount_ratio = math.log1p(amount / max(median, 1))
    else:
        amount_ratio = 0.0

    cities = Counter(o.city for o in history if o.city)
    city_novelty = (1 - cities[city] / max(sum(cities.values()), 1)) if city else 0.0

    recent = [o for o in history if at - timedelta(hours=24) <= o.at < at]
    last = max((o.at for o in history if o.at < at), default=None)
    gap = math.log1p(min((at - last).total_seconds() / 60, 60 * 24 * 30)) if last else math.log1p(60 * 24 * 30)

    return [amount_ratio, hour_rarity, city_novelty, 0.0 if device_known in (True, None) else 1.0,
            math.log1p(len(recent)), gap, 1.0 if hour < 6 else 0.0, *(1.0 if kind == k else 0.0 for k in KINDS)]


def training_matrix(ops_by_user: dict[object, list[PastOp]]) -> np.ndarray:
    """Rejoue l'historique : chaque opération établie est décrite par rapport à celles qui la précèdent."""
    rows = []
    for ops in ops_by_user.values():
        ops = sorted((o for o in ops if not o.simulated), key=lambda o: o.at)
        seen_devices: set = set()
        for i, op in enumerate(ops):
            prior = ops[:i]
            if len([o for o in prior if o.kind != "login"]) >= MIN_HISTORY:
                known = op.device_id in seen_devices if op.device_id else None
                rows.append(features(op.kind, op.at, op.amount, op.city, known, prior))
            if op.device_id:
                seen_devices.add(op.device_id)
    return np.asarray(rows, dtype=float)


# ---------------------------------------------------------------------- entraînement et artefact
def model_dir() -> Path:
    return Path(get_settings().ai_model_dir)


def train(ops_by_user: dict[object, list[PastOp]], out_dir: Path, *, seed: int = 20261113) -> dict:
    x = training_matrix(ops_by_user)
    if len(x) < 100:
        raise RuntimeError(f"Historique insuffisant pour entraîner ({len(x)} opérations, 100 minimum)")
    model = IsolationForest(n_estimators=200, contamination="auto", random_state=seed).fit(x)
    raw = -model.score_samples(x)                       # plus haut = plus anormal
    meta = {
        "version": f"iforest-{datetime.now(UTC):%Y%m%d%H%M}", "features": list(FEATURES), "samples": len(x),
        "users": len(ops_by_user), "p50": float(np.percentile(raw, 50)), "p995": float(np.percentile(raw, 99.5)),
        "trained_at": datetime.now(UTC).isoformat(),
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / MODEL_FILE
    joblib.dump(model, path)
    meta["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    (out_dir / META_FILE).write_text(json.dumps(meta, indent=2))
    return meta


class IsolationForestScorer:
    """`BehaviorScorer` branché sur le moteur de risque (règle BEHAVIORAL_ANOMALY)."""

    def __init__(self, model: IsolationForest, meta: dict) -> None:
        self.model, self.meta, self.version = model, meta, meta["version"]

    @classmethod
    def load(cls, directory: Path) -> IsolationForestScorer:
        meta = json.loads((directory / META_FILE).read_text())
        blob = (directory / MODEL_FILE).read_bytes()
        if hashlib.sha256(blob).hexdigest() != meta["sha256"] or meta["features"] != list(FEATURES):
            raise RuntimeError("Modèle comportemental refusé : empreinte ou variables inattendues")
        return cls(joblib.load(directory / MODEL_FILE), meta)

    def score(self, ctx: OperationContext, baseline: Baseline) -> float | None:
        if baseline.cold_start:
            return None                                 # pas d'habitudes : pas d'avis, les règles décident
        device_known = ctx.device.id in baseline.known_devices if ctx.device else None
        x = features(ctx.kind, ctx.occurred_at, ctx.amount, ctx.city, device_known, baseline.habit_ops)
        raw = float(-self.model.score_samples(np.asarray([x]))[0])
        span = max(self.meta["p995"] - self.meta["p50"], 1e-9)
        return round(max(0.0, min(1.0, (raw - self.meta["p50"]) / span)), 3)


def install_if_available() -> str | None:
    """Au démarrage de l'API : branche le modèle s'il existe. Retourne sa version, ou None (règles seules)."""
    from app.risk.scorer import set_scorer

    directory = model_dir()
    if not (directory / MODEL_FILE).exists():
        logger.warning("IA comportementale absente : règles seules (lancez « make ai-train »)")
        return None
    try:
        scorer = IsolationForestScorer.load(directory)
    except Exception:  # noqa: BLE001 - un modèle illisible ne doit pas empêcher l'API de démarrer
        logger.exception("IA comportementale illisible : règles seules")
        return None
    set_scorer(scorer)
    logger.info("IA comportementale branchée", extra={"model_version": scorer.version})
    return scorer.version


def _cli() -> None:
    from sqlalchemy import select

    from app.core.database import get_session_factory
    from app.models.enums import UserType
    from app.models.identity import User
    from app.risk.state import load_ops

    directory = model_dir()
    if "--if-missing" in sys.argv and (directory / MODEL_FILE).exists():
        print(f"[ia] modèle déjà présent dans {directory}")
        return
    with get_session_factory()() as db:
        now = datetime.now(UTC)
        users = db.scalars(select(User.id).where(User.user_type == UserType.CUSTOMER)).all()
        meta = train({u: load_ops(db, u, now) for u in users}, directory)
    print(f"[ia] modèle {meta['version']} entraîné sur {meta['samples']} opérations de {meta['users']} clients")


if __name__ == "__main__" and sys.argv[1:2] == ["train"]:
    _cli()
