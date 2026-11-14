"""Moteur de risque : somme pondérée de règles explicables, niveau, décision de politique.

Le score comportemental (votre IA) est facultatif : voir risk/scorer.py. Sans scorer, `degraded` reste
False car il n'y a rien à dégrader ; si un scorer est installé et échoue, `degraded=True`.
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import RiskAssessment, RiskRule
from app.models.enums import PolicyDecision, RiskLevel
from app.risk.context import OperationContext
from app.risk.policy import level_for, resolve
from app.risk.rules import EVALUATORS, RuleEnv
from app.risk.scorer import NullScorer, get_scorer
from app.risk.state import Baseline, baseline_for

logger = logging.getLogger("rlbank.risk")
BEHAVIORAL = "BEHAVIORAL_ANOMALY"


@dataclass
class RiskResult:
    score: int
    level: RiskLevel
    decision: PolicyDecision
    actions: list[str]
    reasons: list[dict] = field(default_factory=list)
    ai_score: float | None = None
    rules_version: int = 1
    model_version: str | None = None
    degraded: bool = False
    assessment_id: uuid.UUID | None = None


def active_rules(db: Session) -> list[RiskRule]:
    latest: dict[str, RiskRule] = {}
    for r in db.scalars(select(RiskRule).where(RiskRule.enabled.is_(True)).order_by(RiskRule.version)):
        latest[r.code] = r
    return list(latest.values())


def evaluate(db: Session, ctx: OperationContext, *, baseline: Baseline | None = None) -> RiskResult:
    settings = get_settings()
    db.flush()      # les événements récents de la transaction doivent être visibles des règles
    base = baseline or baseline_for(db, ctx.user.id, ctx.occurred_at)
    reasons: list[dict] = []
    total, version = 0, 1
    ai_score: float | None = None
    degraded = False
    scorer = get_scorer()
    for rule in active_rules(db):
        if str(ctx.op) not in rule.operation_types:
            continue
        version = max(version, rule.version)
        if rule.code == BEHAVIORAL:
            if isinstance(scorer, NullScorer):
                continue
            try:
                ai_score = scorer.score(ctx, base)
            except Exception:  # noqa: BLE001 - un scorer défaillant ne doit jamais bloquer une opération
                logger.exception("Scorer comportemental en échec : règles seules")
                degraded = True
                continue
            if ai_score is not None:
                points = round(max(0.0, min(1.0, ai_score)) * rule.params.get("max_points", rule.weight))
                if points:
                    total += points
                    reasons.append({"code": rule.code, "points": points,
                                    "detail": f"Score d'anomalie {ai_score:.2f}"})
            continue
        evaluator = EVALUATORS.get(rule.code)
        detail = evaluator(RuleEnv(db, ctx, base, rule.params)) if evaluator else None
        if detail:
            total += rule.weight
            reasons.append({"code": rule.code, "points": rule.weight, "detail": detail})
    score = max(0, min(100, total))
    level = level_for(score, settings)
    decision, actions = resolve(db, ctx.op, level)
    return RiskResult(score, level, decision, actions, reasons, ai_score, version,
                      scorer.version if ai_score is not None else None, degraded)


def save_assessment(db: Session, ctx: OperationContext, result: RiskResult, **link: uuid.UUID | None) -> None:
    row = RiskAssessment(user_id=ctx.user.id, operation_type=ctx.op, score=result.score, level=result.level,
                         reasons=result.reasons, ai_score=result.ai_score, rules_version=result.rules_version,
                         model_version=result.model_version, decision=result.decision,
                         degraded=result.degraded, **link)
    db.add(row)
    db.flush()
    result.assessment_id = row.id
