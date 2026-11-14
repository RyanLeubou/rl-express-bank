"""POINT D'EXTENSION POUR VOTRE IA COMPORTEMENTALE.

Le moteur de risque (risk/engine.py) est un moteur de règles explicables. Il réserve la règle
`BEHAVIORAL_ANOMALY` (0 à 15 points par défaut) à un `BehaviorScorer` : tant que vous n'en avez
pas branché, `NullScorer` répond « pas d'avis » et la règle ne contribue pas au score.

Pour brancher votre modèle :
    1. Créez une classe qui implémente `score(ctx, baseline) -> float | None` (0 = normal, 1 = très anormal) ;
    2. Appelez `set_scorer(MonScorer())` au démarrage (par exemple dans app/main.py) ;
    3. Si votre modèle échoue ou est indisponible, levez une exception ou renvoyez None :
       le moteur continue avec les règles seules (`degraded=True` dans l'évaluation).
Le contexte (`OperationContext`) et le profil de référence (`Baseline`) donnent tout ce qu'il faut
pour construire vos variables : montant, heure, ville, appareil, historique du client, etc.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from app.risk.context import OperationContext
    from app.risk.state import Baseline

MODEL_VERSION = "none"


class BehaviorScorer(Protocol):
    version: str

    def score(self, ctx: OperationContext, baseline: Baseline) -> float | None:
        """Retourne un score d'anomalie entre 0 et 1, ou None si aucun avis."""


class NullScorer:
    version = MODEL_VERSION

    def score(self, ctx: OperationContext, baseline: Baseline) -> float | None:  # noqa: ARG002
        return None


_scorer: BehaviorScorer = NullScorer()


def get_scorer() -> BehaviorScorer:
    return _scorer


def set_scorer(scorer: BehaviorScorer) -> None:
    global _scorer  # noqa: PLW0603
    _scorer = scorer
