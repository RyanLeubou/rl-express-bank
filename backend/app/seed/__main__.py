"""python -m app.seed [--demo] : initialise la plateforme (idempotent).

Sans option : base indispensable uniquement (rôles, règles, distributeurs, fiches, comptes internes), AUCUN compte
connectable. --demo : ajoute le personnel et les clients fictifs aux mots de passe connus (installation locale).
"""
from __future__ import annotations

import logging
import sys

from app.core.config import get_settings
from app.core.database import get_session_factory
from app.core.logging import configure_logging
from app.seed.runner import SeedRefused, run_seed

logger = logging.getLogger("rlbank.seed")


def main(argv: list[str]) -> int:
    configure_logging(get_settings().log_level, service="rlbank-seed")
    demo = "--demo" in argv
    with get_session_factory()() as db:
        try:
            summary = run_seed(db, demo=demo)
        except SeedRefused as exc:
            logger.error(str(exc))
            return 1
        if summary.get("skipped"):
            logger.info("Données déjà présentes : seed ignoré")
            return 0
        db.commit()
    logger.info("Seed terminé (démonstration)" if demo else "Plateforme initialisée, sans compte utilisateur",
                extra=summary)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
