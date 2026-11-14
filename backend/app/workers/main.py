"""Worker RL EXPRESS BANK.

Phase 2 : boucle de supervision (heartbeat Valkey, vérification PostgreSQL, arrêt propre).
Les jobs s'ajoutent au registre JOBS au fil des phases :
  phase 8  : expiration des codes sans carte et des réservations de fonds
  phase 10 : expédition de l'outbox (fichier Wazuh, index OpenSearch)
  phase 12 : recalcul des profils comportementaux, entraînement
  phase 13 : corrélation d'événements
"""
from __future__ import annotations

import logging
import signal
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from app.core.cache import WORKER_HEARTBEAT_KEY, get_valkey
from app.core.config import get_settings
from app.core.database import check_database
from app.core.logging import configure_logging

logger = logging.getLogger("rlbank.worker")
HEARTBEAT_INTERVAL = 10
HEARTBEAT_TTL = 30


@dataclass
class Job:
    name: str
    interval_seconds: int
    run: Callable[[], None]
    last_run: float = field(default=0.0)


def expire_codes() -> None:
    """Expire les codes de retrait sans carte échus et libère les fonds réservés."""
    from datetime import UTC, datetime

    from sqlalchemy import select

    from app.core.database import get_session_factory
    from app.models import CardlessCode, Withdrawal
    from app.models.enums import CardlessCodeStatus, HoldStatus, WithdrawalStatus
    from app.services.banking.holds import release_hold

    with get_session_factory()() as db:
        now = datetime.now(UTC)
        due = select(CardlessCode).where(CardlessCode.status == CardlessCodeStatus.ACTIVE,
                                         CardlessCode.expires_at <= now).with_for_update(skip_locked=True)
        for code in db.scalars(due):
            code.status = CardlessCodeStatus.EXPIRED
            if code.hold_id:
                release_hold(db, code.hold_id, HoldStatus.EXPIRED)
            w = db.get(Withdrawal, code.withdrawal_id)
            if w and w.status == WithdrawalStatus.PENDING:
                w.status = WithdrawalStatus.CANCELLED
        db.commit()


JOBS: list[Job] = [Job("expire_cardless_codes", 60, expire_codes)]


class Worker:
    def __init__(self) -> None:
        self.running = True
        signal.signal(signal.SIGTERM, self._stop)
        signal.signal(signal.SIGINT, self._stop)

    def _stop(self, signum: int, _frame: object) -> None:
        logger.info("Signal d'arrêt reçu", extra={"signal": signum})
        self.running = False

    def heartbeat(self) -> None:
        try:
            get_valkey().set(WORKER_HEARTBEAT_KEY, str(time.time()), ex=HEARTBEAT_TTL)
        except Exception:  # noqa: BLE001
            logger.warning("Heartbeat impossible : Valkey indisponible")

    def run_due_jobs(self) -> None:
        now = time.time()
        for job in JOBS:
            if now - job.last_run < job.interval_seconds:
                continue
            job.last_run = now
            try:
                job.run()
            except Exception:  # noqa: BLE001 - un job en échec ne doit pas arrêter les autres
                logger.exception("Échec du job", extra={"job": job.name})

    def loop(self) -> None:
        logger.info("Worker démarré", extra={"jobs": [j.name for j in JOBS]})
        last_heartbeat = 0.0
        while self.running:
            if time.time() - last_heartbeat >= HEARTBEAT_INTERVAL:
                db = check_database()
                if db["status"] != "ok":
                    logger.warning("PostgreSQL indisponible, jobs suspendus")
                self.heartbeat()
                last_heartbeat = time.time()
                if db["status"] == "ok":
                    self.run_due_jobs()
            time.sleep(1)
        try:
            get_valkey().delete(WORKER_HEARTBEAT_KEY)
        except Exception:  # noqa: BLE001
            logger.debug("Heartbeat non supprimé : Valkey indisponible à l'arrêt")
        logger.info("Worker arrêté proprement")


def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level, service="rlbank-worker")
    Worker().loop()


if __name__ == "__main__":
    main()
