"""Contrôle d'intégrité démontrable : chaîne d'audit et invariants comptables.

Usage : make integrity   (ou python scripts/verify_integrity.py dans le conteneur API)
Code de sortie 0 si tout est intègre, 1 sinon.
"""
from __future__ import annotations

import sys

from sqlalchemy import text

from app.core.database import get_session_factory
from app.events.audit import verify_audit_chain

CHECKS = {
    "Journaux comptables équilibrés (débit = crédit)":
        "SELECT count(*) FROM (SELECT journal_id FROM ledger_entries GROUP BY journal_id HAVING sum(amount) <> 0) x",
    "Soldes égaux à la somme des écritures":
        "SELECT count(*) FROM accounts a WHERE a.balance <> COALESCE((SELECT sum(amount) FROM ledger_entries l "
        "WHERE l.account_id = a.id), 0)",
    "Aucun solde client négatif":
        "SELECT count(*) FROM accounts WHERE account_type <> 'INTERNAL' AND balance < 0",
    "Somme de tous les soldes nulle (partie double)":
        "SELECT CASE WHEN COALESCE(sum(balance), 0) = 0 THEN 0 ELSE 1 END FROM accounts",
}


def main() -> int:
    ok = True
    with get_session_factory()() as db:
        for label, sql in CHECKS.items():
            anomalies = db.execute(text(sql)).scalar_one()
            ok &= anomalies == 0
            suffix = f" : {anomalies} anomalie(s)" if anomalies else ""
            print(f"[{'OK ' if anomalies == 0 else 'KO '}] {label}{suffix}")
        report = verify_audit_chain(db)
        ok &= report.valid
        detail = f"{report.entries} entrée(s)" if report.valid else f"rupture à l'entrée n° {report.broken_at_seq}"
        print(f"[{'OK ' if report.valid else 'KO '}] Chaîne d'audit SHA-256 : {detail}")
    print("Intégrité vérifiée." if ok else "ANOMALIE D'INTÉGRITÉ DÉTECTÉE.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
