"""Grand livre en partie double (socle phase 3, utilisé par toutes les opérations financières).

Chaque mouvement = un journal de deux écritures de somme nulle (débit d'un compte, crédit d'un autre).
Les comptes sont verrouillés (SELECT ... FOR UPDATE) dans l'ordre de leur identifiant pour éviter
les interblocages ; le solde est vérifié sous verrou puis protégé par les contraintes CHECK.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.banking import Account, LedgerEntry
from app.models.enums import AccountStatus, AccountType, LedgerOperation


class LedgerError(Exception):
    """Erreur métier du grand livre (solde insuffisant, compte inactif, montant invalide)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def post_transfer(db: Session, *, debit_account_id: uuid.UUID, credit_account_id: uuid.UUID, amount: int,
                  operation_type: LedgerOperation, operation_id: uuid.UUID | None, description: str,
                  value_date: datetime | None = None) -> uuid.UUID:
    """Débite un compte, crédite l'autre, dans la transaction courante. Retourne l'identifiant du journal."""
    if amount <= 0:
        raise LedgerError("invalid_amount", "Le montant doit être strictement positif")
    if debit_account_id == credit_account_id:
        raise LedgerError("same_account", "Comptes débité et crédité identiques")

    ids = sorted([debit_account_id, credit_account_id])
    locked = {a.id: a for a in db.scalars(
        select(Account).where(Account.id.in_(ids)).order_by(Account.id).with_for_update())}
    if len(locked) != 2:
        raise LedgerError("account_not_found", "Compte introuvable")
    debit, credit = locked[debit_account_id], locked[credit_account_id]
    for account in (debit, credit):
        if account.status != AccountStatus.ACTIVE:
            raise LedgerError("account_inactive", f"Compte {account.account_number} non actif")
    if debit.account_type != AccountType.INTERNAL and debit.available_balance < amount:
        raise LedgerError("insufficient_funds", "Solde disponible insuffisant")

    journal_id = uuid.uuid4()
    debit.balance -= amount
    debit.available_balance -= amount
    credit.balance += amount
    credit.available_balance += amount
    extra = {"value_date": value_date} if value_date else {}
    db.add_all([
        LedgerEntry(journal_id=journal_id, account_id=debit.id, amount=-amount, balance_after=debit.balance,
                    operation_type=operation_type, operation_id=operation_id, description=description, **extra),
        LedgerEntry(journal_id=journal_id, account_id=credit.id, amount=amount, balance_after=credit.balance,
                    operation_type=operation_type, operation_id=operation_id, description=description, **extra),
    ])
    return journal_id
