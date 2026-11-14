"""Ouverture de comptes clients : numéro aléatoire unique, RIB rattaché à l'agence de la ville du client."""
from __future__ import annotations

import secrets

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.banking import Account
from app.models.enums import AccountStatus, AccountType
from app.models.identity import User
from app.services.banking.rib import CITY_AGENCY, build_rib

LABELS = {AccountType.CURRENT: "Compte courant", AccountType.SAVINGS: "Livret épargne"}


def agency_for(city: str | None) -> str:
    return CITY_AGENCY.get(city or "", "Douala")


def open_account(db: Session, user: User, kind: AccountType) -> Account:
    while True:                                              # numéro aléatoire, unicité vérifiée en base
        number = f"{secrets.randbelow(9 * 10**10) + 10**10:011d}"
        if not db.scalar(select(Account.id).where(Account.account_number == number)):
            break
    rib = build_rib(number, agency_for(user.city))
    account = Account(user_id=user.id, label=LABELS[kind], account_number=rib.account_number,
                      bank_code=rib.bank_code, branch_code=rib.branch_code, rib_key=rib.rib_key, iban=rib.iban,
                      bic=rib.bic, account_type=kind, balance=0, available_balance=0, status=AccountStatus.ACTIVE)
    db.add(account)
    db.flush()
    return account
