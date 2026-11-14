"""Orchestration du seed : idempotent (ne fait rien si la banque est déjà initialisée)."""
from __future__ import annotations

import logging
import random
import secrets
import time
import uuid
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.events.audit import record_audit
from app.models import ATM, Account, Beneficiary, Card, Device, Notification, Role, User, UserRole
from app.models.enums import (
    AccountStatus,
    AccountType,
    ActorType,
    CardType,
    DeviceStatus,
    LedgerOperation,
    RoleCode,
    UserStatus,
    UserType,
)
from app.security.auth.passwords import hash_secret
from app.seed.history import (
    ClientContext,
    build_behavior_profile,
    device_fingerprint,
    ensure_beneficiary_active,
    generate_history,
    now_utc,
)
from app.seed.people import (
    CLIENTS,
    DEMO_CARD_PIN,
    DEMO_PASSWORDS,
    DOMAIN,
    EXTERNAL_BANKS,
    EXTERNAL_PEOPLE,
    STAFF,
)
from app.seed.reference import seed_reference
from app.services.banking.ledger import post_transfer
from app.services.banking.rib import build_rib

logger = logging.getLogger("rlbank.seed")
SEED = 20260928
ALLOWED_ENVIRONMENTS = {"development", "demo", "test"}


class SeedRefused(RuntimeError):
    pass


def _account_number(rng: random.Random, used: set[str]) -> str:
    while True:
        number = f"{rng.randrange(10**10, 10**11):011d}"
        if number not in used:
            used.add(number)
            return number


def _new_account(db: Session, rng, used, user: User, label: str, kind: AccountType, city: str) -> Account:
    rib = build_rib(_account_number(rng, used), city)
    account = Account(user_id=user.id, label=label, account_number=rib.account_number, bank_code=rib.bank_code,
                      branch_code=rib.branch_code, rib_key=rib.rib_key, iban=rib.iban, bic=rib.bic,
                      account_type=kind, balance=0, available_balance=0, status=AccountStatus.ACTIVE)
    db.add(account)
    db.flush()
    return account


INTERNAL_ACCOUNTS = (("EXTERNAL", "Compensation interbancaire"), ("ATM", "Règlement ATM"),
                     ("CARD", "Règlement cartes"))


def seed_base(db: Session) -> dict[str, int]:
    """Initialisation indispensable, SANS AUCUN COMPTE CONNECTABLE : rôles et permissions, règles, politiques,
    distributeurs, base de connaissances, utilisateur SYSTEM (désactivé) et comptes internes de la banque.

    Les clients créent ensuite leur compte par l'inscription ; le personnel est créé avec `make staff`.
    """
    if db.scalar(select(func.count()).select_from(Role)):
        return {"skipped": 1}
    rng = random.Random(SEED)
    seed_reference(db)
    # Comptes techniques de la banque, portés par l'utilisateur SYSTEM (jamais connectable)
    system = User(email=f"systeme@{DOMAIN}", first_name="Système", last_name="RL EXPRESS BANK",
                  user_type=UserType.SYSTEM, status=UserStatus.DISABLED, password_hash=None)
    db.add(system)
    db.flush()
    used: set[str] = set()
    for _, label in INTERNAL_ACCOUNTS:
        _new_account(db, rng, used, system, label, AccountType.INTERNAL, "Douala")
    record_audit(db, action="BASE_INITIALIZED", target_type="platform", target_id=str(uuid.UUID(int=SEED)),
                 actor_type=ActorType.SYSTEM, after={"internal_accounts": len(INTERNAL_ACCOUNTS)},
                 justification="Initialisation de la plateforme, sans compte utilisateur")
    return {"base": 1}


def run_seed(db: Session, demo: bool = True) -> dict[str, int]:
    """Base indispensable, puis (si `demo`) personnel et clients FICTIFS aux mots de passe connus.

    La démonstration est réservée à une installation locale de test : SEED_DEMO_DATA=false par défaut.
    """
    settings = get_settings()
    if settings.app_env not in ALLOWED_ENVIRONMENTS:
        raise SeedRefused(f"Seed interdit en environnement {settings.app_env}")
    base = seed_base(db)
    if not demo:
        return base
    if db.scalar(select(User.id).where(User.email == f"{STAFF[0][0]}@{DOMAIN}")):
        return {"skipped": 1}

    started = time.perf_counter()
    rng = random.Random(SEED)
    for _ in INTERNAL_ACCOUNTS:                  # tirages consommés par seed_base : données de démo identiques
        rng.randrange(10**10, 10**11)
    now = now_utc()
    history_start = now - timedelta(days=91)
    roles = {RoleCode(r.code): r for r in db.scalars(select(Role))}
    atms = {a.atm_code: a for a in db.scalars(select(ATM))}
    used_numbers: set[str] = set(db.scalars(select(Account.account_number)))
    labels = dict(INTERNAL_ACCOUNTS)
    internal = {key: db.scalar(select(Account).where(Account.account_type == AccountType.INTERNAL,
                                                     Account.label == label))
                for key, label in labels.items()}

    # ---- Personnel ----
    for login, first, last, role in STAFF:
        user = User(email=f"{login}@{DOMAIN}", first_name=first, last_name=last, user_type=UserType.STAFF,
                    password_hash=hash_secret(DEMO_PASSWORDS[role]), city="Douala", password_changed_at=now)
        db.add(user)
        db.flush()
        db.add(UserRole(user_id=user.id, role_id=roles[role].id))

    # ---- Clients ----
    contexts: list[ClientContext] = []
    client_password_hash = hash_secret(DEMO_PASSWORDS[RoleCode.CLIENT])
    for index, p in enumerate(CLIENTS):
        user = User(email=f"{p.login}@{DOMAIN}", first_name=p.first_name, last_name=p.last_name,
                    phone=f"+237 6{rng.randrange(10**7, 10**8)}", city=p.city,
                    address=f"{rng.randint(1, 200)} rue fictive, {p.city}", user_type=UserType.CUSTOMER,
                    password_hash=client_password_hash, password_changed_at=history_start,
                    created_at=history_start, updated_at=history_start)
        db.add(user)
        db.flush()
        db.add(UserRole(user_id=user.id, role_id=roles[RoleCode.CLIENT].id))

        current = _new_account(db, rng, used_numbers, user, "Compte courant", AccountType.CURRENT, p.city)
        post_transfer(db, debit_account_id=internal["EXTERNAL"].id, credit_account_id=current.id,
                      amount=p.opening, operation_type=LedgerOperation.OPENING, operation_id=None,
                      description="Dépôt d'ouverture", value_date=history_start)
        if p.savings:
            savings = _new_account(db, rng, used_numbers, user, "Compte épargne", AccountType.SAVINGS, p.city)
            post_transfer(db, debit_account_id=internal["EXTERNAL"].id, credit_account_id=savings.id,
                          amount=p.savings, operation_type=LedgerOperation.OPENING, operation_id=None,
                          description="Dépôt d'ouverture", value_date=history_start)
        if p.secondary:
            _new_account(db, rng, used_numbers, user, "Compte secondaire", AccountType.SECONDARY, p.city)

        last4 = f"{rng.randrange(10**4):04d}"
        card = Card(user_id=user.id, account_id=current.id, card_token=secrets.token_hex(24),
                    masked_pan=f"**** **** **** {last4}", last4=last4,
                    holder_name=f"{p.first_name} {p.last_name}".upper(),
                    card_type=CardType.PREMIUM if p.salary >= 600_000 else CardType.DEBIT,
                    expiry_month=rng.randint(1, 12), expiry_year=now.year + 3, pin_hash=hash_secret(DEMO_CARD_PIN))
        db.add(card)

        devices = []
        for n, spec in enumerate([p.device] + ([p.extra_device] if p.extra_device else [])):
            name, os_name, browser = spec
            d = Device(user_id=user.id, fingerprint_hash=device_fingerprint(f"seed:{p.login}:{n}"), name=name,
                       os=os_name, browser=browser, last_ip=f"10.20.{index}.{10 + n}", last_city=p.city,
                       last_country="CM", status=DeviceStatus.TRUSTED, first_seen=history_start,
                       last_seen=now, trusted_at=history_start, created_at=history_start)
            db.add(d)
            devices.append(d)
        db.flush()
        contexts.append(ClientContext(p, user, current, card, devices, [], ip=f"10.20.{index}.10"))

    # ---- Bénéficiaires : un client RL (virement interne) + deux externes fictifs ----
    for i, ctx in enumerate(contexts):
        other = contexts[(i + 1) % len(contexts)]
        beneficiaries = [Beneficiary(user_id=ctx.user.id, first_name=other.user.first_name,
                                     last_name=other.user.last_name, bank_name="RL EXPRESS BANK",
                                     iban=other.current.iban, internal_account_id=other.current.id)]
        for j in range(2):
            first, last = EXTERNAL_PEOPLE[(i * 2 + j) % len(EXTERNAL_PEOPLE)]
            bank_name, bank_code = EXTERNAL_BANKS[(i + j) % len(EXTERNAL_BANKS)]
            rib = build_rib(_account_number(rng, used_numbers), "Douala", bank_code=bank_code)
            beneficiaries.append(Beneficiary(user_id=ctx.user.id, first_name=first, last_name=last,
                                             bank_name=bank_name, iban=rib.iban))
        for b in beneficiaries:
            ensure_beneficiary_active(b, history_start)
        db.add_all(beneficiaries)
        ctx.beneficiaries = beneficiaries
    db.flush()

    # ---- Historique de 90 jours, puis profils comportementaux ----
    for i, ctx in enumerate(contexts):
        generate_history(db, ctx, internal, atms, random.Random(SEED + i), now)
        db.add(build_behavior_profile(ctx, atms))
        db.add(Notification(user_id=ctx.user.id, type="WELCOME", title="Bienvenue chez RL EXPRESS BANK",
                            body="Vos comptes sont prêts. RL EXPRESS BANK ne vous demandera jamais vos codes."))
    db.flush()

    summary = {"clients": len(contexts), "staff": len(STAFF), "atms": len(atms),
               "withdrawals": sum(len(c.withdrawals) for c in contexts),
               "payments": sum(len(c.payments) for c in contexts),
               "transfers": sum(len(c.transfers) for c in contexts)}
    record_audit(db, action="SEED_EXECUTED", target_type="platform", target_id=str(uuid.UUID(int=SEED)),
                 actor_type=ActorType.SYSTEM, after=summary,
                 justification="Initialisation des données de démonstration fictives")
    summary["seconds"] = round(time.perf_counter() - started, 1)
    return summary
