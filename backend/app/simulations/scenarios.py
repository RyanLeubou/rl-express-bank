"""Scénarios d'attaque de laboratoire, rejoués dans la vraie chaîne de détection.

Chaque étape construit un contexte d'opération, l'évalue avec le moteur de règles, enregistre l'évaluation,
émet l'événement (acteur SIMULATION, lié à l'exécution), crée l'alerte et applique les actions de la politique.
Aucun argent ne bouge : seules les réponses automatiques (carte verrouillée, appareil bloqué…) sont réelles,
et réversibles depuis le SOC.
"""
from __future__ import annotations

import hashlib
import secrets
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.events.catalog import EventType as E
from app.events.logger import emit
from app.models import ATM, Account, Beneficiary, Card, Device, SimulationRun, SupportConversation, User
from app.models.enums import (
    AccountType,
    ActorType,
    DeviceStatus,
    PolicyDecision,
    RiskOperation,
    SimulationStatus,
    UserType,
)
from app.risk import response as resp
from app.risk.context import OperationContext
from app.risk.engine import evaluate, save_assessment
from app.risk.geo import country_of
from app.risk.state import baseline_for
from app.services.banking.rib import build_rib

Op = RiskOperation


class Lab:
    def __init__(self, db: Session, run: SimulationRun, victim: User) -> None:
        self.db, self.run, self.victim = db, run, victim
        self.steps: list[dict[str, Any]] = []
        self.card = db.scalar(select(Card).where(Card.user_id == victim.id))
        self.account = db.scalar(select(Account).where(Account.user_id == victim.id,
                                                       Account.account_type == AccountType.CURRENT))

    def new_device(self, name: str = "Appareil inconnu (simulation)") -> Device:
        d = Device(user_id=self.victim.id, fingerprint_hash=hashlib.sha256(secrets.token_bytes(16)).hexdigest(),
                   name=name, os="Android", browser="Chrome", status=DeviceStatus.NEW, last_ip="198.51.100.9")
        self.db.add(d)
        self.db.flush()
        return d

    def step(self, title: str, op: Op, event: E, ok_event: E | None = None, *, user: User | None = None,
             city: str | None = None, device: Device | None = None, amount: int | None = None,
             atm: ATM | None = None, beneficiary: Beneficiary | None = None, extra: dict | None = None,
             target: User | None = None) -> dict[str, Any]:
        who = user or self.victim
        ctx = OperationContext(user=who, op=op, occurred_at=datetime.now(UTC), amount=amount,
                               account=self.account if who is self.victim else None, city=city,
                               country=country_of(city), device=device, ip="198.51.100.9", atm=atm,
                               beneficiary=beneficiary, extra=extra or {}, simulation_run_id=self.run.id,
                               target_user_id=target.id if target else None)
        result = evaluate(self.db, ctx, baseline=baseline_for(self.db, who.id))
        save_assessment(self.db, ctx, result)
        blocked = result.decision == PolicyDecision.BLOCK
        etype = event if (blocked or ok_event is None) else ok_event
        ev = emit(self.db, etype, actor_type=ActorType.SIMULATION, user_id=who.id,
                  device_id=device.id if device else None, ip_address="198.51.100.9", location=city,
                  country=country_of(city), amount=amount, atm_id=atm.id if atm else None,
                  risk_score=result.score, status="BLOCKED" if blocked else "SIMULATED",
                  simulation_run_id=self.run.id,
                  metadata={"scenario": self.run.scenario, "step": title, "reasons": result.reasons,
                            "customer_id": str(target.id) if target else None})
        alert = None
        if result.score >= 60 or blocked:
            alert = resp.raise_alert(self.db, user_id=who.id, title=f"[SIM] {title}", result=result, event=ev)
        if blocked:
            resp.run_policy_actions(self.db, result, who, card=self.card if who is self.victim else None,
                                    device=device, alert=alert)
        row = {"step": title, "score": result.score, "level": str(result.level), "decision": str(result.decision),
               "reasons": [r["code"] for r in result.reasons], "alert": bool(alert), "blocked": blocked}
        self.steps.append(row)
        return row


def _atm(db: Session, city: str) -> ATM | None:
    return db.scalar(select(ATM).where(ATM.city == city, ATM.status.in_(["ONLINE", "SUSPICIOUS"])))


def account_takeover(lab: Lab, _: dict) -> None:
    d = lab.new_device()
    for _i in range(4):
        lab.step("Échec de connexion", Op.LOGIN, E.LOGIN_FAILED, city="Lagos", device=d)
    lab.step("Connexion depuis un appareil inconnu à l'étranger", Op.LOGIN, E.NEW_DEVICE_LOGIN, E.USER_LOGIN,
             city="Lagos", device=d)
    iban = build_rib(f"{80000000000 + secrets.randbelow(10**6):011d}", bank_code="10001").iban
    mule = Beneficiary(user_id=lab.victim.id, first_name="Compte", last_name="Mule (sim)", bank_name="Banque X",
                       iban=iban, status="ACTIVE", activated_at=datetime.now(UTC))
    lab.db.add(mule)
    lab.db.flush()
    lab.step("Ajout d'un bénéficiaire", Op.BENEFICIARY, E.BENEFICIARY_VERIFICATION_FAILED, E.BENEFICIARY_CREATED,
             city="Lagos", device=d, beneficiary=mule)
    emit(lab.db, E.PASSWORD_CHANGED, actor_type=ActorType.SIMULATION, user_id=lab.victim.id,
         simulation_run_id=lab.run.id, ip_address="198.51.100.9", metadata={"step": "Mot de passe modifié"})
    amount = int((lab.account.balance if lab.account else 1_000_000) * 0.9)
    lab.step("Virement vidant le compte", Op.TRANSFER, E.TRANSFER_BLOCKED, E.UNUSUAL_TRANSFER_DETECTED, city="Lagos",
             device=d, amount=amount, beneficiary=mule)


def impossible_travel(lab: Lab, _: dict) -> None:
    home, far = _atm(lab.db, "Douala"), _atm(lab.db, "Yaoundé")
    lab.step("Retrait à Douala", Op.WITHDRAWAL_CARD, E.WITHDRAWAL_BLOCKED, E.ATM_WITHDRAWAL, city="Douala",
             atm=home, amount=40_000)
    lab.step("Retrait à Paris 10 minutes plus tard", Op.WITHDRAWAL_CARD, E.WITHDRAWAL_BLOCKED, E.ATM_WITHDRAWAL,
             city="Paris", amount=250_000, device=lab.new_device("Carte clonée (sim)"))
    lab.step("Retrait à Yaoundé aussitôt après", Op.WITHDRAWAL_CARD, E.WITHDRAWAL_BLOCKED, E.ATM_WITHDRAWAL,
             city="Yaoundé", atm=far, amount=200_000)


def cardless_fraud(lab: Lab, _: dict) -> None:
    d = lab.new_device()
    atm = _atm(lab.db, "Douala")
    for i in range(4):
        lab.step(f"Retrait sans carte n°{i + 1}", Op.WITHDRAWAL_CARDLESS, E.WITHDRAWAL_BLOCKED,
                 E.CARDLESS_WITHDRAWAL, city="Douala", atm=atm, device=d, amount=150_000 + i * 20_000)


def phishing_scam(lab: Lab, _: dict) -> None:
    lab.db.add(SupportConversation(user_id=lab.victim.id, topic="Arnaque (sim)", scam_signal=True))
    lab.db.flush()
    lab.step("Le client déclare avoir communiqué son code", Op.TRANSFER, E.SUPPORT_SCAM_SIGNAL_DETECTED,
             E.SUPPORT_SCAM_SIGNAL_DETECTED, city="Douala", amount=10_000)
    iban = build_rib(f"{81000000000 + secrets.randbelow(10**6):011d}", bank_code="10001").iban
    b = Beneficiary(user_id=lab.victim.id, first_name="Inconnu", last_name="(sim)", bank_name="Banque Y", iban=iban,
                    status="ACTIVE", activated_at=datetime.now(UTC))
    lab.db.add(b)
    lab.db.flush()
    lab.step("Virement vers un bénéficiaire frais", Op.TRANSFER, E.TRANSFER_BLOCKED, E.UNUSUAL_TRANSFER_DETECTED,
             city="Douala", amount=int((lab.account.balance if lab.account else 500_000) * 0.85), beneficiary=b,
             device=lab.new_device("Téléphone (sim)"))


def mule_network(lab: Lab, _: dict) -> None:
    iban = build_rib(f"{82000000000 + secrets.randbelow(10**6):011d}", bank_code="10001").iban
    others = list(lab.db.scalars(select(User).where(User.user_type == UserType.CUSTOMER, User.id != lab.victim.id)
                                 .limit(4)))
    for other in [lab.victim, *others]:
        b = Beneficiary(user_id=other.id, first_name="Compte", last_name="Collecteur (sim)", bank_name="Banque Z",
                        iban=iban, status="ACTIVE", activated_at=datetime.now(UTC))
        lab.db.add(b)
        lab.db.flush()
        lab.step(f"Virement de {other.first_name} vers le compte collecteur", Op.TRANSFER, E.TRANSFER_BLOCKED,
                 E.UNUSUAL_TRANSFER_DETECTED, user=other, city=other.city, amount=300_000, beneficiary=b)


def insider_bulk_access(lab: Lab, params: dict) -> None:
    agent = lab.db.scalar(select(User).where(User.email.like("support1@%")))
    customers = list(lab.db.scalars(select(User).where(User.user_type == UserType.CUSTOMER)))
    for i in range(10):
        c = customers[i % len(customers)]
        emit(lab.db, E.STAFF_CUSTOMER_ACCESSED, actor_type=ActorType.SIMULATION, user_id=agent.id,
             simulation_run_id=lab.run.id, metadata={"customer_id": str(c.id), "purpose": "sim"})
    lab.step("Consultation en rafale de dossiers clients", Op.SUPPORT_ACTION, E.STAFF_PRIVILEGE_ABUSE_DETECTED,
             E.STAFF_BULK_ACCESS_DETECTED, user=agent, target=customers[0], extra={"assigned": False})


SCENARIOS: dict[str, tuple[str, Callable[[Lab, dict], None]]] = {
    "account_takeover": ("Prise de contrôle de compte : appareil inconnu, bénéficiaire frais, virement massif",
                         account_takeover),
    "impossible_travel": ("Clonage de carte : retraits dans des villes éloignées en quelques minutes",
                          impossible_travel),
    "cardless_fraud": ("Fraude au retrait sans carte : rafale de retraits depuis un appareil inconnu",
                       cardless_fraud),
    "phishing_scam": ("Hameçonnage : le client communique son code puis un virement suspect part",
                      phishing_scam),
    "mule_network": ("Réseau de mules : plusieurs clients virent vers le même compte collecteur", mule_network),
    "insider_bulk_access": ("Menace interne : un agent consulte 10 dossiers clients en rafale",
                            insider_bulk_access),
}


def run_scenario(db: Session, scenario: str, victim: User, launched_by: User, params: dict) -> SimulationRun:
    run = SimulationRun(id=uuid.uuid4(), scenario=scenario, launched_by=launched_by.id, parameters=params)
    db.add(run)
    db.flush()
    emit(db, E.SIMULATION_STARTED, actor_type=ActorType.SIMULATION, user_id=victim.id, simulation_run_id=run.id,
         metadata={"scenario": scenario})
    lab = Lab(db, run, victim)
    try:
        SCENARIOS[scenario][1](lab, params)
        run.status = SimulationStatus.COMPLETED
    except Exception as exc:  # noqa: BLE001 - une simulation en échec doit rester consultable
        run.status = SimulationStatus.FAILED
        lab.steps.append({"error": type(exc).__name__})
        raise
    finally:
        run.ended_at = datetime.now(UTC)
        run.summary = {"steps": lab.steps, "alerts": sum(1 for s in lab.steps if s.get("alert")),
                       "blocked": sum(1 for s in lab.steps if s.get("blocked"))}
    emit(db, E.SIMULATION_COMPLETED, actor_type=ActorType.SIMULATION, user_id=victim.id, simulation_run_id=run.id,
         metadata=run.summary)
    return run
