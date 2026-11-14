"""Opérations bancaires du client : bénéficiaires, virements, paiements carte, retraits, step-up.

Chaque opération suit le même chemin :
    1. contrôles métier (propriété, statut, plafonds, solde) ;
    2. évaluation du risque (règles explicables) -> décision de politique ;
    3. BLOCK : opération refusée, alerte SOC et actions automatiques ;
       STEP_UP : défi TOTP lié à l'opération (charge utile dans Valkey, 5 min) ;
       sinon : exécution immédiate.
Une décision STEP_UP_PASSKEY est servie par le TOTP tant que les passkeys ne sont pas intégrées (documenté).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import redis
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.events.audit import record_audit
from app.events.catalog import EventType as E
from app.events.logger import emit
from app.models import (
    ATM,
    Account,
    Beneficiary,
    Card,
    CardlessCode,
    CardPayment,
    Device,
    MFAConfiguration,
    StepUpChallenge,
    Transfer,
    User,
    Withdrawal,
)
from app.models import Session as AuthSession
from app.models.enums import (
    AccountStatus,
    AccountType,
    ActorType,
    AtmStatus,
    BeneficiaryStatus,
    CardlessCodeStatus,
    CardStatus,
    ChallengeStatus,
    DeviceStatus,
    HoldStatus,
    LedgerOperation,
    MerchantCategory,
    PaymentStatus,
    PolicyDecision,
    RiskOperation,
    Severity,
    StepUpMethod,
    TransferStatus,
    WithdrawalStatus,
    WithdrawalType,
)
from app.risk import response as resp
from app.risk.context import OperationContext
from app.risk.engine import RiskResult, evaluate, save_assessment
from app.risk.geo import CITIES, country_of
from app.risk.policy import needs_step_up
from app.security.auth.errors import AuthError
from app.security.auth.passwords import verify_secret
from app.security.mfa import totp
from app.security.ratelimit.throttle import ProgressiveThrottle, mfa_buckets
from app.services.banking.holds import create_hold, release_hold
from app.services.banking.ledger import LedgerError, post_transfer
from app.services.banking.rib import iban_is_valid

STEP_UP_TTL = 300
CODE_TTL = timedelta(minutes=15)
PREFIX = "rlbank:stepup:"
Op = RiskOperation


@dataclass
class Caller:
    user: User
    session: AuthSession
    device: Device | None
    ip: str | None
    ua: str | None = None


@dataclass
class Outcome:
    status: str                      # completed | step_up_required | blocked
    data: dict[str, Any]
    challenge_id: uuid.UUID | None = None


def _now() -> datetime:
    return datetime.now(UTC)


def _fail(status: int, code: str, detail: str) -> AuthError:
    return AuthError(status, code, detail)


class BankingService:
    def __init__(self, db: Session, settings: Settings, valkey: redis.Redis, caller: Caller) -> None:
        self.db, self.settings, self.valkey, self.c = db, settings, valkey, caller
        self.throttle = ProgressiveThrottle(valkey, settings)

    # ------------------------------------------------------------------ utilitaires
    @property
    def user(self) -> User:
        return self.c.user

    def _city(self, simulated: str | None) -> str | None:
        if simulated and self.settings.lab_mode and simulated in CITIES:
            return simulated
        return (self.c.device.last_city if self.c.device and self.c.device.last_city else self.user.city)

    def _fields(self, city: str | None = None) -> dict[str, Any]:
        d = self.c.device
        return dict(user_id=self.user.id, session_id=self.c.session.id, device_id=d.id if d else None,
                    ip_address=self.c.ip, device=d.name if d else None, os=d.os if d else None,
                    browser=d.browser if d else None, location=city, country=country_of(city) or "CM")

    def _own_account(self, account_id: uuid.UUID) -> Account:
        acc = self.db.get(Account, account_id)
        if acc is None or acc.user_id != self.user.id or acc.account_type == AccountType.INTERNAL:
            raise _fail(404, "account_not_found", "Compte introuvable.")
        if acc.status != AccountStatus.ACTIVE:
            raise _fail(409, "account_inactive", "Ce compte n'est pas actif.")
        return acc

    def _internal(self, label: str) -> Account:
        acc = self.db.scalar(select(Account).where(Account.account_type == AccountType.INTERNAL,
                                                   Account.label == label))
        if acc is None:
            raise _fail(500, "internal_account_missing", "Configuration bancaire incomplète.")
        return acc

    def _context(self, op: Op, *, city: str | None, **kw: Any) -> OperationContext:
        return OperationContext(user=self.user, op=op, session=self.c.session, device=self.c.device, ip=self.c.ip,
                                city=city, country=country_of(city), **kw)

    def _idempotent(self, model: type, key: str | None):
        if not key:
            return None
        return self.db.scalar(select(model).where(model.user_id == self.user.id, model.idempotency_key == key))

    # ------------------------------------------------------------------ défis step-up
    def _challenge(self, op: Op, kind: str, operation_id: uuid.UUID | None, data: dict[str, Any],
                   result: RiskResult) -> uuid.UUID:
        payload = json.dumps({"kind": kind, "data": data, "user": str(self.user.id)}, sort_keys=True, default=str)
        ch = StepUpChallenge(user_id=self.user.id, session_id=self.c.session.id, operation_type=op,
                             operation_id=operation_id, payload_hash=hashlib.sha256(payload.encode()).hexdigest(),
                             required_method=StepUpMethod.TOTP, expires_at=_now() + timedelta(seconds=STEP_UP_TTL))
        self.db.add(ch)
        self.db.flush()
        self.valkey.setex(PREFIX + str(ch.id), STEP_UP_TTL, payload)
        emit(self.db, E.STEP_UP_REQUIRED, metadata={"operation": str(op), "decision": str(result.decision),
                                                      "score": result.score}, **self._fields())
        return ch.id

    def _gate(self, ctx: OperationContext, result: RiskResult, kind: str, operation_id: uuid.UUID | None,
              data: dict[str, Any]) -> tuple[str, uuid.UUID | None]:
        if result.decision == PolicyDecision.BLOCK:
            return "blocked", None
        if needs_step_up(result.decision):
            return "step_up_required", self._challenge(ctx.op, kind, operation_id, data, result)
        return "execute", None

    def _on_block(self, ctx: OperationContext, result: RiskResult, title: str, event: E, *, card: Card | None = None,
                  **link: Any) -> None:
        city = ctx.city
        ev = emit(self.db, event, risk_score=result.score, status="BLOCKED", amount=ctx.amount,
                  metadata={"reasons": result.reasons, "level": str(result.level)}, **link, **self._fields(city))
        alert = resp.raise_alert(self.db, user_id=self.user.id, title=title, result=result, event=ev)
        resp.run_policy_actions(self.db, result, self.user, card=card, session=self.c.session, device=self.c.device,
                                alert=alert)

    def _monitor(self, ctx: OperationContext, result: RiskResult, title: str, **link: Any) -> None:
        """Opération autorisée mais suspecte (MEDIUM+) : événement et alerte pour le SOC."""
        if result.score >= self.settings.risk_medium_from:
            ev = emit(self.db, E.UNUSUAL_TRANSFER_DETECTED if ctx.op == Op.TRANSFER else E.UNUSUAL_WITHDRAWAL_DETECTED,
                      risk_score=result.score, amount=ctx.amount, metadata={"reasons": result.reasons},
                      **link, **self._fields(ctx.city))
            if result.score >= self.settings.risk_high_from:
                resp.raise_alert(self.db, user_id=self.user.id, title=title, result=result, event=ev)

    # ------------------------------------------------------------------ vérification du step-up
    def verify_step_up(self, challenge_id: uuid.UUID, code: str) -> Outcome:
        ch = self.db.scalar(select(StepUpChallenge).where(StepUpChallenge.id == challenge_id).with_for_update())
        if (ch is None or ch.user_id != self.user.id or ch.session_id != self.c.session.id
                or ch.status != ChallengeStatus.PENDING or ch.expires_at <= _now()):
            raise _fail(404, "challenge_invalid", "Vérification expirée ou introuvable.")
        buckets = mfa_buckets(self.settings, str(self.user.id), self.c.ip)
        wait, _ = self.throttle.check(buckets)
        if wait:
            raise AuthError(429, "too_many_attempts", "Trop de tentatives. Patientez avant de réessayer.",
                            headers={"Retry-After": str(wait)})
        cfg = self.db.scalar(select(MFAConfiguration).where(MFAConfiguration.user_id == self.user.id).with_for_update())
        step = None
        if cfg and cfg.enabled and cfg.totp_secret_encrypted and totp.is_totp_format(code.strip()):
            secret = totp.decrypt_secret(self.settings, cfg.totp_secret_encrypted, self.user.id)
            step = totp.verify_totp(secret, code.strip(), cfg.last_used_step)
        if step is None:
            self.throttle.fail(buckets)
            ch.attempts += 1
            if ch.attempts >= 5:
                ch.status = ChallengeStatus.FAILED
            emit(self.db, E.STEP_UP_FAILED, metadata={"operation": str(ch.operation_type),
                                                        "attempts": ch.attempts}, **self._fields())
            self.db.commit()
            raise _fail(401, "invalid_code", "Code incorrect ou expiré.")
        cfg.last_used_step = step
        self.throttle.reset(buckets)
        raw = self.valkey.getdel(PREFIX + str(ch.id))
        if raw is None or hashlib.sha256(raw.encode()).hexdigest() != ch.payload_hash:
            ch.status = ChallengeStatus.EXPIRED
            self.db.commit()
            raise _fail(410, "challenge_expired", "L'opération a expiré. Recommencez.")
        ch.status, ch.verified_at = ChallengeStatus.CONSUMED, _now()
        payload = json.loads(raw)
        emit(self.db, E.STEP_UP_VERIFIED, metadata={"operation": str(ch.operation_type)}, **self._fields())
        data = payload["data"]
        runner = {"beneficiary": self._finish_beneficiary, "transfer": self._finish_transfer,
                  "payment": self._finish_payment, "withdrawal_card": self._finish_withdrawal_card,
                  "withdrawal_cardless": self._finish_cardless, "security": self._finish_security}[payload["kind"]]
        outcome = runner(data)
        self.db.commit()
        return outcome

    # ------------------------------------------------------------------ bénéficiaires
    def add_beneficiary(self, first_name: str, last_name: str, bank_name: str, iban: str,
                        simulated_city: str | None = None) -> Outcome:
        iban = iban.replace(" ", "").upper()
        if not iban_is_valid(iban):
            raise _fail(422, "invalid_iban", "IBAN invalide.")
        if self.db.scalar(select(Beneficiary.id).where(
                Beneficiary.user_id == self.user.id, Beneficiary.iban == iban,
                Beneficiary.status != BeneficiaryStatus.DELETED)):
            raise _fail(409, "beneficiary_exists", "Ce bénéficiaire existe déjà.")
        internal = self.db.scalar(select(Account).where(
            Account.iban == iban, Account.account_type != AccountType.INTERNAL))
        if internal is not None and internal.user_id == self.user.id:
            raise _fail(422, "own_account", "Utilisez un virement entre vos comptes.")
        city = self._city(simulated_city)
        b = Beneficiary(user_id=self.user.id, first_name=first_name.strip(), last_name=last_name.strip(),
                        bank_name=bank_name.strip(), iban=iban, internal_account_id=internal.id if internal else None)
        self.db.add(b)
        self.db.flush()
        emit(self.db, E.BENEFICIARY_CREATION_STARTED, beneficiary_id=b.id, **self._fields(city))
        return self._beneficiary_gate(b, city, created=True)

    def verify_beneficiary(self, beneficiary_id: uuid.UUID, simulated_city: str | None = None) -> Outcome:
        """Relance la vérification d'un bénéficiaire resté en attente (code non saisi, défi expiré…)."""
        b = self.db.get(Beneficiary, beneficiary_id)
        if b is None or b.user_id != self.user.id or b.status == BeneficiaryStatus.DELETED:
            raise _fail(404, "beneficiary_not_found", "Bénéficiaire introuvable.")
        if b.status != BeneficiaryStatus.PENDING_VERIFICATION:
            raise _fail(409, "beneficiary_not_pending", "Ce bénéficiaire est déjà vérifié.")
        return self._beneficiary_gate(b, self._city(simulated_city), created=False)

    def _beneficiary_gate(self, b: Beneficiary, city: str, *, created: bool) -> Outcome:
        """Évaluation du risque puis défi TOTP (ou blocage) avant l'activation d'un bénéficiaire."""
        ctx = self._context(Op.BENEFICIARY, city=city, beneficiary=b)
        result = evaluate(self.db, ctx)
        save_assessment(self.db, ctx, result)
        verdict, cid = self._gate(ctx, result, "beneficiary", b.id, {"beneficiary_id": str(b.id)})
        if verdict == "blocked":
            b.status, b.deleted_at = BeneficiaryStatus.DELETED, _now()
            self._on_block(ctx, result, "Ajout de bénéficiaire bloqué", E.BENEFICIARY_VERIFICATION_FAILED,
                           beneficiary_id=b.id)
            self.db.commit()
            raise _fail(403, "operation_blocked", "Opération refusée par mesure de sécurité.")
        if created:
            emit(self.db, E.BENEFICIARY_CREATED, beneficiary_id=b.id, risk_score=result.score, **self._fields(city))
        if verdict == "execute":      # la politique impose un plancher TOTP ; ceci ne se produit que si désactivé
            out = self._finish_beneficiary({"beneficiary_id": str(b.id)})
            self.db.commit()
            return out
        self.db.commit()
        return Outcome("step_up_required", {"beneficiary_id": str(b.id)}, cid)

    def _finish_beneficiary(self, data: dict) -> Outcome:
        b = self.db.get(Beneficiary, uuid.UUID(data["beneficiary_id"]))
        b.status, b.activated_at = BeneficiaryStatus.ACTIVE, _now()
        emit(self.db, E.BENEFICIARY_VERIFICATION_SUCCESS, beneficiary_id=b.id, **self._fields())
        emit(self.db, E.BENEFICIARY_ACTIVATED, beneficiary_id=b.id, **self._fields())
        return Outcome("completed", {"beneficiary_id": str(b.id), "status": "ACTIVE"})

    def delete_beneficiary(self, beneficiary_id: uuid.UUID) -> None:
        b = self.db.get(Beneficiary, beneficiary_id)
        if b is None or b.user_id != self.user.id or b.status == BeneficiaryStatus.DELETED:
            raise _fail(404, "beneficiary_not_found", "Bénéficiaire introuvable.")
        b.status, b.deleted_at = BeneficiaryStatus.DELETED, _now()
        emit(self.db, E.BENEFICIARY_DELETED, beneficiary_id=b.id, **self._fields())
        self.db.commit()

    # ------------------------------------------------------------------ virements
    def create_transfer(self, source_account_id: uuid.UUID, beneficiary_id: uuid.UUID, amount: int, reference: str,
                        idempotency_key: str | None = None, simulated_city: str | None = None) -> Outcome:
        if (prior := self._idempotent(Transfer, idempotency_key)) is not None:
            return Outcome({"COMPLETED": "completed", "PENDING": "step_up_required"}.get(prior.status, "blocked"),
                           {"transfer_id": str(prior.id), "status": prior.status, "replayed": True})
        src = self._own_account(source_account_id)
        b = self.db.get(Beneficiary, beneficiary_id)
        if b is None or b.user_id != self.user.id or b.status != BeneficiaryStatus.ACTIVE:
            raise _fail(404, "beneficiary_not_found", "Bénéficiaire introuvable ou non activé.")
        if amount > src.available_balance:
            raise _fail(409, "insufficient_funds", "Solde disponible insuffisant.")
        city = self._city(simulated_city)
        t = Transfer(user_id=self.user.id, source_account_id=src.id, beneficiary_id=b.id,
                     destination_account_id=b.internal_account_id, amount=amount, reference=reference.strip(),
                     status=TransferStatus.PENDING, idempotency_key=idempotency_key,
                     device_id=self.c.device.id if self.c.device else None)
        self.db.add(t)
        self.db.flush()
        emit(self.db, E.TRANSFER_CREATED, transfer_id=t.id, beneficiary_id=b.id, amount=amount, **self._fields(city))
        ctx = self._context(Op.TRANSFER, city=city, amount=amount, account=src, beneficiary=b)
        result = evaluate(self.db, ctx)
        save_assessment(self.db, ctx, result, transfer_id=t.id)
        t.risk_score, t.risk_level = result.score, result.level
        verdict, cid = self._gate(ctx, result, "transfer", t.id, {"transfer_id": str(t.id)})
        if verdict == "blocked":
            t.status, t.failure_reason = TransferStatus.BLOCKED, "Bloqué par la politique de sécurité"
            self._on_block(ctx, result, "Virement bloqué", E.TRANSFER_BLOCKED, transfer_id=t.id, beneficiary_id=b.id)
            self.db.commit()
            raise _fail(403, "operation_blocked", "Opération refusée par mesure de sécurité.")
        if verdict == "step_up_required":
            self._monitor(ctx, result, "Virement inhabituel en attente de confirmation", transfer_id=t.id)
            self.db.commit()
            return Outcome("step_up_required", {"transfer_id": str(t.id), "risk_level": str(result.level)}, cid)
        self._monitor(ctx, result, "Virement inhabituel autorisé", transfer_id=t.id)
        out = self._finish_transfer({"transfer_id": str(t.id)})
        self.db.commit()
        return out

    def _finish_transfer(self, data: dict) -> Outcome:
        t = self.db.get(Transfer, uuid.UUID(data["transfer_id"]), with_for_update=True)
        if t.status != TransferStatus.PENDING:
            raise _fail(409, "already_processed", "Opération déjà traitée.")
        try:
            post_transfer(self.db, debit_account_id=t.source_account_id,
                          credit_account_id=t.destination_account_id or self._internal("Compensation interbancaire").id,
                          amount=t.amount, operation_type=LedgerOperation.TRANSFER, operation_id=t.id,
                          description=f"Virement {t.reference}")
        except LedgerError as exc:
            t.status, t.failure_reason = TransferStatus.FAILED, exc.args[0]
            emit(self.db, E.TRANSFER_FAILED, transfer_id=t.id, amount=t.amount, **self._fields())
            self.db.commit()
            raise _fail(409, exc.code, str(exc)) from exc
        t.status, t.executed_at = TransferStatus.COMPLETED, _now()
        emit(self.db, E.TRANSFER_COMPLETED, transfer_id=t.id, beneficiary_id=t.beneficiary_id, amount=t.amount,
             status="COMPLETED", risk_score=t.risk_score, **self._fields(self.user.city))
        return Outcome("completed", {"transfer_id": str(t.id), "status": "COMPLETED"})

    def cancel_transfer(self, transfer_id: uuid.UUID) -> None:
        t = self.db.get(Transfer, transfer_id)
        if t is None or t.user_id != self.user.id or t.status != TransferStatus.PENDING:
            raise _fail(404, "transfer_not_found", "Virement en attente introuvable.")
        t.status = TransferStatus.CANCELLED
        self.db.commit()

    # ------------------------------------------------------------------ paiements par carte
    def _spent_today(self, model, column, key: str, value: uuid.UUID, statuses: tuple) -> int:
        day = _now().replace(hour=0, minute=0, second=0, microsecond=0)
        return self.db.scalar(select(func.coalesce(func.sum(column), 0)).where(
            getattr(model, key) == value, model.status.in_(statuses), model.created_at >= day)) or 0

    def _own_card(self, card_id: uuid.UUID) -> Card:
        card = self.db.get(Card, card_id)
        if card is None or card.user_id != self.user.id:
            raise _fail(404, "card_not_found", "Carte introuvable.")
        if card.status != CardStatus.ACTIVE:
            raise _fail(409, "card_blocked", "Carte bloquée ou expirée.")
        return card

    def pay_by_card(self, card_id: uuid.UUID, amount: int, merchant: str, category: MerchantCategory,
                    city: str, idempotency_key: str | None = None) -> Outcome:
        if (prior := self._idempotent(CardPayment, idempotency_key)) is not None:
            return Outcome("completed" if prior.status == PaymentStatus.APPROVED else "blocked",
                           {"payment_id": str(prior.id), "status": prior.status, "replayed": True})
        card = self._own_card(card_id)
        acc = self._own_account(card.account_id)
        if city not in CITIES:
            raise _fail(422, "unknown_city", "Ville inconnue du simulateur.")
        spent = self._spent_today(CardPayment, CardPayment.amount, "card_id", card.id, (PaymentStatus.APPROVED,))
        if spent + amount > card.daily_payment_limit:
            raise _fail(409, "limit_exceeded", "Plafond de paiement journalier atteint.")
        if amount > acc.available_balance:
            raise _fail(409, "insufficient_funds", "Solde disponible insuffisant.")
        ctx = self._context(Op.CARD_PAYMENT, city=city, amount=amount, account=acc, merchant=merchant)
        result = evaluate(self.db, ctx)
        data = {"card_id": str(card.id), "amount": amount, "merchant": merchant, "category": str(category),
                "city": city, "idem": idempotency_key, "score": result.score, "level": str(result.level)}
        emit(self.db, E.CARD_PAYMENT_CREATED, amount=amount, **self._fields(city))
        verdict, cid = self._gate(ctx, result, "payment", None, data)
        if verdict == "blocked":
            pay = self._record_payment(data, PaymentStatus.BLOCKED, "Bloqué par la politique de sécurité")
            save_assessment(self.db, ctx, result, card_payment_id=pay.id)
            self._on_block(ctx, result, "Paiement par carte bloqué", E.CARD_PAYMENT_BLOCKED, card=card,
                           card_payment_id=pay.id)
            self.db.commit()
            raise _fail(403, "operation_blocked", "Opération refusée par mesure de sécurité.")
        if verdict == "step_up_required":
            save_assessment(self.db, ctx, result)
            self.db.commit()
            return Outcome("step_up_required", {"risk_level": str(result.level)}, cid)
        out = self._finish_payment(data)
        save_assessment(self.db, ctx, result, card_payment_id=uuid.UUID(out.data["payment_id"]))
        self.db.commit()
        return out

    def _record_payment(self, d: dict, status: PaymentStatus, reason: str | None = None) -> CardPayment:
        card = self.db.get(Card, uuid.UUID(d["card_id"]))
        pay = CardPayment(card_id=card.id, account_id=card.account_id, user_id=self.user.id,
                          merchant_name=d["merchant"][:120], category=MerchantCategory(d["category"]),
                          country=country_of(d["city"]) or "CM", city=d["city"], amount=d["amount"], status=status,
                          decline_reason=reason, risk_score=d.get("score"), idempotency_key=d.get("idem"))
        self.db.add(pay)
        self.db.flush()
        return pay

    def _finish_payment(self, d: dict) -> Outcome:
        card = self._own_card(uuid.UUID(d["card_id"]))
        pay = self._record_payment(d, PaymentStatus.APPROVED)
        try:
            post_transfer(self.db, debit_account_id=card.account_id,
                          credit_account_id=self._internal("Règlement cartes").id,
                          amount=pay.amount, operation_type=LedgerOperation.CARD_PAYMENT, operation_id=pay.id,
                          description=f"Paiement {pay.merchant_name}")
        except LedgerError as exc:
            pay.status, pay.decline_reason = PaymentStatus.DECLINED, exc.code
            emit(self.db, E.CARD_PAYMENT_DECLINED, card_payment_id=pay.id, amount=pay.amount, **self._fields())
            self.db.commit()
            raise _fail(409, exc.code, str(exc)) from exc
        emit(self.db, E.CARD_PAYMENT_APPROVED, card_payment_id=pay.id, amount=pay.amount, status="APPROVED",
             risk_score=pay.risk_score, **self._fields(pay.city))
        return Outcome("completed", {"payment_id": str(pay.id), "status": "APPROVED"})

    # ------------------------------------------------------------------ retraits
    def withdraw(self, wtype: WithdrawalType, account_id: uuid.UUID, amount: int, *, atm_id: uuid.UUID | None = None,
                 card_id: uuid.UUID | None = None, pin: str | None = None, idempotency_key: str | None = None,
                 simulated_city: str | None = None) -> Outcome:
        if (prior := self._idempotent(Withdrawal, idempotency_key)) is not None:
            return Outcome("completed" if prior.status == WithdrawalStatus.APPROVED else "blocked",
                           {"withdrawal_id": str(prior.id), "status": prior.status, "replayed": True})
        acc = self._own_account(account_id)
        card: Card | None = None
        atm: ATM | None = None
        if wtype == WithdrawalType.CARD:
            if card_id is None or pin is None or atm_id is None:
                raise _fail(422, "card_withdrawal_incomplete", "Carte, PIN et ATM requis.")
            card = self._own_card(card_id)
            if card.account_id != acc.id:
                raise _fail(409, "card_account_mismatch", "Cette carte n'est pas liée à ce compte.")
            atm = self._usable_atm(atm_id)
            self._check_pin(card, pin)
        limit_card = card or self.db.scalar(select(Card).where(Card.user_id == self.user.id, Card.account_id == acc.id))
        if limit_card is not None:
            used = self._spent_today(Withdrawal, Withdrawal.amount, "account_id", acc.id,
                                     (WithdrawalStatus.APPROVED, WithdrawalStatus.PENDING))
            if used + amount > limit_card.daily_withdrawal_limit:
                raise _fail(409, "limit_exceeded", "Plafond de retrait journalier atteint.")
        if amount > acc.available_balance:
            raise _fail(409, "insufficient_funds", "Solde disponible insuffisant.")
        op = Op.WITHDRAWAL_CARD if wtype == WithdrawalType.CARD else Op.WITHDRAWAL_CARDLESS
        city = atm.city if atm else self._city(simulated_city)
        w = Withdrawal(user_id=self.user.id, account_id=acc.id, card_id=card.id if card else None,
                       atm_id=None, withdrawal_type=wtype, amount=amount, city=city, country=country_of(city),
                       device_id=self.c.device.id if self.c.device else None, status=WithdrawalStatus.PENDING,
                       authentication_method="PIN" if card else None, idempotency_key=idempotency_key)
        self.db.add(w)
        self.db.flush()
        emit(self.db, E.WITHDRAWAL_CREATED, withdrawal_id=w.id, amount=amount, atm_id=atm.id if atm else None,
             **self._fields(city))
        ctx = self._context(op, city=city, amount=amount, account=acc, atm=atm)
        result = evaluate(self.db, ctx)
        save_assessment(self.db, ctx, result, withdrawal_id=w.id)
        w.risk_score, w.risk_level = result.score, result.level
        kind = "withdrawal_card" if card else "withdrawal_cardless"
        verdict, cid = self._gate(ctx, result, kind, w.id,
                                  {"withdrawal_id": str(w.id), "atm_id": str(atm.id) if atm else None})
        if verdict == "blocked":
            w.status, w.decline_reason = WithdrawalStatus.BLOCKED, "security_policy"
            self._on_block(ctx, result, "Retrait bloqué", E.WITHDRAWAL_BLOCKED, card=card, withdrawal_id=w.id,
                           atm_id=atm.id if atm else None)
            self.db.commit()
            raise _fail(403, "operation_blocked", "Opération refusée par mesure de sécurité.")
        self._monitor(ctx, result, "Retrait inhabituel", withdrawal_id=w.id)
        if verdict == "step_up_required":
            emit(self.db, E.WITHDRAWAL_AUTHENTICATION_STARTED, withdrawal_id=w.id, **self._fields(city))
            self.db.commit()
            return Outcome("step_up_required", {"withdrawal_id": str(w.id), "risk_level": str(result.level)}, cid)
        out = self._finish_cardless_or_card(kind, {"withdrawal_id": str(w.id), "atm_id": str(atm.id) if atm else None})
        self.db.commit()
        return out

    def _finish_cardless_or_card(self, kind: str, data: dict) -> Outcome:
        return self._finish_withdrawal_card(data) if kind == "withdrawal_card" else self._finish_cardless(data)

    def _usable_atm(self, atm_id: uuid.UUID) -> ATM:
        atm = self.db.get(ATM, atm_id)
        if atm is None:
            raise _fail(404, "atm_not_found", "Distributeur introuvable.")
        if atm.status not in (AtmStatus.ONLINE, AtmStatus.SUSPICIOUS):
            raise _fail(409, "atm_unavailable", "Distributeur indisponible.")
        return atm

    def _check_pin(self, card: Card, pin: str) -> None:
        if verify_secret(card.pin_hash, pin):
            card.pin_failed_attempts = 0
            return
        card.pin_failed_attempts += 1
        emit(self.db, E.WITHDRAWAL_AUTHENTICATION_FAILED, metadata={"attempts": card.pin_failed_attempts},
             **self._fields())
        if card.pin_failed_attempts >= 3:
            card.status, card.blocked_reason = CardStatus.BLOCKED, "PIN_ATTEMPTS"
            emit(self.db, E.CARD_BLOCKED, severity=Severity.MEDIUM, metadata={"reason": "PIN_ATTEMPTS"},
                 **self._fields())
        self.db.commit()
        raise _fail(401, "invalid_pin", "PIN incorrect.")

    def _finish_withdrawal_card(self, d: dict) -> Outcome:
        w = self.db.get(Withdrawal, uuid.UUID(d["withdrawal_id"]), with_for_update=True)
        atm = self._usable_atm(uuid.UUID(d["atm_id"]))
        if w.status != WithdrawalStatus.PENDING:
            raise _fail(409, "already_processed", "Opération déjà traitée.")
        try:
            post_transfer(self.db, debit_account_id=w.account_id, credit_account_id=self._internal("Règlement ATM").id,
                          amount=w.amount, operation_type=LedgerOperation.WITHDRAWAL, operation_id=w.id,
                          description=f"Retrait {atm.atm_code}")
        except LedgerError as exc:
            w.status, w.decline_reason = WithdrawalStatus.DECLINED, exc.code
            emit(self.db, E.WITHDRAWAL_DECLINED, withdrawal_id=w.id, **self._fields())
            self.db.commit()
            raise _fail(409, exc.code, str(exc)) from exc
        w.status, w.atm_id = WithdrawalStatus.APPROVED, atm.id
        ev = emit(self.db, E.ATM_WITHDRAWAL, actor_type=ActorType.ATM, withdrawal_id=w.id, atm_id=atm.id,
                  amount=w.amount, status="APPROVED", risk_score=w.risk_score, **self._fields(atm.city))
        self.db.flush()
        w.security_event_id = ev.id
        return Outcome("completed", {"withdrawal_id": str(w.id), "status": "APPROVED"})

    def _code_hmac(self, reference: str, code: str) -> str:
        key = self.settings.cardless_hmac_key.get_secret_value().encode()
        return hmac.new(key, f"{reference}:{code}".encode(), hashlib.sha256).hexdigest()

    def _finish_cardless(self, d: dict) -> Outcome:
        w = self.db.get(Withdrawal, uuid.UUID(d["withdrawal_id"]), with_for_update=True)
        if w.status != WithdrawalStatus.PENDING:
            raise _fail(409, "already_processed", "Opération déjà traitée.")
        try:
            hold = create_hold(self.db, w.account_id, w.amount, "CARDLESS_WITHDRAWAL", w.id, _now() + CODE_TTL)
        except LedgerError as exc:
            w.status, w.decline_reason = WithdrawalStatus.DECLINED, exc.code
            self.db.commit()
            raise _fail(409, exc.code, str(exc)) from exc
        reference = "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(8))
        code = f"{secrets.randbelow(10**6):06d}"
        self.db.add(CardlessCode(withdrawal_id=w.id, user_id=self.user.id, account_id=w.account_id, hold_id=hold.id,
                                 reference=reference, code_hmac=self._code_hmac(reference, code), amount=w.amount,
                                 expires_at=hold.expires_at))
        w.authentication_method = "TOTP"
        emit(self.db, E.WITHDRAWAL_AUTHENTICATION_SUCCESS, withdrawal_id=w.id, **self._fields())
        emit(self.db, E.CARDLESS_CODE_CREATED, withdrawal_id=w.id, amount=w.amount, **self._fields())
        return Outcome("completed", {"withdrawal_id": str(w.id), "status": "PENDING", "reference": reference,
                                     "code": code, "expires_at": hold.expires_at.isoformat()})

    def cancel_cardless(self, withdrawal_id: uuid.UUID) -> None:
        code = self.db.scalar(select(CardlessCode).where(
            CardlessCode.withdrawal_id == withdrawal_id, CardlessCode.user_id == self.user.id,
            CardlessCode.status == CardlessCodeStatus.ACTIVE).with_for_update())
        if code is None:
            raise _fail(404, "code_not_found", "Code actif introuvable.")
        code.status = CardlessCodeStatus.CANCELLED
        if code.hold_id:
            release_hold(self.db, code.hold_id)
        self.db.get(Withdrawal, withdrawal_id).status = WithdrawalStatus.CANCELLED
        emit(self.db, E.CARDLESS_CODE_CANCELLED, withdrawal_id=withdrawal_id, **self._fields())
        self.db.commit()

    # ------------------------------------------------------------------ réglages de sécurité (avec step-up)
    def request_security_change(self, action: str, target_id: uuid.UUID) -> Outcome:
        if action == "unblock_card":
            card = self.db.get(Card, target_id)
            if card is None or card.user_id != self.user.id:
                raise _fail(404, "card_not_found", "Carte introuvable.")
            if card.blocked_reason == "SECURITY_LOCK":
                raise _fail(409, "locked_by_security", "Cette carte a été verrouillée par la sécurité : "
                                                       "contactez RL SOLUTION.")
        elif action == "trust_device":
            dev = self.db.get(Device, target_id)
            if dev is None or dev.user_id != self.user.id or dev.status == DeviceStatus.BLOCKED:
                raise _fail(404, "device_not_found", "Appareil introuvable.")
        else:
            raise _fail(422, "unknown_action", "Action inconnue.")
        ctx = self._context(Op.SECURITY_SETTINGS, city=self._city(None))
        result = evaluate(self.db, ctx)
        save_assessment(self.db, ctx, result)
        verdict, cid = self._gate(ctx, result, "security", None, {"action": action, "target_id": str(target_id)})
        if verdict == "blocked":
            self._on_block(ctx, result, "Modification de sécurité bloquée", E.TRANSFER_BLOCKED)
            self.db.commit()
            raise _fail(403, "operation_blocked", "Opération refusée par mesure de sécurité.")
        if verdict == "execute":
            out = self._finish_security({"action": action, "target_id": str(target_id)})
            self.db.commit()
            return out
        self.db.commit()
        return Outcome("step_up_required", {"action": action}, cid)

    def _finish_security(self, d: dict) -> Outcome:
        target = uuid.UUID(d["target_id"])
        if d["action"] == "unblock_card":
            card = self.db.get(Card, target)
            card.status, card.blocked_reason, card.pin_failed_attempts = CardStatus.ACTIVE, None, 0
            emit(self.db, E.CARD_UNBLOCKED, **self._fields())
        else:
            dev = self.db.get(Device, target)
            dev.status, dev.trusted_at = DeviceStatus.TRUSTED, _now()
            fields = {**self._fields(), "device_id": dev.id}
            emit(self.db, E.DEVICE_TRUSTED, **fields)
        record_audit(self.db, action=f"CUSTOMER_{d['action'].upper()}", target_type="user", target_id=self.user.id,
                     actor_id=self.user.id, ip_address=self.c.ip)
        return Outcome("completed", {"action": d["action"], "status": "DONE"})

    def block_card(self, card_id: uuid.UUID) -> None:
        card = self.db.get(Card, card_id)
        if card is None or card.user_id != self.user.id:
            raise _fail(404, "card_not_found", "Carte introuvable.")
        card.status, card.blocked_reason = CardStatus.BLOCKED, "CUSTOMER_REQUEST"
        emit(self.db, E.CARD_BLOCKED, **self._fields())
        self.db.commit()


# ---------------------------------------------------------------------- retrait sans carte au distributeur
def redeem_cardless(db: Session, settings: Settings, *, atm: ATM, reference: str, code: str,
                    ip: str | None) -> dict[str, Any]:
    """Appelé par le terminal ATM authentifié. 3 essais maximum, code à usage unique, 15 minutes."""
    row = db.scalar(select(CardlessCode).where(CardlessCode.reference == reference.upper(),
                                               CardlessCode.status == CardlessCodeStatus.ACTIVE).with_for_update())
    base = dict(actor_type=ActorType.ATM, atm_id=atm.id, ip_address=ip)
    if row is None:
        emit(db, E.WITHDRAWAL_AUTHENTICATION_FAILED, metadata={"reason": "unknown_reference"}, **base)
        db.commit()
        raise _fail(404, "invalid_code", "Référence ou code incorrect.")
    user = db.get(User, row.user_id)
    w = db.get(Withdrawal, row.withdrawal_id)
    if row.expires_at <= _now():
        row.status = CardlessCodeStatus.EXPIRED
        if row.hold_id:
            release_hold(db, row.hold_id, HoldStatus.EXPIRED)
        w.status = WithdrawalStatus.CANCELLED
        db.commit()
        raise _fail(410, "code_expired", "Code expiré.")
    key = settings.cardless_hmac_key.get_secret_value().encode()
    expected = hmac.new(key, f"{row.reference}:{code}".encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, row.code_hmac):
        row.attempts += 1
        emit(db, E.WITHDRAWAL_AUTHENTICATION_FAILED, user_id=user.id, withdrawal_id=w.id,
             metadata={"attempts": row.attempts}, **base)
        if row.attempts >= 3:
            row.status = CardlessCodeStatus.LOCKED
            if row.hold_id:
                release_hold(db, row.hold_id)
            w.status = WithdrawalStatus.BLOCKED
            resp.notify(db, user.id, "CARDLESS_LOCKED", "Code de retrait verrouillé",
                        "Trois essais incorrects ont verrouillé votre code de retrait sans carte.", Severity.HIGH)
        db.commit()
        raise _fail(401, "invalid_code", "Référence ou code incorrect.")
    if atm.status not in (AtmStatus.ONLINE, AtmStatus.SUSPICIOUS):
        raise _fail(409, "atm_unavailable", "Distributeur indisponible.")
    account = db.get(Account, row.account_id)
    ctx = OperationContext(user=user, op=Op.WITHDRAWAL_CARDLESS, amount=row.amount, account=account, atm=atm,
                           city=atm.city, country=atm.country, ip=ip, strong_auth=True)
    result = evaluate(db, ctx)
    save_assessment(db, ctx, result, withdrawal_id=w.id)
    if result.decision == PolicyDecision.BLOCK:
        row.status = CardlessCodeStatus.CANCELLED
        if row.hold_id:
            release_hold(db, row.hold_id)
        w.status, w.decline_reason = WithdrawalStatus.BLOCKED, "security_policy"
        ev = emit(db, E.WITHDRAWAL_BLOCKED, user_id=user.id, withdrawal_id=w.id, amount=row.amount,
                  risk_score=result.score, metadata={"reasons": result.reasons}, **base)
        alert = resp.raise_alert(db, user_id=user.id, title="Retrait sans carte bloqué au distributeur",
                                 result=result, event=ev)
        resp.run_policy_actions(db, result, user, alert=alert)
        db.commit()
        raise _fail(403, "operation_blocked", "Opération refusée par mesure de sécurité.")
    if row.hold_id:
        release_hold(db, row.hold_id, HoldStatus.CAPTURED)
    post_transfer(db, debit_account_id=row.account_id, credit_account_id=db.scalar(select(Account.id).where(
        Account.account_type == AccountType.INTERNAL, Account.label == "Règlement ATM")), amount=row.amount,
        operation_type=LedgerOperation.WITHDRAWAL, operation_id=w.id, description=f"Retrait sans carte {atm.atm_code}")
    row.status, row.used_at, row.used_atm_id = CardlessCodeStatus.USED, _now(), atm.id
    w.status, w.atm_id, w.risk_score, w.risk_level = WithdrawalStatus.APPROVED, atm.id, result.score, result.level
    ev = emit(db, E.CARDLESS_WITHDRAWAL, actor_type=ActorType.ATM, user_id=user.id, withdrawal_id=w.id, atm_id=atm.id,
              amount=row.amount, location=atm.city, country=atm.country, status="APPROVED", risk_score=result.score,
              ip_address=ip)
    db.flush()
    w.security_event_id = ev.id
    if result.score >= settings.risk_high_from:
        resp.raise_alert(db, user_id=user.id, title="Retrait sans carte inhabituel", result=result, event=ev)
    resp.notify(db, user.id, "CARDLESS_USED", "Retrait sans carte effectué",
                f"{row.amount} XAF retirés à {atm.name} ({atm.city}).")
    db.commit()
    return {"status": "APPROVED", "amount": row.amount, "atm": atm.atm_code}
