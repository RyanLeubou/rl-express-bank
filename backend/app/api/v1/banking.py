"""Opérations du client : comptes, RIB, bénéficiaires, virements, cartes, paiements, retraits, step-up."""
from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Header, Query, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.api.v1.deps_banking import get_banking, outcome_response
from app.core.config import Settings, get_settings
from app.core.database import get_db
from app.events.audit import record_audit
from app.events.catalog import EventType as E
from app.events.logger import emit
from app.models import ATM, Account, Beneficiary, Card, CardPayment, LedgerEntry, Transfer, Withdrawal
from app.models.enums import AccountType, BeneficiaryStatus, LedgerOperation
from app.models.identity import User
from app.schemas.banking import (
    BeneficiaryIn,
    PaymentIn,
    RibEventIn,
    StepUpVerifyIn,
    TransferIn,
    WithdrawalIn,
)
from app.security.auth.deps import AuthContext, check_origin, client_ip, require_permission
from app.security.auth.errors import AuthError
from app.services.banking.opening import open_account
from app.services.banking.operations import BankingService
from app.services.banking.receipt import build_receipt
from app.services.banking.rib import BANK_NAME, format_iban
from app.services.cards.details import cvv, full_pan

router = APIRouter(tags=["Banque"], dependencies=[Depends(check_origin)])
IDEM = Header(default=None, alias="Idempotency-Key", min_length=8, max_length=100)


def _mask(iban: str) -> str:
    return f"{iban[:4]} •••• •••• {iban[-4:]}"


def _acc(a: Account) -> dict[str, Any]:
    return {"id": a.id, "label": a.label, "type": a.account_type, "balance": a.balance,
            "available_balance": a.available_balance, "currency": a.currency, "status": a.status,
            "iban_masked": _mask(a.iban), "account_number_last4": a.account_number[-4:]}


def _own_account(db: DbSession, ctx: AuthContext, account_id: uuid.UUID) -> Account:
    acc = db.get(Account, account_id)
    if acc is None or acc.user_id != ctx.user.id or acc.account_type == AccountType.INTERNAL:
        raise AuthError(404, "account_not_found", "Compte introuvable.")
    return acc


# ---- comptes et RIB -------------------------------------------------------------------------------
@router.get("/accounts", summary="Mes comptes")
def accounts(ctx: AuthContext = Depends(require_permission("account:read:own")), db: DbSession = Depends(get_db)):
    rows = db.scalars(select(Account).where(Account.user_id == ctx.user.id).order_by(Account.created_at))
    return [_acc(a) for a in rows]


@router.post("/accounts/savings", status_code=201, summary="Ouvrir mon livret épargne")
def open_savings(request: Request, ctx: AuthContext = Depends(require_permission("account:create:own")),
                 db: DbSession = Depends(get_db)):
    if db.scalar(select(Account.id).where(Account.user_id == ctx.user.id,
                                          Account.account_type == AccountType.SAVINGS)):
        raise AuthError(409, "savings_exists", "Vous avez déjà un livret épargne.")
    account = open_account(db, ctx.user, AccountType.SAVINGS)
    emit(db, E.ACCOUNT_OPENED, user_id=ctx.user.id, session_id=ctx.session.id,
         metadata={"account_id": str(account.id), "account_type": "SAVINGS"})
    record_audit(db, action="ACCOUNT_OPENED", target_type="account", target_id=account.id, actor_id=ctx.user.id,
                 actor_role="CLIENT", after={"account_type": "SAVINGS", "branch_code": account.branch_code},
                 ip_address=client_ip(request))
    db.commit()
    return _acc(account)


@router.get("/accounts/{account_id}/transactions", summary="Historique d'un compte")
def transactions(account_id: uuid.UUID, limit: int = Query(30, ge=1, le=100), before_seq: int | None = None,
                 ctx: AuthContext = Depends(require_permission("account:read:own")),
                 db: DbSession = Depends(get_db)):
    _own_account(db, ctx, account_id)
    q = select(LedgerEntry).where(LedgerEntry.account_id == account_id).order_by(LedgerEntry.seq.desc()).limit(limit)
    if before_seq:
        q = q.where(LedgerEntry.seq < before_seq)
    return [{"seq": e.seq, "date": e.value_date, "amount": e.amount, "balance_after": e.balance_after,
             "type": e.operation_type, "description": e.description} for e in db.scalars(q)]


@router.get("/accounts/{account_id}/rib", summary="Afficher mon RIB")
def rib(account_id: uuid.UUID, ctx: AuthContext = Depends(require_permission("rib:read:own")),
        db: DbSession = Depends(get_db)):
    a = _own_account(db, ctx, account_id)
    emit(db, E.RIB_VIEWED, user_id=ctx.user.id, session_id=ctx.session.id, ip_address=None)
    db.commit()
    return {"holder": ctx.user.full_name, "bank": BANK_NAME, "bank_code": a.bank_code, "branch_code": a.branch_code,
            "account_number": a.account_number, "rib_key": a.rib_key, "iban": format_iban(a.iban), "bic": a.bic}


@router.post("/accounts/{account_id}/rib/event", status_code=204, summary="Tracer une copie ou un téléchargement")
def rib_event(account_id: uuid.UUID, body: RibEventIn,
              ctx: AuthContext = Depends(require_permission("rib:read:own")), db: DbSession = Depends(get_db)):
    _own_account(db, ctx, account_id)
    emit(db, E.RIB_COPIED if body.action == "copied" else E.RIB_DOWNLOADED, user_id=ctx.user.id,
         session_id=ctx.session.id)
    db.commit()


# ---- bénéficiaires --------------------------------------------------------------------------------
@router.get("/beneficiaries", summary="Mes bénéficiaires")
def beneficiaries(ctx: AuthContext = Depends(require_permission("beneficiary:read:own")),
                  db: DbSession = Depends(get_db)):
    rows = db.scalars(select(Beneficiary).where(Beneficiary.user_id == ctx.user.id,
                                                Beneficiary.status != BeneficiaryStatus.DELETED))
    return [{"id": b.id, "name": f"{b.first_name} {b.last_name}", "bank_name": b.bank_name,
             "iban_masked": _mask(b.iban), "status": b.status, "internal": b.internal_account_id is not None,
             "activated_at": b.activated_at} for b in rows]


@router.post("/beneficiaries", summary="Ajouter un bénéficiaire (authentification renforcée)")
def add_beneficiary(body: BeneficiaryIn, _: AuthContext = Depends(require_permission("beneficiary:create:own")),
                    svc: BankingService = Depends(get_banking)):
    return outcome_response(svc.add_beneficiary(body.first_name, body.last_name, body.bank_name, body.iban,
                                                body.simulated_city))


@router.get("/beneficiaries/{beneficiary_id}", summary="Fiche complète d'un bénéficiaire")
def beneficiary_detail(beneficiary_id: uuid.UUID,
                       ctx: AuthContext = Depends(require_permission("beneficiary:read:own")),
                       db: DbSession = Depends(get_db)):
    b = db.get(Beneficiary, beneficiary_id)
    if b is None or b.user_id != ctx.user.id or b.status == BeneficiaryStatus.DELETED:
        raise AuthError(404, "beneficiary_not_found", "Bénéficiaire introuvable.")
    emit(db, E.BENEFICIARY_VIEWED, user_id=ctx.user.id, session_id=ctx.session.id, beneficiary_id=b.id)
    db.commit()
    recent = db.scalars(select(Transfer).where(Transfer.user_id == ctx.user.id, Transfer.beneficiary_id == b.id)
                        .order_by(Transfer.created_at.desc()).limit(10))
    return {"id": b.id, "first_name": b.first_name, "last_name": b.last_name, "bank_name": b.bank_name,
            "iban": format_iban(b.iban), "status": b.status, "internal": b.internal_account_id is not None,
            "created_at": b.created_at, "activated_at": b.activated_at,
            "transfers": [{"id": t.id, "amount": t.amount, "reference": t.reference, "status": t.status,
                           "created_at": t.created_at} for t in recent]}


@router.post("/beneficiaries/{beneficiary_id}/verify", summary="Vérifier un bénéficiaire en attente (code)")
def verify_beneficiary(beneficiary_id: uuid.UUID,
                       _: AuthContext = Depends(require_permission("beneficiary:create:own")),
                       svc: BankingService = Depends(get_banking)):
    return outcome_response(svc.verify_beneficiary(beneficiary_id))


@router.delete("/beneficiaries/{beneficiary_id}", status_code=204, summary="Supprimer un bénéficiaire")
def delete_beneficiary(beneficiary_id: uuid.UUID,
                       _: AuthContext = Depends(require_permission("beneficiary:delete:own")),
                       svc: BankingService = Depends(get_banking)):
    svc.delete_beneficiary(beneficiary_id)


# ---- virements ------------------------------------------------------------------------------------
_INCOMING = (LedgerOperation.TRANSFER, LedgerOperation.SALARY)


def _own_account_ids(db: DbSession, ctx: AuthContext) -> list[uuid.UUID]:
    return list(db.scalars(select(Account.id).where(Account.user_id == ctx.user.id,
                                                    Account.account_type != AccountType.INTERNAL)))


def _sender(db: DbSession, entry: LedgerEntry) -> tuple[str, str | None, str | None]:
    """(nom de l'émetteur, IBAN masqué, motif) d'un crédit : client RL, salaire ou autre banque."""
    t = db.get(Transfer, entry.operation_id) if entry.operation_id else None
    if t is not None:
        src = db.get(Account, t.source_account_id)
        owner = db.get(User, src.user_id) if src else None
        return (owner.full_name if owner else "Client RL EXPRESS BANK", _mask(src.iban) if src else None,
                t.reference)
    if entry.operation_type == LedgerOperation.SALARY:
        return "Employeur (salaire)", None, entry.description
    return "Autre banque", None, entry.description


@router.get("/transfers", summary="Mes virements émis et reçus")
def transfers(ctx: AuthContext = Depends(require_permission("transfer:read:own")), db: DbSession = Depends(get_db),
              limit: int = Query(30, ge=1, le=100)):
    out = [{"id": str(t.id), "direction": "OUT", "amount": t.amount, "reference": t.reference, "status": t.status,
            "counterparty": f"{b.first_name} {b.last_name}" if (b := db.get(Beneficiary, t.beneficiary_id)) else None,
            "created_at": t.created_at, "executed_at": t.executed_at, "risk_level": t.risk_level}
           for t in db.scalars(select(Transfer).where(Transfer.user_id == ctx.user.id)
                               .order_by(Transfer.created_at.desc()).limit(limit))]
    credits = db.scalars(select(LedgerEntry).where(LedgerEntry.account_id.in_(_own_account_ids(db, ctx)),
                                                   LedgerEntry.amount > 0, LedgerEntry.operation_type.in_(_INCOMING))
                         .order_by(LedgerEntry.value_date.desc()).limit(limit))
    incoming = []
    for e in credits:
        name, _, reference = _sender(db, e)
        incoming.append({"id": str(e.seq), "direction": "IN", "amount": e.amount, "reference": reference,
                         "status": "COMPLETED", "counterparty": name, "created_at": e.value_date,
                         "executed_at": e.value_date, "risk_level": None})
    return sorted(out + incoming, key=lambda r: r["created_at"], reverse=True)[:limit]


def _sent_detail(db: DbSession, ctx: AuthContext, transfer_id: uuid.UUID) -> dict[str, Any]:
    t = db.get(Transfer, transfer_id)
    if t is None or t.user_id != ctx.user.id:
        raise AuthError(404, "transfer_not_found", "Virement introuvable.")
    src, b = db.get(Account, t.source_account_id), db.get(Beneficiary, t.beneficiary_id)
    return {"id": t.id, "direction": "OUT", "amount": t.amount, "currency": t.currency, "reference": t.reference,
            "status": t.status, "created_at": t.created_at, "executed_at": t.executed_at,
            "account": {"label": src.label, "iban_masked": _mask(src.iban)},
            "counterparty": {"name": f"{b.first_name} {b.last_name}", "bank": b.bank_name, "iban": format_iban(b.iban),
                             "internal": b.internal_account_id is not None},
            "risk_level": t.risk_level, "risk_score": t.risk_score, "failure_reason": t.failure_reason}


def _received_detail(db: DbSession, ctx: AuthContext, seq: int) -> dict[str, Any]:
    e = db.scalar(select(LedgerEntry).where(LedgerEntry.seq == seq))
    if (e is None or e.amount <= 0 or e.operation_type not in _INCOMING
            or e.account_id not in _own_account_ids(db, ctx)):
        raise AuthError(404, "transfer_not_found", "Virement introuvable.")
    acc = db.get(Account, e.account_id)
    name, iban_masked, reference = _sender(db, e)
    return {"id": str(e.seq), "direction": "IN", "amount": e.amount, "currency": "XAF", "reference": reference,
            "status": "COMPLETED", "created_at": e.value_date, "executed_at": e.value_date,
            "account": {"label": acc.label, "iban_masked": _mask(acc.iban)},
            "counterparty": {"name": name, "bank": BANK_NAME if iban_masked else None, "iban": iban_masked,
                             "internal": iban_masked is not None},
            "balance_after": e.balance_after}


def _receipt(db: DbSession, ctx: AuthContext, detail: dict[str, Any]) -> Response:
    emit(db, E.TRANSFER_RECEIPT_DOWNLOADED, user_id=ctx.user.id, session_id=ctx.session.id,
         metadata={"direction": detail["direction"], "id": str(detail["id"])})
    db.commit()
    day = detail["created_at"].strftime("%Y%m%d")
    name = f"avis-virement-{'recu' if detail['direction'] == 'IN' else 'emis'}-{day}-{str(detail['id'])[:8]}.pdf"
    return Response(build_receipt(detail, ctx.user.full_name), media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


_READ_TRANSFERS = require_permission("transfer:read:own")


@router.get("/transfers/sent/{transfer_id}", summary="Détail d'un virement émis")
def sent_transfer(transfer_id: uuid.UUID, ctx: AuthContext = Depends(_READ_TRANSFERS),
                  db: DbSession = Depends(get_db)):
    return _sent_detail(db, ctx, transfer_id)


@router.get("/transfers/received/{seq}", summary="Détail d'un virement reçu")
def received_transfer(seq: int, ctx: AuthContext = Depends(_READ_TRANSFERS), db: DbSession = Depends(get_db)):
    return _received_detail(db, ctx, seq)


@router.get("/transfers/sent/{transfer_id}/receipt.pdf", summary="Avis de virement émis (PDF)")
def sent_receipt(transfer_id: uuid.UUID, ctx: AuthContext = Depends(_READ_TRANSFERS),
                 db: DbSession = Depends(get_db)):
    return _receipt(db, ctx, _sent_detail(db, ctx, transfer_id))


@router.get("/transfers/received/{seq}/receipt.pdf", summary="Avis de virement reçu (PDF)")
def received_receipt(seq: int, ctx: AuthContext = Depends(_READ_TRANSFERS), db: DbSession = Depends(get_db)):
    return _receipt(db, ctx, _received_detail(db, ctx, seq))


@router.post("/transfers", summary="Émettre un virement")
def create_transfer(body: TransferIn, _: AuthContext = Depends(require_permission("transfer:create:own")),
                    svc: BankingService = Depends(get_banking), idempotency_key: str | None = IDEM):
    return outcome_response(svc.create_transfer(body.source_account_id, body.beneficiary_id, body.amount,
                                                body.reference, idempotency_key, body.simulated_city))


@router.post("/transfers/{transfer_id}/cancel", status_code=204, summary="Annuler un virement en attente")
def cancel_transfer(transfer_id: uuid.UUID, _: AuthContext = Depends(require_permission("transfer:cancel:own")),
                    svc: BankingService = Depends(get_banking)):
    svc.cancel_transfer(transfer_id)


# ---- cartes et paiements --------------------------------------------------------------------------
@router.get("/cards", summary="Mes cartes")
def cards(ctx: AuthContext = Depends(require_permission("card:read:own")), db: DbSession = Depends(get_db)):
    return [{"id": c.id, "masked_pan": c.masked_pan, "holder": c.holder_name, "type": c.card_type,
             "expiry": f"{c.expiry_month:02d}/{c.expiry_year % 100:02d}", "status": c.status,
             "blocked_reason": c.blocked_reason, "account_id": c.account_id,
             "daily_withdrawal_limit": c.daily_withdrawal_limit, "daily_payment_limit": c.daily_payment_limit}
            for c in db.scalars(select(Card).where(Card.user_id == ctx.user.id))]


@router.get("/cards/{card_id}/details", summary="Afficher le numéro complet et le CVV de ma carte")
def card_details(card_id: uuid.UUID, ctx: AuthContext = Depends(require_permission("card:read:own")),
                 db: DbSession = Depends(get_db), settings: Settings = Depends(get_settings)):
    card = db.get(Card, card_id)
    if card is None or card.user_id != ctx.user.id:
        raise AuthError(404, "card_not_found", "Carte introuvable.")
    # Chaque affichage est tracé : un pic de consultations est un signal de prise de contrôle du compte
    emit(db, E.CARD_VIEWED, user_id=ctx.user.id, session_id=ctx.session.id, metadata={"card_id": str(card.id)})
    db.commit()
    pan = full_pan(settings, card)
    return {"pan": " ".join(pan[i:i + 4] for i in range(0, 16, 4)), "cvv": cvv(settings, card),
            "expiry": f"{card.expiry_month:02d}/{card.expiry_year % 100:02d}", "holder": card.holder_name}


@router.post("/cards/{card_id}/block", status_code=204, summary="Bloquer ma carte")
def block_card(card_id: uuid.UUID, _: AuthContext = Depends(require_permission("card:block:own")),
               svc: BankingService = Depends(get_banking)):
    svc.block_card(card_id)


@router.post("/cards/{card_id}/unblock", summary="Débloquer ma carte (authentification renforcée)")
def unblock_card(card_id: uuid.UUID, _: AuthContext = Depends(require_permission("card:unblock:own")),
                 svc: BankingService = Depends(get_banking)):
    return outcome_response(svc.request_security_change("unblock_card", card_id))


@router.get("/payments", summary="Mes paiements")
def payments(ctx: AuthContext = Depends(require_permission("payment:read:own")), db: DbSession = Depends(get_db),
             limit: int = Query(30, ge=1, le=100)):
    rows = db.scalars(select(CardPayment).where(CardPayment.user_id == ctx.user.id)
                      .order_by(CardPayment.occurred_at.desc()).limit(limit))
    return [{"id": p.id, "merchant": p.merchant_name, "category": p.category, "city": p.city, "amount": p.amount,
             "status": p.status, "date": p.occurred_at} for p in rows]


@router.post("/payments", summary="Payer par carte (simulation)")
def pay(body: PaymentIn, _: AuthContext = Depends(require_permission("payment:create:own")),
        svc: BankingService = Depends(get_banking), idempotency_key: str | None = IDEM):
    return outcome_response(svc.pay_by_card(body.card_id, body.amount, body.merchant, body.category, body.city,
                                            idempotency_key))


# ---- retraits et ATM ------------------------------------------------------------------------------
@router.get("/atms", summary="Distributeurs")
def atms(_: AuthContext = Depends(require_permission("atm:read:any")), db: DbSession = Depends(get_db)):
    return [{"id": a.id, "code": a.atm_code, "name": a.name, "city": a.city, "status": a.status,
             "latitude": float(a.latitude), "longitude": float(a.longitude)} for a in db.scalars(select(ATM))]


@router.get("/withdrawals", summary="Mes retraits")
def withdrawals(ctx: AuthContext = Depends(require_permission("withdrawal:read:own")),
                db: DbSession = Depends(get_db), limit: int = Query(30, ge=1, le=100)):
    rows = db.scalars(select(Withdrawal).where(Withdrawal.user_id == ctx.user.id)
                      .order_by(Withdrawal.created_at.desc()).limit(limit))
    return [{"id": w.id, "type": w.withdrawal_type, "amount": w.amount, "status": w.status, "city": w.city,
             "created_at": w.created_at, "decline_reason": w.decline_reason} for w in rows]


@router.post("/withdrawals", summary="Retirer avec ou sans carte")
def withdraw(body: WithdrawalIn, _: AuthContext = Depends(require_permission("withdrawal:create:own")),
             svc: BankingService = Depends(get_banking), idempotency_key: str | None = IDEM):
    return outcome_response(svc.withdraw(body.type, body.account_id, body.amount, atm_id=body.atm_id,
                                         card_id=body.card_id, pin=body.pin, idempotency_key=idempotency_key,
                                         simulated_city=body.simulated_city))


@router.post("/withdrawals/{withdrawal_id}/cancel", status_code=204, summary="Annuler un code de retrait")
def cancel_withdrawal(withdrawal_id: uuid.UUID, _: AuthContext = Depends(require_permission("withdrawal:cancel:own")),
                      svc: BankingService = Depends(get_banking)):
    svc.cancel_cardless(withdrawal_id)


# ---- step-up --------------------------------------------------------------------------------------
@router.post("/step-up/{challenge_id}/verify", summary="Valider une opération avec le code TOTP")
def verify_step_up(challenge_id: uuid.UUID, body: StepUpVerifyIn, svc: BankingService = Depends(get_banking)):
    return outcome_response(svc.verify_step_up(challenge_id, body.code))


@router.post("/devices/{device_id}/trust", summary="Faire confiance à un appareil (authentification renforcée)")
def trust_device(device_id: uuid.UUID, _: AuthContext = Depends(require_permission("device:trust:own")),
                 svc: BankingService = Depends(get_banking)):
    return outcome_response(svc.request_security_change("trust_device", device_id))

