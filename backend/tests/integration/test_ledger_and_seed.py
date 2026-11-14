"""Grand livre, concurrence, audit chaîné, seed et catalogues."""
import threading

import pytest
from sqlalchemy import func, select, text

from app.core.database import get_session_factory
from app.events.audit import record_audit, verify_audit_chain, verify_entries
from app.events.catalog import EventType
from app.events.logger import emit
from app.models import (
    Account,
    AuditLog,
    BehaviorProfile,
    OutboxEvent,
    Permission,
    Role,
    SecurityEvent,
    User,
    Withdrawal,
)
from app.models.enums import AccountType, ActorType, LedgerOperation
from app.seed.runner import run_seed
from app.services.banking.ledger import LedgerError, post_transfer
from app.services.banking.rib import build_rib, iban_is_valid, rib_key


def test_invariants_comptables(db):
    unbalanced = db.execute(text("SELECT count(*) FROM (SELECT journal_id FROM ledger_entries GROUP BY journal_id "
                                 "HAVING sum(amount) <> 0) x")).scalar_one()
    incoherent = db.execute(text("SELECT count(*) FROM accounts a WHERE a.balance <> COALESCE((SELECT sum(amount) "
                                 "FROM ledger_entries l WHERE l.account_id = a.id), 0)")).scalar_one()
    assert unbalanced == 0 and incoherent == 0
    assert db.scalar(select(func.sum(Account.balance))) == 0  # partie double : la banque est équilibrée


def test_seed_idempotent(db, seeded):
    assert seeded["clients"] == 8 and seeded["withdrawals"] > 50
    assert run_seed(db) == {"skipped": 1}


def test_profil_jean_dupont_conforme_au_cahier_des_charges(db):
    jean = db.scalar(select(User).where(User.email.like("jean.dupont@%")))
    profile = db.get(BehaviorProfile, jean.id)
    stats = profile.amount_stats["withdrawal"]
    assert 20_000 <= stats["mean"] <= 50_000 and stats["max"] <= 50_000
    assert 0.8 <= profile.withdrawals_per_week <= 2.5
    assert set(profile.usual_cities) == {"Douala"}
    local_hours = [h for h, n in enumerate(profile.usual_hours) if n]
    assert min(local_hours) >= 8 and max(local_hours) < 20


def test_solde_insuffisant_refuse(db):
    acc = db.scalar(select(Account).where(Account.account_type == AccountType.CURRENT).limit(1))
    atm = db.scalar(select(Account).where(Account.label == "Règlement ATM"))
    with pytest.raises(LedgerError) as err:
        post_transfer(db, debit_account_id=acc.id, credit_account_id=atm.id, amount=acc.available_balance + 1,
                      operation_type=LedgerOperation.WITHDRAWAL, operation_id=None, description="test")
    assert err.value.code == "insufficient_funds"


def test_deux_retraits_simultanes_un_seul_passe(seeded):
    """Scénario du cahier des charges : solde 100 000, deux retraits de 80 000 en parallèle."""
    factory = get_session_factory()
    with factory() as s:
        acc = s.scalar(select(Account).where(Account.account_type == AccountType.SECONDARY).limit(1))
        ext = s.scalar(select(Account).where(Account.label == "Compensation interbancaire"))
        atm = s.scalar(select(Account).where(Account.label == "Règlement ATM"))
        post_transfer(s, debit_account_id=ext.id, credit_account_id=acc.id, amount=100_000 - acc.balance,
                      operation_type=LedgerOperation.ADJUSTMENT, operation_id=None, description="Préparation")
        s.commit()
        acc_id, atm_id = acc.id, atm.id

    barrier, results = threading.Barrier(2), []

    def withdraw():
        with factory() as s:
            barrier.wait()
            try:
                post_transfer(s, debit_account_id=acc_id, credit_account_id=atm_id, amount=80_000,
                              operation_type=LedgerOperation.WITHDRAWAL, operation_id=None, description="Concurrent")
                s.commit()
                results.append("ok")
            except LedgerError as exc:
                s.rollback()
                results.append(exc.code)

    threads = [threading.Thread(target=withdraw) for _ in range(2)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sorted(results) == ["insufficient_funds", "ok"]
    with factory() as s:
        assert s.get(Account, acc_id).balance == 20_000


def test_chaine_d_audit_valide_et_falsification_detectee(db):
    record_audit(db, action="TEST_ACTION", target_type="test", actor_type=ActorType.SYSTEM, after={"password": "x"})
    report = verify_audit_chain(db)
    assert report.valid and report.entries >= 2
    entries = list(db.scalars(select(AuditLog).order_by(AuditLog.seq)))
    assert entries[-1].after == {"password": "[MASQUÉ]"}
    db.expunge_all()
    entries[0].justification = "modifié après coup"
    assert verify_entries(entries).broken_at_seq == entries[0].seq


def test_emit_ecrit_evenement_et_outbox_dans_la_transaction(db):
    user = db.scalar(select(User).where(User.user_type == "CUSTOMER").limit(1))
    event = emit(db, EventType.RIB_VIEWED, user_id=user.id, metadata={"otp": "123456", "page": "rib"})
    db.flush()
    assert db.get(SecurityEvent, event.id).metadata_ == {"otp": "[MASQUÉ]", "page": "rib"}
    assert db.scalar(select(func.count()).select_from(OutboxEvent)
                     .where(OutboxEvent.security_event_id == event.id)) == 2


def test_emit_refuse_type_ou_champ_inconnu(db):
    with pytest.raises(ValueError):
        emit(db, "EVENEMENT_INVENTE")
    with pytest.raises(ValueError):
        emit(db, EventType.RIB_VIEWED, password="x")


def test_iban_et_cle_rib_valides(db):
    for acc in db.scalars(select(Account)):
        assert iban_is_valid(acc.iban)
        assert acc.rib_key == rib_key(acc.bank_code, acc.branch_code, acc.account_number)
    assert not iban_is_valid(build_rib("00000000001").iban[:-1] + "0")


def test_retraits_historiques_lies_a_leur_evenement(db):
    missing = db.scalar(select(func.count()).select_from(Withdrawal).where(
        Withdrawal.security_event_id.is_(None), Withdrawal.status == "APPROVED"))
    assert missing == 0


def test_rbac_en_base_conforme_au_catalogue(db):
    from app.security.authz.catalog import PERMISSIONS, ROLE_PERMISSIONS
    assert db.scalar(select(func.count()).select_from(Permission)) == len(PERMISSIONS)
    for role in db.scalars(select(Role)):
        assert {p.code for p in role.permissions} == set(ROLE_PERMISSIONS[role.code])
