"""Sécurité du schéma : privilèges, tables en ajout seul, contraintes d'intégrité."""
import uuid

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError, IntegrityError

from app.models import Account, AuditLog, Beneficiary, LedgerEntry, User
from app.models.enums import BeneficiaryStatus


def _fails(db, sql, params=None, exc=DBAPIError):
    with pytest.raises(exc):
        db.execute(text(sql), params or {})
        db.flush()
    db.rollback()


def test_role_applicatif_sans_ddl(db):
    _fails(db, "CREATE TABLE pirate(id int)")
    _fails(db, "DROP TABLE users")
    _fails(db, "ALTER TABLE accounts DROP CONSTRAINT ck_accounts_balance_non_negative")


@pytest.mark.parametrize("table", ["audit_logs", "ledger_entries", "security_events"])
def test_tables_en_ajout_seul_pour_le_role_applicatif(db, table):
    _fails(db, f"UPDATE {table} SET id = id")
    _fails(db, f"DELETE FROM {table}")
    _fails(db, f"TRUNCATE {table}")


@pytest.mark.parametrize("table", ["audit_logs", "ledger_entries", "security_events"])
def test_meme_le_proprietaire_ne_peut_pas_modifier_l_historique(owner_conn, table):
    with pytest.raises(DBAPIError, match="ajout seul"):
        owner_conn.execute(text(f"DELETE FROM {table}"))


def test_solde_client_negatif_refuse(db):
    account = db.scalar(select(Account).where(Account.account_type == "CURRENT").limit(1))
    _fails(db, "UPDATE accounts SET balance = -1, available_balance = -1 WHERE id = :id", {"id": account.id},
           IntegrityError)


def test_disponible_superieur_au_solde_refuse(db):
    account = db.scalar(select(Account).where(Account.account_type == "CURRENT").limit(1))
    _fails(db, "UPDATE accounts SET available_balance = balance + 1 WHERE id = :id", {"id": account.id},
           IntegrityError)


def test_retrait_carte_sans_carte_refuse(db):
    account = db.scalar(select(Account).where(Account.account_type == "CURRENT").limit(1))
    _fails(db, "INSERT INTO withdrawals (id, user_id, account_id, withdrawal_type, amount, status, currency) "
               "VALUES (gen_random_uuid(), :u, :a, 'CARD', 10000, 'PENDING', 'XAF')",
           {"u": account.user_id, "a": account.id}, IntegrityError)


@pytest.mark.parametrize("amount", [0, -5000])
def test_montant_nul_ou_negatif_refuse(db, amount):
    account = db.scalar(select(Account).where(Account.account_type == "CURRENT").limit(1))
    _fails(db, "INSERT INTO withdrawals (id, user_id, account_id, withdrawal_type, amount, status, currency) "
               "VALUES (gen_random_uuid(), :u, :a, 'CARDLESS', :m, 'PENDING', 'XAF')",
           {"u": account.user_id, "a": account.id, "m": amount}, IntegrityError)


def test_statut_hors_enumeration_refuse(db):
    account = db.scalar(select(Account).limit(1))
    _fails(db, "UPDATE accounts SET status = 'HACKED' WHERE id = :id", {"id": account.id}, IntegrityError)


def test_iban_beneficiaire_unique_sauf_si_supprime(db):
    b = db.scalar(select(Beneficiary).limit(1))
    dup = Beneficiary(user_id=b.user_id, first_name="X", last_name="Y", bank_name="Z", iban=b.iban,
                      status=BeneficiaryStatus.ACTIVE)
    db.add(dup)
    with pytest.raises(IntegrityError):
        db.flush()
    db.rollback()
    b = db.scalar(select(Beneficiary).limit(1))
    b.status, b.deleted_at = BeneficiaryStatus.DELETED, b.updated_at
    db.add(Beneficiary(user_id=b.user_id, first_name="X", last_name="Y", bank_name="Z", iban=b.iban,
                       status=BeneficiaryStatus.ACTIVE))
    db.flush()  # autorisé : l'ancien est supprimé logiquement


def test_compte_system_non_connectable(db):
    system = db.scalar(select(User).where(User.user_type == "SYSTEM"))
    assert system.password_hash is None and system.status == "DISABLED"
    _fails(db, "INSERT INTO users (id, email, first_name, last_name, user_type, status, failed_login_count, "
               "must_change_password) VALUES (:id, 'x@test.test', 'a', 'b', 'CUSTOMER', 'ACTIVE', 0, false)",
           {"id": uuid.uuid4()}, IntegrityError)


def test_vue_transaction_risks_lisible(db):
    db.execute(text("SELECT count(*) FROM transaction_risks")).scalar_one()


def test_aucune_donnee_sensible_en_clair(db):
    assert db.scalar(select(LedgerEntry).limit(1)) is not None
    cols = {r[0] for r in db.execute(text(
        "SELECT column_name FROM information_schema.columns WHERE table_schema='public'"))}
    assert not {"password", "cvv", "pan", "pin", "totp_secret", "cardless_code", "card_number"} & cols
    assert db.scalar(select(AuditLog).limit(1)).hash
