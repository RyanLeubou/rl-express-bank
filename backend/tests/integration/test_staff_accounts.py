"""Comptes du personnel créés par l'exploitant (make staff) : jamais d'identifiant pré-existant à réutiliser."""
import pytest
from sqlalchemy import select

from app.models import AuditLog, Role, User, UserRole
from app.models.enums import RoleCode, UserType
from app.security.auth.passwords import verify_secret
from app.seed.runner import seed_base
from app.seed.staff import create_staff

STRONG = "Soc-Analyste-2026x"


def test_analyste_cree_avec_son_role_et_trace(db):
    user = create_staff(db, " Awa.Fotso@Exemple.test ", "Awa", "Fotso", RoleCode.SECURITY_ANALYST, STRONG)
    assert user.email == "awa.fotso@exemple.test" and user.user_type == UserType.STAFF
    assert verify_secret(user.password_hash, STRONG)
    role = db.scalar(select(Role.code).join(UserRole, UserRole.role_id == Role.id).where(UserRole.user_id == user.id))
    assert role == RoleCode.SECURITY_ANALYST.value
    assert db.scalar(select(AuditLog.id).where(AuditLog.action == "STAFF_ACCOUNT_CREATED",
                                               AuditLog.target_id == str(user.id)))


@pytest.mark.parametrize(("password", "role", "message"), [
    ("court-A1", RoleCode.AUDITOR, "12 caractères"),
    ("sansmajuscule2026", RoleCode.AUDITOR, "majuscule"),
    ("Awa.Fotso-Mot2Passe", RoleCode.AUDITOR, "12 caractères"),     # contient l'identifiant de l'e-mail
    (STRONG, RoleCode.CLIENT, "inscription"),                       # un client s'inscrit lui-même
])
def test_mot_de_passe_faible_ou_role_client_refuses(db, password, role, message):
    with pytest.raises(ValueError, match=message):
        create_staff(db, "awa.fotso@exemple.test", "Awa", "Fotso", role, password)


def test_adresse_deja_utilisee_refusee(db):
    create_staff(db, "conseil@exemple.test", "Paul", "Ebo", RoleCode.SUPPORT_AGENT, STRONG)
    with pytest.raises(ValueError, match="existe déjà"):
        create_staff(db, "conseil@exemple.test", "Paul", "Ebo", RoleCode.SUPPORT_AGENT, STRONG)


def test_base_deja_initialisee_non_rejouee(db):
    before = db.scalar(select(User.id).order_by(User.created_at.desc()).limit(1))
    assert seed_base(db) == {"skipped": 1}
    assert db.scalar(select(User.id).order_by(User.created_at.desc()).limit(1)) == before
