"""Création d'un compte du personnel (administrateur, analyste SOC, auditeur, conseiller).

    make staff ROLE=SUPER_ADMIN EMAIL=prenom.nom@exemple.test PRENOM=Prénom NOM=Nom

Le mot de passe est saisi au clavier (jamais en argument ni dans un fichier) et soumis à la même règle que
l'inscription. À la première connexion, le compte doit activer la double authentification.
"""
from __future__ import annotations

import argparse
import getpass
import sys
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.events.audit import record_audit
from app.models import Role, User, UserRole
from app.models.enums import ActorType, RoleCode, UserType
from app.security.auth.passwords import hash_secret
from app.security.auth.service import PASSWORD_RULE

STAFF_ROLES = [r for r in RoleCode if r != RoleCode.CLIENT]


def password_ok(password: str, email: str) -> bool:
    return (len(password) >= 12 and any(c.islower() for c in password) and any(c.isupper() for c in password)
            and any(c.isdigit() for c in password) and email.split("@")[0].lower() not in password.lower())


def create_staff(db: Session, email: str, first_name: str, last_name: str, role: RoleCode, password: str) -> User:
    email = email.strip().lower()
    if role == RoleCode.CLIENT:
        raise ValueError("Un client crée son compte lui-même par l'inscription.")
    if not password_ok(password, email):
        raise ValueError(PASSWORD_RULE)
    if db.scalar(select(User.id).where(User.email == email)):
        raise ValueError("Un compte existe déjà avec cette adresse e-mail.")
    role_row = db.scalar(select(Role).where(Role.code == role.value))
    if role_row is None:
        raise ValueError("Plateforme non initialisée : démarrez d'abord l'API.")
    user = User(email=email, first_name=first_name.strip(), last_name=last_name.strip(), user_type=UserType.STAFF,
                password_hash=hash_secret(password), city="Douala", password_changed_at=datetime.now(UTC))
    db.add(user)
    db.flush()
    db.add(UserRole(user_id=user.id, role_id=role_row.id))
    record_audit(db, action="STAFF_ACCOUNT_CREATED", target_type="user", target_id=str(user.id),
                 actor_type=ActorType.SYSTEM, after={"email": email, "role": role.value},
                 justification="Création en ligne de commande par l'exploitant (make staff)")
    return user


def main(argv: list[str]) -> int:
    from app.core.database import get_session_factory

    parser = argparse.ArgumentParser(description="Crée un compte du personnel RL EXPRESS BANK.")
    parser.add_argument("--role", required=True, choices=[r.value for r in STAFF_ROLES])
    parser.add_argument("--email", required=True)
    parser.add_argument("--prenom", required=True)
    parser.add_argument("--nom", required=True)
    args = parser.parse_args(argv)
    print(PASSWORD_RULE)
    password = getpass.getpass("Mot de passe : ")
    if password != getpass.getpass("Confirmez : "):
        print("Les deux saisies diffèrent.", file=sys.stderr)
        return 1
    with get_session_factory()() as db:
        try:
            user = create_staff(db, args.email, args.prenom, args.nom, RoleCode(args.role), password)
        except ValueError as exc:
            print(exc, file=sys.stderr)
            return 1
        db.commit()
        print(f"Compte {args.role} créé : {user.email}. À la première connexion, activez la double authentification.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
