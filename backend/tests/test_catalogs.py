"""Cohérence des catalogues (sans base de données)."""
import re

from app.events.catalog import CATALOG, EventType
from app.models.enums import RoleCode
from app.security.authz.catalog import PERMISSIONS, ROLE_PERMISSIONS
from app.services.banking.rib import build_rib, iban_is_valid

WRITE_VERBS = ("create", "update", "delete", "manage", "execute", "lock", "block", "unblock", "revoke",
               "cancel", "trust", "reset", "write", "flag", "assign", "run")


def test_toutes_les_permissions_attribuees_existent():
    for perms in ROLE_PERMISSIONS.values():
        assert set(perms) <= set(PERMISSIONS)


def test_format_des_permissions():
    for code in PERMISSIONS:
        assert re.fullmatch(r"[a-z_]+:[a-z_]+:(own|any|assigned)", code)


def test_auditeur_strictement_en_lecture():
    actions = {p.split(":")[1] for p in ROLE_PERMISSIONS[RoleCode.AUDITOR] if not p.endswith(":own")}
    assert not [a for a in actions if a.startswith(WRITE_VERBS)]


def test_client_limite_a_ses_ressources():
    assert {p for p in ROLE_PERMISSIONS[RoleCode.CLIENT] if not p.endswith(":own")} == {"atm:read:any"}


def test_support_limite_aux_tickets_assignes():
    extra = {p for p in ROLE_PERMISSIONS[RoleCode.SUPPORT_AGENT] if p.endswith(":any")}
    assert extra == {"knowledge_base:read:any"}


def test_personne_ne_modifie_un_solde_ni_un_journal():
    all_perms = {p for perms in ROLE_PERMISSIONS.values() for p in perms}
    assert not [p for p in all_perms if p.startswith(("ledger:", "balance:")) or p.startswith("audit:delete")]


def test_evenements_du_cahier_des_charges_presents():
    required = {"USER_LOGIN", "NEW_DEVICE_LOGIN", "RIB_DOWNLOADED", "TRANSFER_BLOCKED", "CARD_PAYMENT_BLOCKED",
                "CARDLESS_WITHDRAWAL", "UNUSUAL_WITHDRAWAL_DETECTED", "MFA_LOCKOUT", "SESSION_REVOKED",
                "SECURITY_ALERT_CREATED", "SECURITY_ACTION_EXECUTED", "BIOMETRIC_VERIFICATION_FAILED"}
    assert required <= {e.value for e in EventType} and set(CATALOG) == set(EventType)


def test_iban_cemac():
    rib = build_rib("12345678901", "Douala")
    assert rib.iban.startswith("CM") and len(rib.iban) == 27 and iban_is_valid(rib.iban)
