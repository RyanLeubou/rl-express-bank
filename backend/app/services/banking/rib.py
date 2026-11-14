"""Génération de RIB / IBAN fictifs au format CEMAC (Cameroun).

Format : code banque (5) + code guichet (5) + numéro de compte (11) + clé RIB (2) = BBAN de 23 chiffres,
IBAN = CM + 2 chiffres de contrôle ISO 13616 (mod 97) + BBAN. Les numéros sont syntaxiquement
valides mais le code banque 99990 est fictif : aucun compte réel ne peut correspondre.
"""
from __future__ import annotations

from dataclasses import dataclass

FICTIONAL_BANK_CODE = "99990"
FICTIONAL_BIC = "RLXBCMCXXXX"
BANK_NAME = "RL EXPRESS BANK"
BRANCHES = {"Douala": "00101", "Yaoundé": "00201", "Kribi": "00301", "Bafoussam": "00401"}
BANK_ADDRESS = "Agence fictive, boulevard de la Liberté, Douala"
# Ville de résidence -> agence la plus proche (le code guichet du RIB en découle)
CITY_AGENCY = {
    "Douala": "Douala", "Limbé": "Douala", "Buea": "Douala", "Édéa": "Douala", "Nkongsamba": "Douala",
    "Yaoundé": "Yaoundé", "Mbalmayo": "Yaoundé", "Obala": "Yaoundé", "Bertoua": "Yaoundé", "Ebolowa": "Yaoundé",
    "Ngaoundéré": "Yaoundé", "Garoua": "Yaoundé", "Maroua": "Yaoundé",
    "Kribi": "Kribi", "Campo": "Kribi", "Lolodorf": "Kribi",
    "Bafoussam": "Bafoussam", "Dschang": "Bafoussam", "Mbouda": "Bafoussam", "Foumban": "Bafoussam",
    "Bamenda": "Bafoussam",
}


def rib_key(bank: str, branch: str, account: str) -> str:
    """Clé RIB : 97 - ((89 × banque + 15 × guichet + 3 × compte) mod 97)."""
    value = 89 * int(bank) + 15 * int(branch) + 3 * int(account)
    return f"{97 - value % 97:02d}"


def iban_check_digits(country: str, bban: str) -> str:
    rearranged = bban + country + "00"
    numeric = "".join(str(int(c, 36)) for c in rearranged)
    return f"{98 - int(numeric) % 97:02d}"


def iban_is_valid(iban: str) -> bool:
    compact = iban.replace(" ", "")
    if len(compact) < 15 or not compact[:2].isalpha():
        return False
    rearranged = compact[4:] + compact[:4]
    try:
        return int("".join(str(int(c, 36)) for c in rearranged)) % 97 == 1
    except ValueError:
        return False


def format_iban(iban: str) -> str:
    return " ".join(iban[i:i + 4] for i in range(0, len(iban), 4))


@dataclass(frozen=True)
class RibParts:
    bank_code: str
    branch_code: str
    account_number: str
    rib_key: str
    iban: str
    bic: str = FICTIONAL_BIC


def build_rib(account_number: str, city: str = "Douala", bank_code: str = FICTIONAL_BANK_CODE) -> RibParts:
    if len(account_number) != 11 or not account_number.isdigit():
        raise ValueError("Le numéro de compte doit comporter 11 chiffres")
    branch = BRANCHES.get(city, BRANCHES["Douala"])
    key = rib_key(bank_code, branch, account_number)
    bban = f"{bank_code}{branch}{account_number}{key}"
    return RibParts(bank_code, branch, account_number, key, f"CM{iban_check_digits('CM', bban)}{bban}")
