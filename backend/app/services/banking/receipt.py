"""Avis de virement (preuve) au format PDF, construit à partir du détail renvoyé par l'API.

Polices standard PDF (Latin-1) : les caractères hors Latin-1 (•, −, guillemets typographiques…) sont remplacés.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from typing import Any

from fpdf import FPDF

from app.services.banking.rib import BANK_ADDRESS, BANK_NAME, FICTIONAL_BIC

INK, SOFT, LAGOON, OK, RULE = (11, 42, 51), (90, 108, 115), (14, 116, 128), (21, 128, 61), (213, 223, 226)
STATUS = {"COMPLETED": "Exécuté", "PENDING": "En attente de validation", "BLOCKED": "Bloqué par la sécurité",
          "FAILED": "Refusé", "CANCELLED": "Annulé"}
RISK = {"LOW": "Faible", "MEDIUM": "Moyen", "HIGH": "Élevé", "CRITICAL": "Critique"}
_REPLACE = str.maketrans({"\u2022": "*", "\u2212": "-", "\u2019": "'", "\u201c": '"', "\u201d": '"', "\u2026": "...",
                           "\u00a0": " ", "\u202f": " "})


def _t(value: object) -> str:
    return str(value).translate(_REPLACE).encode("latin-1", "replace").decode("latin-1")


def _xaf(amount: int) -> str:
    return f"{amount:,}".replace(",", " ") + " XAF"


DOUALA = timezone(timedelta(hours=1))


def _date(value: datetime | None) -> str:
    if value is None:
        return "-"
    return f"{value.astimezone(DOUALA):%d/%m/%Y à %H:%M} (heure de Douala)"


def build_receipt(d: dict[str, Any], holder: str) -> bytes:
    incoming = d["direction"] == "IN"
    pdf = FPDF(format="A4")
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.set_title(_t(f"Avis de virement {d['id']}"))
    pdf.set_author(BANK_NAME)
    pdf.add_page()

    # En-tête
    pdf.set_fill_color(*LAGOON)
    pdf.rect(0, 0, 210, 6, "F")
    pdf.set_y(14)
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(*INK)
    pdf.cell(0, 9, BANK_NAME, new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*SOFT)
    pdf.cell(0, 5, _t(f"Banque virtuelle - {BANK_ADDRESS} - BIC {FICTIONAL_BIC}"), new_x="LMARGIN", new_y="NEXT")

    pdf.ln(8)
    pdf.set_font("Helvetica", "B", 15)
    pdf.set_text_color(*INK)
    pdf.cell(0, 8, _t("Avis de virement reçu" if incoming else "Avis de virement émis"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*SOFT)
    pdf.cell(0, 5, _t(f"Référence : {d['id']}  -  Édité le {_date(datetime.now(UTC))}"), new_x="LMARGIN", new_y="NEXT")

    # Montant
    pdf.ln(5)
    pdf.set_draw_color(*RULE)
    pdf.set_fill_color(242, 247, 248)
    top = pdf.get_y()
    pdf.rect(pdf.l_margin, top, 210 - 2 * pdf.l_margin, 24, "DF")
    pdf.set_xy(pdf.l_margin + 6, top + 4)
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(0, 5, "Montant")
    pdf.set_xy(pdf.l_margin + 6, top + 10)
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(*(OK if incoming else INK))
    pdf.cell(100, 10, _t(("+ " if incoming else "- ") + _xaf(d["amount"])))
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(*INK)
    pdf.cell(0, 10, _t(STATUS.get(str(d["status"]), str(d["status"]))), align="R")
    pdf.set_y(top + 30)

    def row(label: str, value: object) -> None:
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*SOFT)
        pdf.cell(55, 7, _t(label))
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*INK)
        pdf.multi_cell(0, 7, _t(value), new_x="LMARGIN", new_y="NEXT")

    def section(title: str) -> None:
        pdf.ln(3)
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(*LAGOON)
        pdf.cell(0, 7, _t(title), new_x="LMARGIN", new_y="NEXT")
        pdf.set_draw_color(*RULE)
        pdf.line(pdf.l_margin, pdf.get_y(), 210 - pdf.r_margin, pdf.get_y())
        pdf.ln(1)

    c, acc = d["counterparty"], d["account"]
    section("Opération")
    row("Motif", d["reference"] or "-")
    row("Date de l'ordre", _date(d["created_at"]))
    row("Date d'exécution", _date(d["executed_at"]) if d.get("executed_at") else "Non exécuté")
    if d.get("risk_level"):
        row("Contrôle de sécurité", RISK.get(str(d["risk_level"]), str(d["risk_level"])))
    if d.get("failure_reason"):
        row("Motif du refus", d["failure_reason"])

    section("Émetteur" if incoming else "Donneur d'ordre")
    if incoming:
        row("Nom", c["name"])
        row("Banque", c["bank"] or "-")
        row("IBAN", c["iban"] or "-")
    else:
        row("Titulaire", holder)
        row("Compte débité", f"{acc['label']}  {acc['iban_masked']}")

    section("Bénéficiaire")
    if incoming:
        row("Titulaire", holder)
        row("Compte crédité", f"{acc['label']}  {acc['iban_masked']}")
    else:
        row("Nom", c["name"])
        row("Banque", c["bank"] or "-")
        row("IBAN", c["iban"] or "-")

    pdf.ln(8)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(*SOFT)
    pdf.multi_cell(0, 4.5, _t(
        f"Document généré par {BANK_NAME} à la demande du titulaire du compte. RL EXPRESS BANK est une banque "
        "virtuelle de démonstration : ce document est fictif et ne constitue pas une preuve de paiement réelle."))
    return bytes(pdf.output())
