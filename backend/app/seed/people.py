"""Personnes fictives : personnel de la banque et clients avec leurs habitudes.

Identifiants de DÉMONSTRATION uniquement (documentés dans le README). Domaine .test réservé (RFC 2606) :
aucune adresse ne peut appartenir à une personne réelle.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.models.enums import MerchantCategory as M
from app.models.enums import RoleCode

DOMAIN = "demo.rl-express-bank.test"
DEMO_PASSWORDS = {
    RoleCode.SUPER_ADMIN: "Admin!Demo2026",
    RoleCode.SECURITY_ANALYST: "Analyst!Demo2026",
    RoleCode.AUDITOR: "Auditor!Demo2026",
    RoleCode.SUPPORT_AGENT: "Support!Demo2026",
    RoleCode.CLIENT: "Client!Demo2026",
}
DEMO_CARD_PIN = "1234"  # PIN simulé de toutes les cartes de démonstration

STAFF = [
    ("admin", "Hélène", "Kamga", RoleCode.SUPER_ADMIN),
    ("analyste1", "Boris", "Ndjock", RoleCode.SECURITY_ANALYST),
    ("analyste2", "Linda", "Owona", RoleCode.SECURITY_ANALYST),
    ("auditeur", "Roger", "Etoa", RoleCode.AUDITOR),
    ("support1", "Sandrine", "Mballa", RoleCode.SUPPORT_AGENT),
    ("support2", "Yves", "Nkoulou", RoleCode.SUPPORT_AGENT),
]


@dataclass
class ClientProfile:
    login: str
    first_name: str
    last_name: str
    city: str
    salary: int
    opening: int
    withdrawal_range: tuple[int, int]
    withdrawals_per_week: float
    hours: tuple[int, int]                 # heures locales habituelles (Africa/Douala)
    usual_atms: list[str]
    payments_per_week: float
    categories: dict[M, int]
    transfers_per_month: float
    device: tuple[str, str, str]           # nom, OS, navigateur
    savings: int = 0
    secondary: bool = False
    extra_device: tuple[str, str, str] | None = None
    cardless_share: float = 0.1
    tags: list[str] = field(default_factory=list)


CLIENTS = [
    # Profil de référence du cahier des charges (scénario de démonstration)
    ClientProfile("jean.dupont", "Jean", "Dupont", "Douala", 450_000, 600_000, (20_000, 50_000), 1.5, (8, 20),
                  ["ATM-DLA-004", "ATM-DLA-001"], 3, {M.FOOD: 5, M.TRANSPORT: 3, M.RESTAURANT: 2,
                                                     M.SHOPPING: 1}, 2, ("iPhone de Jean", "iOS", "Safari"),
                  savings=1_200_000, tags=["demo-principal"]),
    ClientProfile("fatima.bello", "Fatima", "Bello", "Yaoundé", 620_000, 900_000, (30_000, 80_000), 1.0, (9, 19),
                  ["ATM-YDE-001", "ATM-YDE-002"], 4, {M.FOOD: 3, M.TECHNOLOGY: 2, M.RESTAURANT: 3,
                                                     M.SHOPPING: 2}, 3, ("Pixel de Fatima", "Android", "Chrome"),
                  savings=2_500_000, secondary=True, extra_device=("PC bureau", "Windows", "Edge")),
    ClientProfile("paul.mbarga", "Paul", "Mbarga", "Douala", 280_000, 300_000, (10_000, 30_000), 2.0, (7, 21),
                  ["ATM-DLA-002", "ATM-DLA-003"], 3, {M.FOOD: 6, M.TRANSPORT: 4, M.OTHER: 1}, 1,
                  ("Galaxy de Paul", "Android", "Chrome"), cardless_share=0.3),
    ClientProfile("marie.nguema", "Marie", "Nguema", "Yaoundé", 850_000, 1_500_000, (50_000, 150_000), 0.7,
                  (10, 18), ["ATM-YDE-002"], 5, {M.HOTEL: 1, M.RESTAURANT: 4, M.SHOPPING: 3, M.TRAVEL: 1},
                  2, ("MacBook de Marie", "macOS", "Safari"), savings=4_000_000,
                  extra_device=("iPhone de Marie", "iOS", "Safari")),
    ClientProfile("samuel.tchoupo", "Samuel", "Tchoupo", "Douala", 350_000, 400_000, (15_000, 40_000), 1.5, (8, 22),
                  ["ATM-DLA-001", "ATM-DLA-006"], 3, {M.FOOD: 4, M.TECHNOLOGY: 2, M.TRANSPORT: 2}, 2,
                  ("Redmi de Samuel", "Android", "Chrome")),
    ClientProfile("grace.eyenga", "Grace", "Eyenga", "Kribi", 300_000, 350_000, (20_000, 60_000), 1.0, (9, 18),
                  ["ATM-DLA-003"], 2, {M.FOOD: 5, M.HOTEL: 1, M.RESTAURANT: 2}, 1,
                  ("Tecno de Grace", "Android", "Chrome"), savings=800_000),
    ClientProfile("ibrahim.moussa", "Ibrahim", "Moussa", "Bafoussam", 400_000, 500_000, (25_000, 70_000), 1.0,
                  (6, 19), ["ATM-BFS-001"], 2, {M.FOOD: 4, M.TRANSPORT: 3, M.OTHER: 2}, 2,
                  ("Infinix d'Ibrahim", "Android", "Chrome"), secondary=True),
    ClientProfile("clarisse.fotso", "Clarisse", "Fotso", "Douala", 520_000, 700_000, (20_000, 60_000), 1.2,
                  (8, 20), ["ATM-DLA-004", "ATM-DLA-002"], 4, {M.SHOPPING: 3, M.RESTAURANT: 3, M.FOOD: 3,
                                                               M.TECHNOLOGY: 1}, 3,
                  ("iPhone de Clarisse", "iOS", "Safari"), savings=1_500_000),
]

EXTERNAL_BANKS = [("Banque Sahel Démo", "99991"), ("Crédit Wouri Démo", "99992"), ("Caisse Sanaga Démo", "99993")]
EXTERNAL_PEOPLE = [("Alain", "Biya-Démo"), ("Esther", "Manga"), ("Rodrigue", "Tchami"), ("Nadège", "Ekwalla"),
                   ("Thierry", "Abena"), ("Josiane", "Kouam"), ("Martin", "Oyono"), ("Carine", "Ngo Bassa")]

MERCHANTS = {
    M.FOOD: [("Supermarché Wouri", 3_000, 35_000), ("Marché Central Épicerie", 2_000, 15_000)],
    M.TRANSPORT: [("Taxi Express", 1_000, 5_000), ("Station Carburant Démo", 10_000, 40_000)],
    M.TECHNOLOGY: [("Tech Store Akwa", 15_000, 250_000), ("Recharge Mobile Démo", 1_000, 10_000)],
    M.HOTEL: [("Hôtel Sanaga Démo", 45_000, 120_000)],
    M.RESTAURANT: [("Restaurant Le Ndolé", 5_000, 25_000), ("Café du Port", 2_000, 8_000)],
    M.SHOPPING: [("Boutique Mode Bonapriso", 10_000, 80_000), ("Librairie Centrale Démo", 3_000, 20_000)],
    M.TRAVEL: [("Agence Voyage Démo", 60_000, 250_000)],
    M.OTHER: [("Pharmacie Démo", 2_000, 20_000)],
}
