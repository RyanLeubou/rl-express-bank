"""Données de référence : rôles, permissions, règles de risque, politiques, ATM, base de connaissances."""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.models import ATM, KnowledgeDocument, Permission, RiskRule, Role, RolePermission, SecurityPolicy
from app.models.enums import AtmStatus, PolicyDecision, RiskLevel, RiskOperation
from app.models.enums import SecurityActionType as A
from app.security.auth.passwords import hash_secret
from app.security.authz.catalog import PERMISSIONS, ROLE_INFO, ROLE_PERMISSIONS
from app.security.crypto.terminal import derive_terminal_secret

Op = RiskOperation
ALL_OPS = [o.value for o in RiskOperation]

# Poids EXPÉRIMENTAUX (simulation universitaire, pas des seuils bancaires réels)
RISK_RULES = [
    ("NEW_DEVICE", "Opération depuis un appareil jamais vu", ALL_OPS, 20, {}),
    ("NEW_LOCATION", "Ville inhabituelle pour ce client", ALL_OPS, 15, {}),
    ("UNUSUAL_AMOUNT", "Montant au-delà du 95e centile personnel",
     [Op.TRANSFER, Op.WITHDRAWAL_CARD, Op.WITHDRAWAL_CARDLESS, Op.CARD_PAYMENT], 20, {"percentile": 95}),
    ("UNUSUAL_TIME", "Heure hors de la plage habituelle (Africa/Douala)", ALL_OPS, 10,
     {"timezone": "Africa/Douala"}),
    ("MULTIPLE_WITHDRAWALS", "Au moins 3 retraits en 1 heure", [Op.WITHDRAWAL_CARD, Op.WITHDRAWAL_CARDLESS], 15,
     {"count": 3, "window_minutes": 60}),
    ("BEHAVIORAL_ANOMALY", "Score d'anomalie de l'IA comportementale (0 à 15 points)", ALL_OPS, 15,
     {"max_points": 15}),
    ("RECENT_BENEFICIARY", "Bénéficiaire ajouté il y a moins de 24 h", [Op.TRANSFER], 20, {"hours": 24}),
    ("FAILED_LOGINS_RECENT", "Échecs de connexion récents", [Op.LOGIN], 15, {"count": 3, "window_minutes": 30}),
    ("IMPOSSIBLE_TRAVEL", "Déplacement impossible entre deux opérations",
     [Op.LOGIN, Op.WITHDRAWAL_CARD, Op.WITHDRAWAL_CARDLESS], 25, {"max_speed_kmh": 900}),
    ("SCAM_SIGNAL_REPORTED", "Arnaque déclarée à RL SOLUTION il y a moins de 24 h",
     [Op.TRANSFER, Op.WITHDRAWAL_CARD, Op.WITHDRAWAL_CARDLESS, Op.BENEFICIARY], 25, {"hours": 24}),
    ("STRONG_AUTH_VERIFIED", "Authentification forte vérifiée pour cette opération", ALL_OPS, -20, {}),
    ("MULE_BENEFICIARY", "Bénéficiaire recevant des virements de plusieurs clients (compte « mule »)",
     [Op.TRANSFER, Op.BENEFICIARY], 25, {"distinct_senders": 3, "days": 7}),
    ("DRAIN_BALANCE", "Opération vidant plus de 80 % du solde", [Op.TRANSFER, Op.WITHDRAWAL_CARD,
                                                                 Op.WITHDRAWAL_CARDLESS], 20,
     {"share": 0.8, "min_amount": 100_000}),
    ("SECURITY_CHANGE_RECENT", "Mot de passe, MFA ou appareil modifié il y a moins de 24 h", ALL_OPS, 15,
     {"hours": 24}),
    ("SUSPICIOUS_ATM", "ATM marqué suspect par le SOC", [Op.WITHDRAWAL_CARD, Op.WITHDRAWAL_CARDLESS], 15, {}),
    ("STAFF_BULK_ACCESS", "Consultation en rafale de dossiers clients par un agent",
     [Op.SUPPORT_ACTION, Op.ADMIN_ACTION], 30, {"distinct_customers": 8, "window_minutes": 15}),
    ("STAFF_OFF_HOURS", "Accès du personnel aux données clients hors horaires de travail",
     [Op.SUPPORT_ACTION, Op.ADMIN_ACTION], 15, {"from_hour": 21, "to_hour": 6}),
    ("STAFF_UNASSIGNED_ACCESS", "Accès à un client sans ticket assigné ni fenêtre d'accès valide",
     [Op.SUPPORT_ACTION, Op.ADMIN_ACTION], 30, {}),
]

D = PolicyDecision
Lv = RiskLevel
BLOCK_ACTIONS = [A.REVOKE_SESSION, A.NOTIFY_CUSTOMER]
# (opération, LOW, MEDIUM, HIGH, CRITICAL, actions CRITICAL, plancher)
POLICIES = [
    (Op.LOGIN, D.ALLOW, D.STEP_UP_TOTP, D.STEP_UP_PASSKEY, D.BLOCK, [A.NOTIFY_CUSTOMER], None),
    (Op.BENEFICIARY, D.STEP_UP_TOTP, D.STEP_UP_TOTP, D.STEP_UP_PASSKEY, D.BLOCK, BLOCK_ACTIONS, D.STEP_UP_TOTP),
    (Op.TRANSFER, D.ALLOW, D.STEP_UP_TOTP, D.STEP_UP_PASSKEY, D.BLOCK, BLOCK_ACTIONS, None),
    (Op.CARD_PAYMENT, D.ALLOW, D.STEP_UP_TOTP, D.STEP_UP_PASSKEY, D.BLOCK, [A.LOCK_CARD, A.NOTIFY_CUSTOMER], None),
    (Op.WITHDRAWAL_CARD, D.ALLOW, D.STEP_UP_TOTP, D.STEP_UP_PASSKEY, D.BLOCK,
     [A.LOCK_CARD, A.REVOKE_SESSION, A.NOTIFY_CUSTOMER], None),
    (Op.WITHDRAWAL_CARDLESS, D.STEP_UP_TOTP, D.STEP_UP_TOTP, D.STEP_UP_TOTP, D.BLOCK,
     [A.CANCEL_CARDLESS_CODES, A.REVOKE_SESSION, A.BLOCK_DEVICE, A.NOTIFY_CUSTOMER], D.STEP_UP_TOTP),
    (Op.SECURITY_SETTINGS, D.STEP_UP_TOTP, D.STEP_UP_TOTP, D.STEP_UP_PASSKEY, D.BLOCK, BLOCK_ACTIONS,
     D.STEP_UP_TOTP),
    (Op.ADMIN_ACTION, D.STEP_UP_PASSKEY, D.STEP_UP_PASSKEY, D.STEP_UP_PASSKEY, D.BLOCK, [A.REVOKE_SESSION],
     D.STEP_UP_PASSKEY),
    (Op.SUPPORT_ACTION, D.ALLOW, D.STEP_UP_TOTP, D.STEP_UP_PASSKEY, D.BLOCK, [A.NOTIFY_CUSTOMER], None),
]

# code, nom, ville, lat, lon, statut
ATMS = [
    ("ATM-DLA-001", "RL Akwa", "Douala", 4.05110, 9.70430, AtmStatus.ONLINE),
    ("ATM-DLA-002", "RL Bonanjo", "Douala", 4.04350, 9.69050, AtmStatus.ONLINE),
    ("ATM-DLA-003", "RL Bonapriso", "Douala", 4.03200, 9.69500, AtmStatus.ONLINE),
    ("ATM-DLA-004", "RL Deïdo", "Douala", 4.06400, 9.70850, AtmStatus.ONLINE),
    ("ATM-DLA-005", "RL Makepe", "Douala", 4.07300, 9.75800, AtmStatus.MAINTENANCE),
    ("ATM-DLA-006", "RL Aéroport", "Douala", 4.00600, 9.71900, AtmStatus.ONLINE),
    ("ATM-YDE-001", "RL Yaoundé Centre", "Yaoundé", 3.86670, 11.51670, AtmStatus.ONLINE),
    ("ATM-YDE-002", "RL Bastos", "Yaoundé", 3.89600, 11.51300, AtmStatus.ONLINE),
    ("ATM-KRI-001", "RL Kribi Centre", "Kribi", 2.94000, 9.91000, AtmStatus.OFFLINE),
    ("ATM-BFS-001", "RL Bafoussam", "Bafoussam", 5.47800, 10.41700, AtmStatus.ONLINE),
]

# Base de connaissances de RL SOLUTION : informations PUBLIQUES uniquement (parcours de l'application, règles
# produit). Jamais de données client, de seuils anti-fraude ni de détails internes. Toute modification des fiches
# d'une base existante passe par une migration (voir 0005_knowledge_public_facts).
KNOWLEDGE = [
    ("a-propos", "À propos de RL EXPRESS BANK",
     "RL EXPRESS BANK est une banque virtuelle pédagogique : comptes, cartes, IBAN, distributeurs et opérations "
     "sont fictifs, aucun argent réel n'est en jeu. Les montants sont en francs CFA (XAF) et les heures suivent le "
     "fuseau de Douala. L'espace client comporte les menus Comptes, Virements, Cartes et paiements, Retraits, "
     "Sécurité et RL SOLUTION (l'assistant). Pour parler à un humain, écrivez « conseiller » à RL SOLUTION."),
    ("jamais-vos-codes", "RL EXPRESS BANK ne vous demandera jamais vos codes",
     "Aucun conseiller, ni RL SOLUTION, ne vous demandera votre mot de passe, le code de votre application "
     "d'authentification, un code de secours, votre PIN, le numéro complet ou le CVV de votre carte, ni un code de "
     "retrait sans carte. Si quelqu'un vous le demande, même en se présentant comme la banque, raccrochez ou ne "
     "répondez pas, puis décrivez la sollicitation à RL SOLUTION : un conseiller sécurité est prévenu. Si vous avez "
     "déjà donné un code, bloquez votre carte dans Cartes et paiements et révoquez les sessions inconnues dans "
     "Sécurité."),
    ("bonnes-pratiques-securite", "Bonnes pratiques de cybersécurité",
     "1. Mot de passe : au moins 12 caractères avec majuscules, minuscules et chiffres, propre à RL EXPRESS BANK et "
     "jamais réutilisé ailleurs ; un gestionnaire de mots de passe aide à les retenir. "
     "2. Activez la double authentification dans Sécurité et gardez vos codes de secours hors de votre téléphone. "
     "3. Ne communiquez jamais vos codes, PIN, CVV ou mot de passe, même à une personne qui dit appeler de la banque. "
     "4. Méfiez-vous des SMS, e-mails ou messages WhatsApp qui pressent d'agir (« compte bloqué », « urgent ») ou "
     "contiennent un lien : n'ouvrez pas le lien, accédez vous-même à l'application. "
     "5. Consultez régulièrement Sécurité (appareils, sessions actives, historique) et révoquez ce que vous ne "
     "reconnaissez pas ; lisez vos notifications. "
     "6. Vérifiez l'identité d'un bénéficiaire avant de l'ajouter, surtout si on vous presse de faire un virement. "
     "7. Au distributeur, cachez le clavier en tapant votre PIN et n'utilisez pas un appareil qui semble modifié. "
     "8. Gardez votre téléphone et votre navigateur à jour, verrouillez l'écran, évitez les opérations bancaires sur "
     "un Wi-Fi public ou un ordinateur partagé, et déconnectez-vous après usage. "
     "9. En cas de doute : bloquez votre carte dans Cartes et paiements, puis écrivez à RL SOLUTION."),
    ("rib-iban", "Trouver et partager mon RIB / IBAN",
     "Votre IBAN figure sur votre RIB, dans le menu Comptes : sur le compte voulu, choisissez Afficher mon RIB. Le RIB "
     "indique le titulaire, la banque, le code banque et le code guichet, le numéro de compte avec sa clé, l'IBAN et "
     "le BIC. Le bouton Copier l'IBAN le copie sans espaces. Vous pouvez donner votre IBAN sans risque à une personne "
     "qui doit vous verser de l'argent : il ne permet pas de retirer de l'argent de votre compte. Chaque compte "
     "(compte courant, livret épargne) a son propre RIB. Les numéros restent masqués tant que vous n'affichez pas le "
     "RIB, et RL SOLUTION ne peut pas lire votre IBAN à votre place. Format : CM, 2 chiffres de contrôle, puis 23 "
     "chiffres (code banque 5, code guichet 5, numéro de compte 11, clé RIB 2)."),
    ("ouvrir-un-compte", "Ouvrir un compte en ligne",
     "Sur la page d'inscription, saisissez nom, prénom, adresse, ville, téléphone, profession, e-mail et un mot de "
     "passe d'au moins 12 caractères (majuscule, minuscule et chiffre). La banque crée aussitôt un compte courant, "
     "son RIB rattaché à l'agence de votre ville, et une carte de débit valable 3 ans dont le PIN est affiché une "
     "seule fois : notez-le. Une adresse e-mail déjà utilisée est refusée."),
    ("livret-epargne", "Ouvrir mon livret épargne",
     "Dans Comptes, le bouton Ouvrir mon livret épargne crée un livret avec un solde de 0 et son propre RIB, dans la "
     "même agence que votre compte courant. Un seul livret est possible par client. Dans Comptes, l'œil à côté du "
     "solde masque ou affiche vos montants sur cet appareil."),
    ("virements-beneficiaires", "Ajouter un bénéficiaire et faire un virement",
     "Dans Virements, ajoutez un bénéficiaire avec son prénom, son nom, sa banque et son IBAN. Il est activé après "
     "une vérification par code ; s'il reste « Pas encore vérifié », utilisez le bouton Vérifier. Choisissez ensuite "
     "le compte, le bénéficiaire et le montant en XAF, puis Envoyer le virement. Un virement inhabituel peut "
     "demander une confirmation par code, ou être refusé par mesure de sécurité. Chaque virement dispose d'un avis "
     "de virement en PDF (Télécharger le PDF ou Partager)."),
    ("carte-plafonds", "Ma carte : détails, plafonds et paiements",
     "Dans Cartes et paiements, l'œil de la carte affiche son numéro complet et son CVV pendant 30 secondes. Plafonds "
     "par défaut : 500 000 XAF de retraits et 1 000 000 XAF de paiements par jour. Le PIN compte 4 chiffres ; trois "
     "PIN erronés bloquent la carte. La carte est valable 3 ans. La section Derniers paiements liste vos achats."),
    ("carte-bloquee", "Bloquer ou débloquer ma carte",
     "En cas de perte, de vol ou de doute, utilisez Bloquer ma carte dans Cartes et paiements. Une carte peut aussi "
     "être bloquée après trois PIN erronés ou par mesure de sécurité. Vous pouvez la débloquer au même endroit avec "
     "Débloquer (avec code), sauf si le blocage vient d'une alerte de sécurité : écrivez alors « conseiller » à RL "
     "SOLUTION pour qu'un conseiller vérifie votre identité."),
    ("retrait-sans-carte", "Retirer sans carte",
     "Dans Retraits, choisissez le compte et le montant, puis Générer un code de retrait, et confirmez avec votre "
     "code de vérification. Vous obtenez une référence et un code, affichés une seule fois : notez-les et "
     "présentez-les au distributeur. Ils sont valables 15 minutes et utilisables une seule fois ; les fonds sont "
     "réservés jusqu'au retrait ou à l'expiration. Annuler ce code libère les fonds."),
    ("operation-refusee", "Pourquoi mon opération a été refusée",
     "Une opération peut être refusée pour solde insuffisant, plafond journalier atteint, carte ou compte bloqué, "
     "ou par précaution quand elle ne ressemble pas à vos habitudes. Dans ce dernier cas, une confirmation par code "
     "peut être demandée ; si l'opération reste bloquée, écrivez « conseiller » à RL SOLUTION. Le détail des "
     "contrôles de sécurité n'est pas communiqué, pour ne pas aider les fraudeurs."),
    ("double-authentification", "Activer la double authentification",
     "Dans Sécurité, choisissez Activer la double authentification, saisissez votre mot de passe actuel, scannez le "
     "QR code avec une application d'authentification (Google Authenticator, Microsoft Authenticator, Aegis…), puis "
     "saisissez le code à 6 chiffres affiché. Des codes de secours s'affichent une seule fois : conservez-les en "
     "lieu sûr, ils servent si vous perdez votre téléphone. Le code est ensuite demandé pour les opérations "
     "sensibles."),
    ("appareils-sessions", "Mes appareils, sessions et historique de sécurité",
     "Dans Sécurité, Mes appareils liste les appareils connectés à votre compte : Faire confiance pour les vôtres, "
     "Révoquer pour ceux que vous ne reconnaissez pas. Sessions actives montre où vous êtes connecté et Mon "
     "historique de sécurité retrace connexions et changements. Un appareil ou une session inconnus doivent être "
     "révoqués, puis signalés à RL SOLUTION."),
]


def seed_reference(db: Session) -> dict[str, Role]:
    perms = {code: Permission(code=code, description=desc, requires_step_up=step)
             for code, (desc, step) in PERMISSIONS.items()}
    db.add_all(perms.values())
    roles: dict[str, Role] = {}
    for code, (name, desc, staff) in ROLE_INFO.items():
        roles[code] = Role(code=code.value, name=name, description=desc, is_staff=staff)
    db.add_all(roles.values())
    db.flush()
    for code, perm_codes in ROLE_PERMISSIONS.items():
        db.add_all(RolePermission(role_id=roles[code].id, permission_id=perms[p].id) for p in perm_codes)

    db.add_all(RiskRule(code=c, description=d, operation_types=[str(o) for o in ops], weight=w, params=p)
               for c, d, ops, w, p in RISK_RULES)
    for op, low, med, high, crit, actions, floor in POLICIES:
        for level, decision in ((Lv.LOW, low), (Lv.MEDIUM, med), (Lv.HIGH, high), (Lv.CRITICAL, crit)):
            db.add(SecurityPolicy(operation_type=op, risk_level=level, decision=decision, floor_decision=floor,
                                  actions=[str(a) for a in actions] if level == Lv.CRITICAL else []))
    for code, name, city, lat, lon, status in ATMS:
        db.add(ATM(atm_code=code, name=name, city=city, country="CM", latitude=lat, longitude=lon,
                   status=status, terminal_secret_hash=hash_secret(derive_terminal_secret(code))))
    db.add_all(KnowledgeDocument(slug=s, title=t, body=b) for s, t, b in KNOWLEDGE)
    db.flush()
    return roles
