# RL EXPRESS BANK

Banque virtuelle pédagogique et laboratoire de cybersécurité (projet universitaire).
**Tout est simulé** : comptes, cartes, IBAN, ATM, utilisateurs et attaques sont fictifs.
Aucune connexion à une banque, un réseau de paiement ou une carte réelle.

> État : **Phase 5 complète + IA branchée.** Banque (ouverture de compte en ligne, comptes, livret épargne, virements,
> cartes, retraits, ATM), moteur de risque à règles explicables **complété par une IA comportementale (Isolation
> Forest)**, réponse automatisée, SOC, administration, audit, assistant **RL SOLUTION propulsé par un LLM open source
> hébergé (Groq, offre gratuite)**, laboratoire d'attaques et interfaces par profil. Wazuh et GoPhish sont volontairement laissés pour plus tard.

## Services

| Service | Rôle | Accès |
| --- | --- | --- |
| `caddy` | Point d'entrée unique, TLS local, en-têtes de sécurité | https://bank.localhost |
| `frontend` | SPA React + TypeScript + Vite + Tailwind | via Caddy |
| `api` | FastAPI : santé, erreurs RFC 9457, logs JSON masqués, docs hors ligne, IA comportementale | https://bank.localhost/api/docs |
| `worker` | Processus de fond (heartbeat, registre de jobs) | interne |
| `postgres` | PostgreSQL 16, 3 rôles séparés | interne uniquement |
| `valkey` | Cache (rate limiting, challenges) | interne uniquement |
| `mailpit` | Boîte e-mail simulée | http://127.0.0.1:8025 |

PostgreSQL et Valkey sont sur un réseau Docker **interne** : aucun port publié, aucune sortie Internet.
Seule l'API sort vers Internet (réseau `edge`), pour joindre le LLM hébergé de RL SOLUTION en HTTPS.

## Base de données (Phase 3)

44 tables réparties en 7 domaines : identité et RBAC, authentification, banque, monétique,
sécurité et SOC, RL SOLUTION, analytique. Migrations Alembic : `0001` crée tout le schéma, `0002` ajoute la
profession du client, `0003` donne au client la permission d'ouvrir un livret épargne, `0004` supprime la table
vectorielle `knowledge_chunks` (fin d'Ollama), `0005` ajoute et corrige les fiches de RL SOLUTION. Elles s'appliquent
automatiquement au démarrage de l'API (`make migrate` pour les forcer).

| Garantie | Mécanisme |
| --- | --- |
| Pas de solde client négatif, disponible ≤ solde | Contraintes CHECK |
| Comptabilité exacte | Grand livre en partie double : chaque journal a une somme nulle |
| Pas de double débit concurrent | `SELECT ... FOR UPDATE`, comptes verrouillés dans un ordre fixe |
| Historique infalsifiable | `audit_logs`, `ledger_entries`, `security_events` en ajout seul (droits + trigger, même pour le propriétaire) |
| Falsification détectable | Journal d'audit chaîné par SHA-256 |
| Aucun secret en clair | Mots de passe, PIN simulés et secrets ATM en Argon2id ; codes sans carte en HMAC ; aucun PAN complet ni CVV stocké (recalculés à l'affichage, voir « Cartes ») |
| Événements jamais perdus | Transactional outbox écrite dans la même transaction que l'opération |

Vérification à tout moment : `make integrity`.

## Authentification (Phase 4)

| Besoin | Mécanisme |
| --- | --- |
| Aucun jeton accessible au JavaScript | Session en cookies `HttpOnly` + `Secure` + `SameSite=Strict` (préfixes `__Host-` / `__Secure-`) ; JWT d'accès Ed25519 de 10 min ; seul le jeton CSRF est lisible |
| Vol de jeton de rafraîchissement | Usage unique, rotation à chaque renouvellement ; une réutilisation révoque toute la famille de sessions et lève un événement `SESSION_REVOKED` de sévérité HIGH |
| Session révoquée = coupée immédiatement | Chaque requête vérifie l'état de la session en base, pas seulement la signature du jeton |
| CSRF et requêtes d'une autre origine | Jeton signé HMAC lié à la session + contrôle de l'en-tête `Origin` |
| Second facteur | TOTP (RFC 6238) : secret chiffré AES-256-GCM lié à l'utilisateur, rejeu d'un même code refusé, 10 codes de secours à usage unique |
| Activation du TOTP | **QR code** à scanner, lien `otpauth://` pour l'ouvrir directement sur le téléphone, ou clé à saisir à la main |
| Qui doit l'utiliser | Personnel : toujours (activation forcée à la première connexion). Client : s'il l'a activé et que l'appareil n'est pas de confiance, et pour toute opération sensible (step-up) |
| Appareils | Identifiant aléatoire en cookie (hash en base) ; « de confiance » seulement après un TOTP réussi et un choix explicite |
| Devinette de mots de passe | Ralentissement progressif (1 s, 2 s, 4 s… plafond 15 min) sur trois portées : compte+IP, IP, compte. Jamais de blocage définitif : un attaquant ne peut pas enfermer sa victime dehors |
| Énumération de comptes | Message et temps de réponse identiques (hash factice) ; la vraie raison n'est écrite que dans l'événement de sécurité |
| Ouvertures de compte en masse | Inscription limitée par adresse IP (même ralentissement progressif) |
| Panne du cache de sécurité | Les connexions sont refusées (503) plutôt que d'être acceptées sans protection |

Routes : `POST /auth/register`, `GET /auth/register/cities`, `POST /auth/login`, `/auth/mfa/verify`,
`/auth/mfa/enroll/start|confirm`, `/auth/refresh`, `/auth/logout`, `GET /auth/me`, `GET /auth/sessions`,
`DELETE /auth/sessions/{id}`. Événements émis : `USER_REGISTERED`, `USER_LOGIN`, `LOGIN_FAILED`, `NEW_DEVICE_LOGIN`,
`MFA_SUCCESS`, `MFA_FAILURE`, `MFA_LOCKOUT`, `MFA_ENABLED`, `RECOVERY_CODE_USED`, `SESSION_REVOKED`, `USER_LOGOUT`.
Un client sans TOTP qui se connecte depuis un appareil inconnu obtient une session de niveau 1 et un
`NEW_DEVICE_LOGIN` : le moteur de risque et le step-up exigeront le second facteur pour les opérations sensibles.

**Activer la double authentification (client)** : espace client > **Sécurité** > mot de passe actuel >
**Activer la double authentification**, puis scannez le QR code avec Google Authenticator, Microsoft Authenticator,
Aegis ou 2FAS et saisissez le code affiché. Sans cette activation, un nouveau bénéficiaire ne peut pas être vérifié :
la fenêtre de vérification l'explique et renvoie vers la page Sécurité.

**Première connexion du personnel** : après le mot de passe, la page affiche le même QR code, puis 10 codes de secours
(affichés une seule fois). Gardez l'application d'authentification : `make reset` efface les activations.

## Application complète (Phase 5)

| Espace | URL | Contenu |
| --- | --- | --- |
| Accueil | `/` | Relevé d'état de la plateforme, boutons « Ouvrir un compte » et « Se connecter » |
| Inscription | `/inscription` | Ouverture de compte en ligne (voir ci-dessous) |
| Client | `/espace` | Comptes, soldes masquables, carte, RIB, livret épargne, bénéficiaires, virements, cartes et paiements, retraits (ATM, sans carte), appareils, notifications, aide RL SOLUTION |
| SOC | `/soc` | Tableau de bord, alertes (raisons, MITRE ATT&CK, actions réversibles), événements, évaluations de risque (score IA inclus), investigations, dossiers clients tracés |
| Administration | `/admin` | Règles et politiques de risque (versionnées, justification obligatoire), utilisateurs, réinitialisation MFA, laboratoire d'attaques, audit |
| Audit | `/audit` | Lecture seule : journal chaîné, vérification d'intégrité, export CSV, alertes, événements |
| Support | `/agent` | File de tickets, accès au dossier limité au ticket pris en charge (2 h), verrouillage de carte à la demande du client |
| Borne ATM | `/atm` | Terminal simulé (code + secret) : validation d'un retrait sans carte |

**Ouverture de compte en ligne** (`/inscription`). Le futur client saisit nom, prénom, adresse, ville, téléphone,
profession, e-mail et mot de passe (12 caractères minimum, majuscule, minuscule et chiffre). La banque crée alors :

- un **compte courant** (le livret épargne s'ouvre ensuite depuis l'espace client) ;
- son **RIB / IBAN** fictif, dont le code guichet dépend de l'**agence attribuée selon la ville** (21 villes
  rattachées aux agences Douala `00101`, Yaoundé `00201`, Kribi `00301`, Bafoussam `00401` ; liste dans
  `CITY_AGENCY`, `backend/app/services/banking/rib.py`) ;
- une **carte de débit** valable 3 ans, avec un **PIN tiré au hasard, affiché une seule fois** puis stocké haché.

Le client est connecté immédiatement. Une adresse déjà utilisée est refusée (message explicite).

**Comptes et livret épargne.** Sur « Mes comptes », un **œil** à côté du solde masque ou affiche les montants (préférence
mémorisée sur l'appareil). Tant que le client n'a pas de livret, le bouton **Ouvrir mon livret épargne** crée un
livret (solde 0, RIB propre, même agence) ; un seul livret par client (`POST /accounts/savings`, événement
`ACCOUNT_OPENED`, journal d'audit).

**Cartes.** La carte apparaît à côté du solde et sur la page Cartes. Son **œil** affiche le numéro complet et le CVV,
qui se masquent seuls après 30 s. Ils ne sont **jamais stockés** : ils sont recalculés à chaque affichage par HMAC
à partir du jeton de la carte et d'une sous-clé de `DATA_ENCRYPTION_KEY`, à la manière d'un HSM qui dérive un CVV
(BIN fictif `999990`, 4 derniers chiffres conservés, contrôle de Luhn respecté). Chaque affichage est tracé
(`CARD_VIEWED`). Route : `GET /cards/{id}/details`.

**Bénéficiaires.** Un clic sur un bénéficiaire ouvre sa **fiche complète** (IBAN entier, banque, dates d'ajout et de
vérification, derniers virements ; événement `BENEFICIARY_VIEWED`). Un bénéficiaire resté en attente a un bouton
**Vérifier** qui relance la vérification par code TOTP (risque réévalué, code neuf). Routes :
`GET /beneficiaries/{id}`, `POST /beneficiaries/{id}/verify`.

**Virements.** La liste « Derniers virements » réunit les virements **émis** et **reçus** (virements d'autres clients
RL EXPRESS BANK et salaires), avec un filtre Tous / Reçus / Émis. Un clic ouvre le détail : motif, émetteur ou
bénéficiaire, banque, IBAN (masqué pour un émetteur, complet pour vos propres bénéficiaires), compte débité ou
crédité, dates, analyse de sécurité et motif de refus éventuel. Un client ne voit jamais les crédits d'un autre.
Routes : `GET /transfers`, `GET /transfers/sent/{id}`, `GET /transfers/received/{seq}`.
Depuis le détail, **Télécharger le PDF** produit un avis de virement (émis ou reçu) et **Partager** ouvre la feuille de
partage du système (AirDrop, Mail, WhatsApp…) avec le PDF en pièce jointe ; sur un navigateur qui ne le permet pas,
le PDF est téléchargé pour être joint à la main. Chaque génération est tracée (`TRANSFER_RECEIPT_DOWNLOADED`).
Routes : `GET /transfers/sent/{id}/receipt.pdf`, `GET /transfers/received/{seq}/receipt.pdf`.

**Décision de risque.** Chaque opération sensible (nouveau bénéficiaire, virement, paiement, retrait, changement
de sécurité) est évaluée par 17 règles pondérées et explicables (`risk_rules`), dont `BEHAVIORAL_ANOMALY` alimentée
par l'IA comportementale, puis une politique (`security_policies`) décide : `ALLOW`, `ALLOW_AND_MONITOR`,
`STEP_UP_TOTP`, `STEP_UP_PASSKEY` ou `BLOCK`. Seuils : moyen 30, élevé 60, critique 80 (`RISK_MEDIUM_FROM`,
`RISK_HIGH_FROM`, `RISK_CRITICAL_FROM`). Sans politique applicable, l'opération est **refusée** (fail-closed).
Le renforcement d'authentification passe par un code TOTP **neuf** (anti-rejeu : un code déjà utilisé est refusé).

**Réponse automatisée.** Selon la politique : verrouillage de carte, révocation de session, blocage d'appareil,
annulation des codes sans carte, gel de compte, notification, changement de mot de passe forcé. Tout est réversible
sauf la révocation de session et la notification. Les alertes sont regroupées par client et par heure.

**UEBA du personnel.** Chaque consultation de dossier est tracée ; accès hors périmètre refusé, accès en masse et
hors horaires signalés.

**Laboratoire.** Avec `LAB_MODE=true`, six scénarios d'attaque simulés (page Administration > Laboratoire). Les événements
sont marqués « simulation » et n'alimentent ni les profils de comportement ni l'entraînement de l'IA.

**Borne ATM** (`https://bank.localhost/atm`). Le « code du terminal » est l'identifiant d'un ATM en service
(`ATM-DLA-001`, `-002`, `-003`, `-004`, `-006`, `ATM-YDE-001`…). Son secret se calcule avec :

```bash
make atm-secret ATM=ATM-DLA-001
# équivalent : docker compose exec -e PYTHONPATH=/app api python scripts/atm_secret.py ATM-DLA-001
```

Référence (8 caractères) et code (6 chiffres) : créez un retrait sans carte dans l'espace client > Retraits.

## Intelligence artificielle

Les deux modèles tournent **en local** : aucune donnée ne quitte la machine. Si l'un d'eux est absent ou en panne,
la banque continue de fonctionner sans lui (règles seules, réponses par mots-clés).

### IA comportementale (moteur de risque)

| Élément | Détail |
| --- | --- |
| Modèle | Isolation Forest (scikit-learn, 200 arbres), détection d'anomalies non supervisée |
| Code | `backend/app/ai/behavior.py`, branché sur `app/risk/scorer.py` au démarrage de l'API |
| Variables | Toutes **relatives aux habitudes du client** : montant / médiane habituelle, rareté de l'heure, nouveauté de la ville, appareil inconnu, opérations des dernières 24 h, temps depuis la dernière opération, nuit, type d'opération |
| Entraînement | Rejoue l'historique (hors simulations) : chaque opération est décrite par rapport à celles qui la précèdent. Automatique au premier démarrage, ou `make ai-train` |
| Score | 0 = habituel, 1 = très anormal, calibré sur l'entraînement (percentile 50 → 0, percentile 99,5 → 1) ; jusqu'à 15 points de risque |
| Démarrage à froid | Moins de 10 opérations établies : pas d'avis, les règles décident seules |
| Intégrité | Le fichier du modèle est vérifié (SHA-256 et liste des variables) avant chargement ; un fichier modifié est refusé |
| Traçabilité | Score IA et version du modèle enregistrés dans chaque évaluation, visibles dans le SOC |

Exemple sur Jean Dupont : retrait habituel à Douala → 0,07 ; retrait de 450 000 XAF à Lagos à 3 h → 1,0.
Le modèle est stocké dans le volume Docker `ai_models`. Après l'ajout de nouvelles données, `make ai-train`
le ré-entraîne et redémarre l'API.

Pour brancher un autre modèle, implémentez `score(ctx, baseline) -> float | None` et appelez
`set_scorer(MonModele())` au démarrage (`app/main.py`). `ctx` (`risk/context.py`) donne montant, heure, ville,
appareil, opération ; `baseline` (`risk/state.py`) donne l'historique du client. Si le modèle échoue ou renvoie
`None`, les règles décident seules (`degraded=True`). Test de référence : `backend/tests/integration/test_scorer_hook.py`.

### RL SOLUTION (assistant du support)

| Élément | Détail |
| --- | --- |
| Modèle | `openai/gpt-oss-120b` (open source, Apache 2.0), hébergé par Groq, offre gratuite ; tout service compatible OpenAI convient (`LLM_BASE_URL`, `LLM_MODEL`) |
| Code | `backend/app/ai/assistant_llm.py`, appelé par `app/services/support/assistant.py` |
| Fonctionnement | La fiche `a-propos` (noms des menus) et les 3 fiches qui partagent le plus de mots avec la question (racines de 5 lettres, titre compté double ; toutes si aucune ne correspond) sont transmises, plus les agences et distributeurs lus en direct quand la question en parle ; le LLM rédige 2 à 5 phrases en texte brut **à partir de ces informations uniquement**. Environ 800 tokens par question au lieu de 2 500 : nécessaire pour l'offre gratuite de Groq (8 000 tokens par minute et 1 000 requêtes par jour pour chaque modèle, lus dans les en-têtes `x-ratelimit-*`), soit environ 6 questions par minute |
| Données envoyées | Le message **déjà masqué** (codes, PIN, OTP remplacés par `[MASQUÉ]`) et les informations publiques, en HTTPS, à un service tiers : aucune donnée de compte. Le LLM sait qu'il n'a accès ni au solde, ni à l'IBAN, ni aux opérations du client : il indique où les trouver |
| Injection de prompt | Le message du client est encadré comme une donnée, jamais comme une consigne ; le LLM n'a aucun outil et ne peut agir sur aucun compte |
| Réponses refusées | Toute phrase qui demande un code, un PIN ou un mot de passe est rejetée (« ne communiquez jamais votre code » reste permis) |
| Repli | Pas de clé, service indisponible, quota gratuit atteint (HTTP 429) ou trop lent (30 s) : la fiche qui partage le plus de mots avec la question (mots du titre comptés double) |
| Inchangé | Détection d'arnaque et escalade vers un conseiller humain restent gérées par des règles, avant le LLM |

Activation : chaque installation utilise **sa propre clé gratuite**. Créez un compte sur https://console.groq.com,
générez une clé dans *API Keys*, collez-la dans `LLM_API_KEY` du fichier `.env`, puis `docker compose up -d api`.
Ne publiez jamais cette clé (dépôt Git, capture d'écran). Les quotas gratuits sont limités par minute et par jour
(voir *Settings > Limits* dans la console Groq). Laissez `LLM_API_KEY` vide pour désactiver le LLM.
En tests (`APP_ENV=test`), les deux IA sont désactivées pour garder des résultats reproductibles.

#### Base de connaissances

Les fiches ne contiennent que des **informations publiques** : parcours de l'application et règles produit.
Source unique : `KNOWLEDGE` dans `backend/app/seed/reference.py`.

| Fiche (`slug`) | Contenu |
| --- | --- |
| `a-propos` | Banque fictive, devise XAF, fuseau de Douala, menus de l'espace client, « conseiller » pour un humain |
| `jamais-vos-codes` | Ce que la banque ne demande jamais (mot de passe, codes, PIN, CVV…) et que faire face à une sollicitation |
| `bonnes-pratiques-securite` | 9 conseils : mot de passe, double authentification, hameçonnage, appareils, distributeur, Wi-Fi public, en cas de doute |
| `rib-iban` | Trouver son IBAN (Comptes > Afficher mon RIB), le copier, le partager sans risque, format CM + 25 chiffres |
| `ouvrir-un-compte` | Inscription en ligne : informations demandées, compte courant, RIB, carte et PIN affiché une seule fois |
| `livret-epargne` | Ouverture du livret (un par client), masquage des soldes |
| `virements-beneficiaires` | Ajout et vérification d'un bénéficiaire, envoi d'un virement, avis de virement en PDF |
| `carte-plafonds` | Numéro et CVV visibles 30 s, plafonds par défaut (500 000 XAF de retraits, 1 000 000 XAF de paiements par jour), PIN |
| `carte-bloquee` | Bloquer ou débloquer sa carte, blocage après trois PIN erronés ou par sécurité |
| `retrait-sans-carte` | Code de retrait : référence et code valables 15 minutes, usage unique, fonds réservés, annulation |
| `operation-refusee` | Causes d'un refus (solde, plafond, blocage, précaution) et que faire |
| `double-authentification` | Activation dans Sécurité, applications compatibles, codes de secours |
| `appareils-sessions` | Faire confiance ou révoquer un appareil, sessions actives, historique de sécurité |

S'y ajoutent, recalculées à chaque question : la banque, son BIC et ses agences avec leurs codes guichet et les
villes rattachées (`app/services/banking/rib.py`), puis la liste des distributeurs et leur état (en service, en
maintenance, hors service), lue dans la table `atms`.

**Volontairement exclus** : règles et seuils anti-fraude (ils aideraient un fraudeur à les contourner), toute donnée
d'un client (solde, IBAN, opérations, contacts), secrets et coordonnées internes des distributeurs.

**Modifier les fiches** : éditez `KNOWLEDGE`, puis ajoutez une migration qui applique le changement aux bases
existantes, sur le modèle de `0005_knowledge_public_facts` (insère les nouvelles fiches et met à jour celles dont le
texte a changé, en incrémentant `version`). Une installation neuve reçoit les fiches par le seed. Les fiches doivent
reprendre les libellés exacts de l'interface : le LLM les cite au client.

## Créer les comptes

**Aucun compte n'existe à l'installation** : pas d'identifiant ni de mot de passe par défaut. Au premier démarrage,
l'API initialise seulement la plateforme (rôles et permissions, règles de risque, 10 ATM simulés, base de
connaissances, comptes internes de la banque).

**Clients** : chacun crée son compte sur https://bank.localhost/inscription (voir « Ouverture de compte en ligne »).
Il reçoit aussitôt un compte courant, son RIB et une carte dont le PIN s'affiche une seule fois.

**Personnel** (administration, SOC, audit, support) : l'exploitant le crée en ligne de commande. Le mot de passe est
saisi au clavier, jamais en argument, avec la même règle qu'à l'inscription :

```bash
make staff ROLE=SUPER_ADMIN EMAIL=prenom.nom@exemple.test PRENOM=Prénom NOM=Nom
# Rôles : SUPER_ADMIN, SECURITY_ANALYST, AUDITOR, SUPPORT_AGENT
```

À la première connexion, le compte du personnel doit activer la double authentification. Chaque création est
inscrite au journal d'audit (`STAFF_ACCOUNT_CREATED`).

**Démonstration locale (facultatif)** : `SEED_DEMO_DATA=true` dans `.env` (ou `make seed-demo`) ajoute du personnel
et 8 clients fictifs avec 90 jours d'historique, utiles pour entraîner l'IA comportementale et rejouer le scénario
du jury. Leurs mots de passe sont connus (`backend/app/seed/people.py`) : **à n'activer que sur votre propre machine,
jamais sur une instance accessible à d'autres**. Sans ces données, l'IA comportementale attend d'avoir assez
d'historique réel et les règles décident seules.

Pour repartir de zéro : `make reset` puis `make up` (les tables en ajout seul ne peuvent pas être vidées).

## Prérequis

- Docker Desktop (Windows / macOS) ou Docker Engine + plugin Compose (Linux)
- Python 3 sur l'hôte (uniquement pour générer `.env`, bibliothèque standard)
- 4 Go de RAM libres ; 16 Go conseillés quand Wazuh arrivera
- Une connexion Internet et une clé Groq gratuite pour les réponses rédigées de RL SOLUTION (facultatif)
- Ports 80 et 443 libres

## Installation

### Linux, macOS, WSL

```bash
make env        # crée .env avec des secrets aléatoires
make up         # construit et démarre
make ps         # tous les services doivent être "running" / "healthy"
```

### Windows (PowerShell, sans make)

```powershell
python scripts\generate_env.py
docker compose up -d --build
docker compose ps
```

Premier démarrage : 2 à 4 minutes (téléchargement des images, installation des dépendances). Au démarrage, l'API attend PostgreSQL et Valkey,
génère les clés JWT si besoin, applique les migrations, initialise la plateforme (sans aucun compte) puis entraîne
l'IA comportementale si l'historique le permet. Créez ensuite votre compte sur `/inscription` et, si besoin, un
compte du personnel avec `make staff` (voir « Créer les comptes »).

**Mise à jour d'une installation existante** : dans votre `.env`, remplacez les lignes `OLLAMA_*` par celles de la
section `IA` de `.env.example` (`LLM_*`, avec votre clé Groq), retirez `assistant` de `COMPOSE_PROFILES`, puis
`docker compose up -d --build --remove-orphans` ; l'API applique la migration qui supprime l'ancienne table vectorielle.
L'ancien volume de modèles peut être supprimé : `docker volume rm rlbank_ollama_data`.

## HTTPS local

Caddy signe les certificats avec sa propre autorité locale. Pour éviter l'avertissement du navigateur,
exportez son certificat racine et faites-le approuver une fois :

```bash
make caddy-ca     # ou : docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt
```

| Système | Commande |
| --- | --- |
| Windows (PowerShell admin) | `certutil -addstore -f ROOT caddy-root.crt` |
| macOS | `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain caddy-root.crt` |
| Linux (Debian/Ubuntu) | `sudo cp caddy-root.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates` |
| Firefox | Paramètres, Certificats, Importer `caddy-root.crt` (magasin propre à Firefox) |

Ce HTTPS n'est pas cosmétique : WebAuthn / passkeys (phase 9) exige un contexte sécurisé.
`caddy-root.crt` est ignoré par Git ; ne le partagez pas.

## Vérifier que tout fonctionne

1. Ouvrez https://bank.localhost : le **relevé d'état de la plateforme** affiche trois lignes
   « Opérationnel » (base de données, cache de sécurité, traitements en arrière-plan).
2. `curl -k https://bank.localhost/api/v1/health/ready` renvoie `"status":"ok"`.
3. https://bank.localhost/api/docs affiche la documentation Swagger (servie localement, sans CDN).
4. Arrêtez le worker (`docker compose stop worker`) : sous 30 s le relevé passe à
   « un service secondaire est arrêté ». Relancez-le avec `docker compose start worker`.
5. IA comportementale : `make logs s=api` contient « IA comportementale branchée ».
6. RL SOLUTION : avec `LLM_API_KEY` renseignée, une question dans l'espace client > Aide reçoit une réponse rédigée
   en quelques secondes ; `make logs s=api` contient « RL SOLUTION : réponse du LLM ».

## Tests

```bash
make test           # backend + intégration PostgreSQL + frontend
make test-integration   # uniquement les tests sur la base rlbank_test
make lint           # ruff
```

| Suite | Contenu |
| --- | --- |
| `backend/tests/test_health.py` | live, ready, 503 si base tombée, état dégradé, aucune fuite d'information |
| `backend/tests/test_security_http.py` | en-têtes, request-id, host non autorisé, problem+json, docs hors ligne |
| `backend/tests/test_redaction.py` | masquage des secrets dans les structures, le texte et les logs JSON |
| `backend/tests/test_config.py` | refus des secrets absents, courts ou d'exemple ; encodage des URL |
| `backend/tests/test_catalogs.py` | matrice RBAC (auditeur en lecture seule, client limité à ses ressources), événements, IBAN |
| `backend/tests/test_card_details.py` | PAN et CVV dérivés : stables, Luhn valide, cohérents avec les 4 derniers chiffres, dépendants de la clé |
| `backend/tests/test_behavior_ai.py` | IA comportementale : anomalie > habitude, démarrage à froid sans avis, artefact modifié refusé |
| `backend/tests/test_assistant_llm.py` | RL SOLUTION : fiches transmises, message encadré, secrets masqués, demande de code rejetée, repli si panne ou quota atteint, clé jamais envoyée en HTTP, données publiques sans secret, fiches IBAN et sécurité présentes sans règle anti-fraude |
| `backend/tests/integration/` | privilèges PostgreSQL, ajout seul, contraintes, concurrence, invariants comptables, chaîne d'audit, seed |
| `backend/tests/integration/test_auth_flow.py` | connexion, MFA, sessions, **inscription** (compte courant, RIB selon la ville, carte et PIN, livret épargne, refus des mots de passe faibles) |
| `backend/tests/integration/test_staff_accounts.py` | comptes du personnel (`make staff`) : rôle, audit, refus des mots de passe faibles, du rôle client et des doublons ; base jamais rejouée |
| `backend/tests/integration/test_banking_flow.py`, `test_soc_flow.py`, `test_scorer_hook.py` | opérations client avec étape de validation, vérification différée d'un bénéficiaire, affichage de la carte, ATM sans carte, attaque bloquée avec réponse automatique, SOC/admin/audit/support, point d'extension IA |
| `backend/tests/test_risk_units.py` | seuils, politique, règles pures |
| `frontend/src/pages/system/StatusPage.test.tsx` | rendu du relevé, message d'erreur actionnable |
| `frontend/src/pages/auth/*.test.tsx` | connexion, inscription (agence selon la ville, PIN affiché une fois) |
| `frontend/src/components/ui/PaymentCard.test.tsx` | œil de la carte : masqué par défaut, affichage puis masquage |
| `frontend/src/auth/RequireRole.test.tsx` | orientation de chaque rôle vers son espace |

## Commandes utiles

| Commande | Effet |
| --- | --- |
| `make logs s=api` | journaux JSON de l'API |
| `make shell-api` | shell dans le conteneur API |
| `make psql` | console PostgreSQL |
| `make integrity` | vérifie la chaîne d'audit et les invariants du grand livre |
| `make staff ROLE=… EMAIL=… PRENOM=… NOM=…` | crée un compte du personnel (mot de passe saisi au clavier) |
| `make seed` | initialise la plateforme sans aucun compte (fait automatiquement au démarrage) |
| `make seed-demo` | ajoute personnel et clients fictifs aux mots de passe connus (machine locale uniquement) |
| `make migrate` | applique les migrations Alembic |
| `make ai-train` | ré-entraîne l'IA comportementale et redémarre l'API |
| `make atm-secret ATM=ATM-DLA-001` | secret d'un terminal ATM simulé |
| `make jwt-rotate` | nouvelles clés JWT (invalide les sessions) |
| `make down` | arrêt, données conservées |
| `make reset` | **supprime** conteneurs, base, cache, clés et modèle comportemental |

## Sécurité déjà en place

- Trois rôles PostgreSQL : amorçage (super-utilisateur), propriétaire du schéma (migrations), applicatif (DML seul, sans DDL, `statement_timeout` 15 s).
- Secrets uniquement dans `.env` (non versionné) ; l'API refuse de démarrer si un secret manque, est court ou vaut une valeur d'exemple.
- Clés JWT Ed25519 dans un volume Docker dédié, permissions 600, jamais sur l'hôte.
- Logs JSON avec identifiant de requête et masquage systématique (mots de passe, jetons, OTP, codes, PIN, numéros de carte).
- Erreurs au format RFC 9457 sans trace technique ; `TrustedHostMiddleware` ; CSP stricte sur l'API et sur la SPA de production.
- Authentification de la phase 4 : voir le tableau ci-dessus. Caddy n'approuve aucun `X-Forwarded-For` fourni par le client (l'IP vue par l'API ne peut pas être usurpée pour contourner la limitation).
- Données sensibles affichées à la demande et tracées : RIB, numéro complet et CVV de carte (masquage automatique), fiche bénéficiaire.
- IA locale : aucun appel à un service externe ; modèle comportemental vérifié par empreinte ; LLM sans outil, alimenté par des messages masqués.
- Conteneurs : `no-new-privileges` partout, capacités Linux supprimées sauf pour la base et le cache, Caddy exposé uniquement sur `127.0.0.1`.
- Documentation et polices servies localement : la démo fonctionne hors ligne (une fois les modèles téléchargés).

## Dépannage

| Symptôme | Solution |
| --- | --- |
| `bank.localhost` ne résout pas | Ajoutez `127.0.0.1 bank.localhost` au fichier hosts, ou utilisez https://localhost |
| Port 80 ou 443 occupé | Arrêtez IIS, Skype, Apache ou un autre proxy local |
| Safari : « ne parvient pas à se connecter au serveur » alors que `curl -k https://bank.localhost` répond | Safari résout `bank.localhost` en IPv6 (`::1`) : Caddy doit aussi être publié sur `[::1]:80` et `[::1]:443` (`docker-compose.yml`), puis `docker compose up -d caddy` |
| L'API redémarre en boucle | `make logs s=api` : un secret manquant est signalé explicitement ; relancez `make env` |
| Base créée avant la Phase 3 (pas de base `rlbank_test`) | `make reset` puis `make up` : le script d'initialisation ne s'exécute que sur un volume vide |
| `password authentication failed` après `generate_env.py --force` | Les secrets ont changé mais pas la base : `make reset` puis `make up` |
| Rechargement à chaud inactif (Windows) | Placez le projet dans le système de fichiers WSL (`\\wsl$`) plutôt que sur `C:\` |
| Frontend : `EACCES: permission denied, mkdir '/app/node_modules/.vite/...'` | Corrigé : en Docker, le cache Vite est dans `/tmp/vite`. Mettez à jour `frontend/vite.config.ts` puis `docker compose restart frontend` |
| La fenêtre de vérification refuse tous les codes | La double authentification n'est pas activée sur ce compte : espace client > Sécurité, scannez le QR code |
| « Code incorrect » alors que l'application est configurée | Utilisez un code **neuf** (un code déjà utilisé est refusé) et vérifiez l'heure automatique du téléphone |
| `IA comportementale absente` dans les logs | Historique insuffisant ou volume `ai_models` vide : `make ai-train` |
| RL SOLUTION répond par fiches brutes, sans phrase rédigée | `LLM_API_KEY` vide ou invalide, ou quota gratuit atteint : `make logs s=api` indique « erreur HTTP 401 » (clé) ou « 429 » (quota, attendre la réinitialisation) |
| Réponses de RL SOLUTION lentes ou coupées | Service saturé : essayez un modèle plus léger (`LLM_MODEL=openai/gpt-oss-20b`) |

## Structure

```
backend/          API FastAPI, worker, migrations Alembic, tests
  app/ai/         IA comportementale (behavior.py) et LLM hébergé de RL SOLUTION (assistant_llm.py)
  app/risk/       moteur de risque à règles explicables, point d'extension BehaviorScorer
frontend/         SPA React (espaces Client, Admin, SOC, Auditeur, Support, borne ATM, inscription)
database/         initialisation PostgreSQL (rôles, extensions, droits)
infra/            Caddy (et Grafana en phase 15)
security/         Wazuh, OpenSearch, MITRE, règles de détection (phases 14 à 16)
ai/               jeux de données et notebooks d'expérimentation de l'IA
assistant/        RL SOLUTION : prompts, base de connaissances, tests adversariaux (phase 13B)
simulations/      scénarios de démonstration (phase 17)
docs/             documentation (phase 19)
```
