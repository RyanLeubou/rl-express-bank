# RL EXPRESS BANK — raccourcis (Linux, macOS, WSL). Sous Windows sans make : voir README.
.PHONY: help env up down restart ps logs build test test-backend test-integration test-frontend lint shell-api psql jwt-rotate caddy-ca reset seed seed-demo staff ai-train atm-secret integrity migrate

help: ## Affiche cette aide
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-14s %s\n", $$1, $$2}'

env: ## Crée .env avec des secrets aléatoires (une seule fois)
	python3 scripts/generate_env.py

up: ## Construit et démarre les profils actifs (COMPOSE_PROFILES)
	docker compose up -d --build

down: ## Arrête les conteneurs (données conservées)
	docker compose down

restart: down up ## Redémarre tout

ps: ## État des conteneurs
	docker compose ps

logs: ## Journaux en continu (ex. : make logs s=api)
	docker compose logs -f $(s)

build: ## Reconstruit les images
	docker compose build

test: test-backend test-integration test-frontend ## Lance tous les tests

test-backend: ## Tests backend dans le conteneur
	docker compose run --rm --no-deps -e APP_ENV=test api python -m pytest -p no:warnings

test-integration: ## Tests d'intégration sur la base PostgreSQL de test (rlbank_test)
	docker compose run --rm -e RLBANK_INTEGRATION=1 -e APP_ENV=test api python -m pytest -p no:warnings tests/integration

seed: ## Initialise la plateforme sans aucun compte (sans effet si déjà fait)
	docker compose exec api python -m app.seed

seed-demo: ## Ajoute personnel et clients FICTIFS aux mots de passe connus (machine locale uniquement)
	docker compose exec api python -m app.seed --demo

staff: ## Crée un compte du personnel : make staff ROLE=SUPER_ADMIN EMAIL=a@b.test PRENOM=Awa NOM=Fotso
	@test -n "$(ROLE)" -a -n "$(EMAIL)" -a -n "$(PRENOM)" -a -n "$(NOM)" || { echo "Usage : make staff ROLE=SUPER_ADMIN|SECURITY_ANALYST|AUDITOR|SUPPORT_AGENT EMAIL=... PRENOM=... NOM=..."; exit 1; }
	docker compose exec api python -m app.seed.staff --role "$(ROLE)" --email "$(EMAIL)" --prenom "$(PRENOM)" --nom "$(NOM)"

ai-train: ## Ré-entraîne l'IA comportementale sur l'historique, puis redémarre l'API pour la charger
	docker compose exec api python -m app.ai.behavior train
	docker compose restart api

atm-secret: ## Secret d'un terminal ATM simulé : make atm-secret ATM=ATM-DLA-001
	docker compose exec -e PYTHONPATH=/app api python scripts/atm_secret.py $(ATM)

integrity: ## Vérifie la chaîne d'audit et les invariants du grand livre
	docker compose exec api python scripts/verify_integrity.py

migrate: ## Applique les migrations Alembic
	docker compose exec api alembic upgrade head

test-frontend: ## Tests frontend dans le conteneur
	docker compose run --rm --no-deps frontend npx vitest run

lint: ## Analyse statique backend
	docker compose run --rm --no-deps api ruff check app tests scripts

shell-api: ## Shell dans le conteneur API
	docker compose exec api sh

psql: ## Console PostgreSQL (super-utilisateur d amorçage)
	docker compose exec postgres sh -c 'psql -U "$$POSTGRES_USER" -d "$$POSTGRES_DB"'

jwt-rotate: ## Régénère les clés JWT (invalide toutes les sessions)
	docker compose exec api python scripts/generate_jwt_keys.py --force

caddy-ca: ## Exporte le certificat racine local de Caddy (à faire approuver par l'OS)
	docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt
	@echo "Certificat exporté : caddy-root.crt (voir README, section HTTPS)"

reset: ## ATTENTION : supprime conteneurs ET données (base, cache, clés)
	docker compose down -v
