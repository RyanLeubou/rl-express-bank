#!/bin/bash
# =====================================================================
# RL EXPRESS BANK — initialisation PostgreSQL (exécuté une seule fois,
# au premier démarrage, lorsque le volume de données est vide).
#
# Séparation des privilèges :
#   - POSTGRES_USER        : super-utilisateur d'amorçage (jamais utilisé par l'application)
#   - RLBANK_OWNER_USER    : propriétaire du schéma, utilisé uniquement par Alembic
#   - RLBANK_APP_USER      : rôle applicatif, droits DML seulement (pas de DDL)
# Deux bases identiques : POSTGRES_DB (application) et POSTGRES_DB_test (tests d'intégration).
# Les restrictions « ajout seul » (audit, grand livre, événements) sont posées par la migration initiale.
# =====================================================================
set -euo pipefail

: "${RLBANK_OWNER_USER:?RLBANK_OWNER_USER manquant}"
: "${RLBANK_OWNER_PASSWORD:?RLBANK_OWNER_PASSWORD manquant}"
: "${RLBANK_APP_USER:?RLBANK_APP_USER manquant}"
: "${RLBANK_APP_PASSWORD:?RLBANK_APP_PASSWORD manquant}"

TEST_DB="${POSTGRES_DB}_test"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -v owner_user="$RLBANK_OWNER_USER" -v owner_password="$RLBANK_OWNER_PASSWORD" \
     -v app_user="$RLBANK_APP_USER" -v app_password="$RLBANK_APP_PASSWORD" \
     -v test_db="$TEST_DB" <<-'EOSQL'
    CREATE ROLE :"owner_user" LOGIN PASSWORD :'owner_password' NOSUPERUSER NOCREATEDB NOCREATEROLE;
    CREATE ROLE :"app_user"   LOGIN PASSWORD :'app_password'   NOSUPERUSER NOCREATEDB NOCREATEROLE;
    ALTER ROLE :"app_user" SET statement_timeout = '15s';
    ALTER ROLE :"app_user" SET idle_in_transaction_session_timeout = '30s';
    ALTER ROLE :"app_user" SET timezone = 'UTC';
    ALTER ROLE :"owner_user" SET timezone = 'UTC';
    CREATE DATABASE :"test_db";
EOSQL

for DB in "$POSTGRES_DB" "$TEST_DB"; do
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$DB" \
     -v owner_user="$RLBANK_OWNER_USER" -v app_user="$RLBANK_APP_USER" -v db_name="$DB" <<-'EOSQL'
    CREATE EXTENSION IF NOT EXISTS pgcrypto;
    CREATE EXTENSION IF NOT EXISTS citext;
    CREATE EXTENSION IF NOT EXISTS vector;   -- pgvector : base de connaissances RL SOLUTION

    REVOKE ALL ON DATABASE :"db_name" FROM PUBLIC;
    GRANT CONNECT, TEMPORARY ON DATABASE :"db_name" TO :"owner_user", :"app_user";

    ALTER SCHEMA public OWNER TO :"owner_user";
    REVOKE CREATE ON SCHEMA public FROM PUBLIC;
    GRANT USAGE ON SCHEMA public TO :"app_user";

    ALTER DEFAULT PRIVILEGES FOR ROLE :"owner_user" IN SCHEMA public
        GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO :"app_user";
    ALTER DEFAULT PRIVILEGES FOR ROLE :"owner_user" IN SCHEMA public
        GRANT USAGE, SELECT ON SEQUENCES TO :"app_user";
    ALTER DEFAULT PRIVILEGES FOR ROLE :"owner_user" IN SCHEMA public
        GRANT EXECUTE ON FUNCTIONS TO :"app_user";
EOSQL
done

echo "RL EXPRESS BANK : rôles ${RLBANK_OWNER_USER}, ${RLBANK_APP_USER} ; bases ${POSTGRES_DB} et ${TEST_DB} prêtes."
