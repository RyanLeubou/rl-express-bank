#!/bin/sh
# Démarrage du conteneur backend.
#  - commande par défaut : attente des services, migrations, puis API (uvicorn)
#  - toute autre commande (worker, pytest, script) est exécutée telle quelle
set -e
cd /app
export PYTHONPATH="/app${PYTHONPATH:+:$PYTHONPATH}"

if [ "$#" -gt 0 ]; then
  exec "$@"
fi

python scripts/wait_for_services.py
python scripts/generate_jwt_keys.py
echo "[migrations] alembic upgrade head"
alembic upgrade head

# Base indispensable, toujours (idempotent) : aucun compte connectable. Les clients s'inscrivent eux-mêmes,
# le personnel est créé avec « make staff ». Comptes fictifs aux mots de passe connus : SEED_DEMO_DATA=true.
if [ "${SEED_DEMO_DATA:-false}" = "true" ]; then
  echo "[seed] base + données de démonstration (idempotent)"
  python -m app.seed --demo
else
  echo "[seed] base de la plateforme (idempotent, sans compte utilisateur)"
  python -m app.seed
fi

# IA comportementale : entraînée une fois sur l'historique ; un échec laisse les règles décider seules
python -m app.ai.behavior train --if-missing || echo "[ia] entraînement impossible : règles seules"

RELOAD_FLAG=""
if [ "${UVICORN_RELOAD:-false}" = "true" ]; then
  RELOAD_FLAG="--reload --reload-dir app"
fi

# Proxy de confiance : uniquement Caddy, sur le réseau Docker privé
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 \
  --proxy-headers --forwarded-allow-ips="${FORWARDED_ALLOW_IPS:-*}" \
  --no-server-header $RELOAD_FLAG
