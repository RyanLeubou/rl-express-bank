# =====================================================================
# RL EXPRESS BANK — image unique pour Render (offre gratuite : un seul service web)
#
# Un conteneur, même origine pour l'interface et l'API (cookies __Host- et SameSite=Strict) :
#   Caddy (interface précompilée + proxy /api)  ->  uvicorn (API)  +  worker  +  Valkey local
# PostgreSQL est externe (Neon). Contexte de construction : racine du dépôt.
# =====================================================================
FROM node:22-alpine AS front
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM caddy:2-alpine AS caddy

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app \
    XDG_DATA_HOME=/tmp/caddy-data \
    XDG_CONFIG_HOME=/tmp/caddy-config
RUN apt-get update \
    && apt-get install -y --no-install-recommends valkey-server \
    && rm -rf /var/lib/apt/lists/*
COPY --from=caddy /usr/bin/caddy /usr/bin/caddy
WORKDIR /app
RUN groupadd --system app && useradd --system --gid app --home-dir /app --shell /usr/sbin/nologin app
COPY backend/requirements.txt .
RUN pip install -r requirements.txt
COPY backend/ ./
RUN rm -rf tests && mkdir -p /app/secrets /app/ai-models && chown app:app /app/secrets /app/ai-models \
    && chmod 700 /app/secrets
COPY --from=front /app/dist /srv
COPY deploy/render/Caddyfile /etc/caddy/Caddyfile
COPY deploy/render/start.py /app/deploy_start.py
USER app
ENV PORT=10000
EXPOSE 10000
CMD ["python", "/app/deploy_start.py"]
