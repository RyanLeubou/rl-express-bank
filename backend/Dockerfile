# =====================================================================
# RL EXPRESS BANK — image backend (API et worker)
#   target dev     : dépendances de test, code monté en volume, rechargement à chaud
#   target runtime : image de démonstration, code copié, utilisateur non root
# =====================================================================
FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app
WORKDIR /app
RUN groupadd --system app && useradd --system --gid app --home-dir /app --shell /usr/sbin/nologin app
COPY requirements.txt .
RUN pip install -r requirements.txt \
    && mkdir -p /app/secrets /app/ai-models && chown app:app /app/secrets /app/ai-models && chmod 700 /app/secrets

FROM base AS dev
COPY requirements-dev.txt .
RUN pip install -r requirements-dev.txt
COPY . .
RUN chmod +x scripts/entrypoint.sh
USER app
EXPOSE 8000
ENTRYPOINT ["/app/scripts/entrypoint.sh"]

FROM base AS runtime
COPY . .
RUN chmod +x scripts/entrypoint.sh && rm -rf tests
USER app
EXPOSE 8000
ENTRYPOINT ["/app/scripts/entrypoint.sh"]
