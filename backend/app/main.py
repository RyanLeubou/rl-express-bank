"""Point d'entrée de l'API RL EXPRESS BANK."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from app.api.docs import DOCS_PATH, mount_docs
from app.api.router import api_router
from app.core.config import Settings, get_settings
from app.core.errors import register_error_handlers
from app.core.logging import configure_logging
from app.core.middleware import RequestContextMiddleware

logger = logging.getLogger("rlbank.api")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level, service="rlbank-api")
    openapi_url = f"{settings.api_prefix}/openapi.json" if settings.docs_enabled else None

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        logger.info("Démarrage de l'API", extra={"environment": settings.app_env,
                                                 "lab_mode": settings.lab_mode,
                                                 "version": settings.app_version})
        if settings.lab_mode:
            logger.warning("LAB_MODE actif : le contexte de simulation signé est accepté")
        if settings.app_env != "test":          # les tests installent leurs propres scorers
            from app.ai.behavior import install_if_available
            install_if_available()
        yield
        logger.info("Arrêt de l'API")

    app = FastAPI(
        title="RL EXPRESS BANK — API",
        description="Banque virtuelle pédagogique et laboratoire de cybersécurité. "
                    "Toutes les données sont fictives.",
        version=settings.app_version,
        openapi_url=openapi_url,
        docs_url=None,
        redoc_url=None,
        lifespan=lifespan,
    )

    # Ordre d'exécution : le dernier ajouté est le premier exécuté
    if settings.cors_origins:
        app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=True,
                           allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
                           allow_headers=["Authorization", "Content-Type", "Idempotency-Key", "X-Request-ID",
                                        "X-CSRF-Token"])
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
    app.add_middleware(RequestContextMiddleware, docs_prefix=DOCS_PATH)

    register_error_handlers(app)
    app.include_router(api_router, prefix=settings.api_prefix)
    if settings.docs_enabled and openapi_url:
        mount_docs(app, openapi_url)
    return app


app = create_app()
