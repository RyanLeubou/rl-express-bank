"""Documentation OpenAPI servie localement (aucun CDN : la démo doit fonctionner hors ligne)."""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from swagger_ui_bundle import swagger_ui_path

DOCS_PATH = "/api/docs"


def mount_docs(app: FastAPI, openapi_url: str) -> None:
    app.mount(f"{DOCS_PATH}/static", StaticFiles(directory=swagger_ui_path), name="swagger-static")

    @app.get(DOCS_PATH, include_in_schema=False)
    def swagger_ui() -> HTMLResponse:
        return get_swagger_ui_html(
            openapi_url=openapi_url,
            title="RL EXPRESS BANK — API",
            swagger_js_url=f"{DOCS_PATH}/static/swagger-ui-bundle.js",
            swagger_css_url=f"{DOCS_PATH}/static/swagger-ui.css",
            swagger_favicon_url=f"{DOCS_PATH}/static/favicon-32x32.png",
        )
