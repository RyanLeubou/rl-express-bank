"""Configuration des tests : environnement « test », sans PostgreSQL ni Valkey réels."""
from __future__ import annotations

import os

os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("DOCS_ENABLED", "true")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.api.v1.health import get_health_checks  # noqa: E402
from app.core.config import Settings  # noqa: E402
from app.main import create_app  # noqa: E402


def ok() -> dict[str, object]:
    return {"status": "ok", "latency_ms": 1.0}


def down() -> dict[str, object]:
    return {"status": "down"}


@pytest.fixture
def settings() -> Settings:
    return Settings(app_env="test", allowed_hosts=["testserver", "bank.localhost"])


@pytest.fixture
def make_client(settings: Settings):
    def _make(checks: dict | None = None) -> TestClient:
        app = create_app(settings)
        if checks is not None:
            app.dependency_overrides[get_health_checks] = lambda: checks
        return TestClient(app)
    return _make


@pytest.fixture
def client(make_client) -> TestClient:
    return make_client({"database": ok, "cache": ok, "worker": ok})


@pytest.fixture(scope="session")
def jwt_key_files(tmp_path_factory):
    """Paire Ed25519 jetable pour les tests (jamais les clés du volume Docker)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    directory = tmp_path_factory.mktemp("jwt")
    key = Ed25519PrivateKey.generate()
    private, public = directory / "private.pem", directory / "public.pem"
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                     serialization.PublicFormat.SubjectPublicKeyInfo))
    return private, public
