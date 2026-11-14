"""Configuration centralisée, chargée depuis les variables d'environnement.

Aucune valeur secrète par défaut : l'application refuse de démarrer si un secret
est absent, trop court ou laissé à une valeur d'exemple (sauf en environnement de test).
"""
from __future__ import annotations

from functools import lru_cache
from typing import Annotated, Literal
from urllib.parse import quote

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

Environment = Literal["development", "demo", "test"]
_WEAK_MARKERS = ("__generate", "change", "password", "example")
_MIN_SECRET_LENGTH = 32


def _split_csv(value: object) -> object:
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return value


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, extra="ignore", case_sensitive=False)

    # ---- Général ----
    app_env: Environment = "development"
    app_name: str = "RL EXPRESS BANK"
    app_version: str = "0.2.1"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    lab_mode: bool = False
    public_base_url: str = "https://bank.localhost"
    allowed_hosts: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["bank.localhost", "localhost", "127.0.0.1", "api"]
    )
    cors_origins: Annotated[list[str], NoDecode] = Field(default_factory=list)
    docs_enabled: bool = True
    timezone: str = "Africa/Douala"
    api_prefix: str = "/api/v1"

    # ---- PostgreSQL ----
    postgres_host: str = "postgres"
    postgres_port: int = 5432
    postgres_db: str = "rlbank"
    rlbank_owner_user: str = "rlbank_owner"
    rlbank_owner_password: SecretStr = SecretStr("")
    rlbank_app_user: str = "rlbank_app"
    rlbank_app_password: SecretStr = SecretStr("")

    # ---- Valkey ----
    valkey_host: str = "valkey"
    valkey_port: int = 6379
    valkey_password: SecretStr = SecretStr("")

    # ---- Secrets applicatifs ----
    app_secret_key: SecretStr = SecretStr("")
    data_encryption_key: SecretStr = SecretStr("")
    cardless_hmac_key: SecretStr = SecretStr("")
    lab_context_hmac_key: SecretStr = SecretStr("")
    wazuh_webhook_secret: SecretStr = SecretStr("")

    # ---- JWT (utilisés à partir de la phase 4) ----
    jwt_private_key_path: str = "/app/secrets/jwt_private.pem"
    jwt_public_key_path: str = "/app/secrets/jwt_public.pem"
    jwt_access_ttl_seconds: int = Field(default=600, ge=60, le=3600)

    # ---- Authentification (phase 4) ----
    # Jeton de rafraîchissement : inactivité maximale, puis durée absolue d'une session
    refresh_idle_ttl_seconds: int = Field(default=7 * 24 * 3600, ge=900, le=30 * 24 * 3600)
    session_absolute_ttl_seconds: int = Field(default=30 * 24 * 3600, ge=3600, le=90 * 24 * 3600)
    mfa_pending_ttl_seconds: int = Field(default=300, ge=60, le=900)
    mfa_max_attempts_per_challenge: int = Field(default=5, ge=3, le=10)
    device_cookie_ttl_days: int = Field(default=365, ge=1, le=730)
    totp_issuer: str = "RL EXPRESS BANK"
    # Ralentissement progressif des échecs (jamais de verrouillage définitif) : après `free`
    # échecs, délai 1 s, 2 s, 4 s… plafonné à `max_delay`. Trois portées indépendantes.
    throttle_window_seconds: int = Field(default=900, ge=60, le=86400)
    throttle_max_delay_seconds: int = Field(default=900, ge=1, le=3600)
    throttle_free_pair: int = Field(default=3, ge=1, le=20)       # même compte depuis la même IP
    throttle_free_ip: int = Field(default=20, ge=3, le=200)       # une IP sur plusieurs comptes
    throttle_free_account: int = Field(default=15, ge=3, le=100)  # un compte depuis plusieurs IP

    # ---- Moteur de risque (seuils des niveaux, sur 100) ----
    risk_medium_from: int = Field(default=30, ge=1, le=99)
    risk_high_from: int = Field(default=60, ge=1, le=99)
    risk_critical_from: int = Field(default=80, ge=1, le=100)

    # ---- IA ----
    ai_model_dir: str = "/app/ai-models"              # volume : modèle comportemental entraîné
    # LLM de RL SOLUTION : tout service compatible OpenAI (Groq par défaut, offre gratuite)
    llm_base_url: str = "https://api.groq.com/openai/v1"
    llm_api_key: SecretStr = SecretStr("")              # vide : RL SOLUTION répond par mots-clés
    llm_model: str = "openai/gpt-oss-120b"             # modèle open source (Apache 2.0)
    llm_timeout_seconds: float = Field(default=30, ge=1, le=300)

    # ---- SMTP simulé ----
    smtp_host: str = "mailpit"
    smtp_port: int = 1025

    _split_hosts = field_validator("allowed_hosts", "cors_origins", mode="before")(_split_csv)

    @model_validator(mode="after")
    def _check_secrets(self) -> Settings:
        if self.app_env == "test":
            return self
        required = {
            "RLBANK_APP_PASSWORD": self.rlbank_app_password,
            "RLBANK_OWNER_PASSWORD": self.rlbank_owner_password,
            "VALKEY_PASSWORD": self.valkey_password,
            "APP_SECRET_KEY": self.app_secret_key,
            "DATA_ENCRYPTION_KEY": self.data_encryption_key,
            "CARDLESS_HMAC_KEY": self.cardless_hmac_key,
            "LAB_CONTEXT_HMAC_KEY": self.lab_context_hmac_key,
            "WAZUH_WEBHOOK_SECRET": self.wazuh_webhook_secret,
        }
        problems = []
        for name, secret in required.items():
            value = secret.get_secret_value()
            if len(value) < _MIN_SECRET_LENGTH:
                problems.append(f"{name} absent ou trop court (min. {_MIN_SECRET_LENGTH} caractères)")
            elif any(marker in value.lower() for marker in _WEAK_MARKERS):
                problems.append(f"{name} contient une valeur d'exemple")
        if problems:
            raise ValueError(
                "Configuration de sécurité invalide : " + " ; ".join(problems)
                + ". Générez les secrets avec : python3 scripts/generate_env.py"
            )
        return self

    # ---- URL dérivées (mots de passe encodés, jamais journalisés) ----
    def _pg_url(self, user: str, password: SecretStr) -> str:
        return (
            f"postgresql+psycopg://{quote(user)}:{quote(password.get_secret_value(), safe='')}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def database_url(self) -> str:
        """Connexion applicative : rôle DML uniquement."""
        return self._pg_url(self.rlbank_app_user, self.rlbank_app_password)

    @property
    def migration_database_url(self) -> str:
        """Connexion des migrations : propriétaire du schéma."""
        return self._pg_url(self.rlbank_owner_user, self.rlbank_owner_password)

    @property
    def valkey_url(self) -> str:
        password = quote(self.valkey_password.get_secret_value(), safe="")
        return f"redis://:{password}@{self.valkey_host}:{self.valkey_port}/0"


@lru_cache
def get_settings() -> Settings:
    return Settings()
