import pytest
from pydantic import ValidationError

from app.core.config import Settings

STRONG = "x" * 20 + "Q7vB2mK9pL4nR8tW" + "y" * 12


def strong_env(**overrides):
    values = dict(app_env="development", rlbank_app_password=STRONG, rlbank_owner_password=STRONG,
                  valkey_password=STRONG, app_secret_key=STRONG, data_encryption_key=STRONG,
                  cardless_hmac_key=STRONG, lab_context_hmac_key=STRONG, wazuh_webhook_secret=STRONG)
    values.update(overrides)
    return values


def test_secrets_forts_acceptes():
    s = Settings(**strong_env())
    assert s.database_url.startswith("postgresql+psycopg://rlbank_app:")


def test_secret_absent_refuse_hors_test():
    with pytest.raises(ValidationError, match="APP_SECRET_KEY"):
        Settings(**strong_env(app_secret_key=""))


def test_valeur_d_exemple_refusee():
    with pytest.raises(ValidationError, match="valeur d'exemple"):
        Settings(**strong_env(valkey_password="__GENERATE__" + "a" * 40))


def test_mot_de_passe_encode_dans_l_url():
    s = Settings(**strong_env(rlbank_app_password=STRONG + "@/:"))
    assert "@/:" not in s.database_url.split("@")[0]


def test_listes_depuis_variables_csv(monkeypatch):
    monkeypatch.setenv("ALLOWED_HOSTS", "bank.localhost, localhost")
    monkeypatch.setenv("APP_ENV", "test")
    assert Settings().allowed_hosts == ["bank.localhost", "localhost"]
