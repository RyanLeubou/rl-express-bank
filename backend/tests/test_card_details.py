"""PAN et CVV dérivés : stables, valides (Luhn), cohérents avec last4 et dépendants de la clé."""
import base64
from types import SimpleNamespace

from pydantic import SecretStr

from app.services.cards.details import FICTIONAL_BIN, cvv, full_pan, luhn_ok


def _settings(seed: bytes) -> SimpleNamespace:
    return SimpleNamespace(data_encryption_key=SecretStr(base64.b64encode(seed * 32).decode()))


CARD = SimpleNamespace(card_token="ab" * 24, last4="4821", expiry_month=7, expiry_year=2029)


def test_pan_valide_et_coherent_avec_les_donnees_stockees():
    pan = full_pan(_settings(b"k"), CARD)
    assert len(pan) == 16 and pan.startswith(FICTIONAL_BIN) and pan.endswith("4821") and luhn_ok(pan)


def test_derivation_stable_et_dependante_de_la_cle():
    a, b = _settings(b"k"), _settings(b"z")
    assert full_pan(a, CARD) == full_pan(a, CARD) and cvv(a, CARD) == cvv(a, CARD)
    assert (full_pan(a, CARD), cvv(a, CARD)) != (full_pan(b, CARD), cvv(b, CARD))
    assert len(cvv(a, CARD)) == 3 and cvv(a, CARD).isdigit()


def test_luhn_sur_de_nombreux_jetons():
    s = _settings(b"k")
    for i in range(500):
        card = SimpleNamespace(card_token=f"{i:048x}", last4=f"{i * 7 % 10000:04d}", expiry_month=1, expiry_year=2030)
        assert luhn_ok(full_pan(s, card))
