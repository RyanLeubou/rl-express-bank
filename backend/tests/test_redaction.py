import json
import logging

from app.core.logging import JsonFormatter
from app.core.redaction import MASK, redact, redact_text


def test_cles_sensibles_masquees_recursivement():
    data = {"email": "jean@rl.test", "password": "S3cret!", "mfa": {"otp": "123456"},
            "items": [{"refresh_token": "abc"}], "amount": 20000}
    out = redact(data)
    assert out["password"] == MASK and out["mfa"]["otp"] == MASK
    assert out["items"][0]["refresh_token"] == MASK
    assert out["email"] == "jean@rl.test" and out["amount"] == 20000


def test_motifs_dans_le_texte_libre():
    assert "eyJ" not in redact_text("jeton eyJhbGciOi.eyJzdWIiOiIx.c2lnbmF0dXJl")
    assert "123456" not in redact_text("code=123456 saisi")
    assert "4970101234567890" not in redact_text("carte 4970101234567890")
    assert "abc.def" not in redact_text("Authorization: Bearer abc.def")


def test_formatter_json_masque_message_et_extras():
    record = logging.LogRecord("t", logging.INFO, __file__, 1, "password=hunter2", None, None)
    record.totp_secret = "JBSWY3DPEHPK3PXP"
    line = json.loads(JsonFormatter("test").format(record))
    assert "hunter2" not in line["message"]
    assert line["extra"]["totp_secret"] == MASK


def test_champs_techniques_non_masques():
    out = redact({"status_code": 200, "currency_code": "XAF", "atm_code": "ATM-DLA-004",
                  "cardless_code": "482913", "recovery_code": "abcd-efgh"})
    assert out["status_code"] == 200 and out["currency_code"] == "XAF" and out["atm_code"] == "ATM-DLA-004"
    assert out["cardless_code"] == MASK and out["recovery_code"] == MASK
