from tests.conftest import down, ok


def test_live_repond_sans_dependance(client):
    r = client.get("/api/v1/health/live")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "service": "rl-express-bank-api", "version": "0.2.0"}


def test_ready_ok_quand_tout_repond(client):
    r = client.get("/api/v1/health/ready")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert set(body["checks"]) == {"database", "cache", "worker"}


def test_ready_503_si_base_indisponible(make_client):
    r = make_client({"database": down, "cache": ok, "worker": ok}).get("/api/v1/health/ready")
    assert r.status_code == 503
    assert r.json()["status"] == "down"


def test_ready_degrade_si_worker_arrete(make_client):
    r = make_client({"database": ok, "cache": ok, "worker": down}).get("/api/v1/health/ready")
    assert r.status_code == 200
    assert r.json()["status"] == "degraded"


def test_ready_ne_divulgue_aucune_version_d_infrastructure(client):
    text = client.get("/api/v1/health/ready").text.lower()
    for leak in ("postgres", "valkey", "redis", "version", "password", "host"):
        assert leak not in text
