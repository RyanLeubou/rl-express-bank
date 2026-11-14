import uuid


def test_entetes_de_securite_sur_l_api(client):
    r = client.get("/api/v1/health/live")
    assert r.headers["content-security-policy"].startswith("default-src 'none'")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["cache-control"] == "no-store"
    assert "server" not in r.headers


def test_request_id_genere_puis_propage(client):
    generated = client.get("/api/v1/health/live").headers["x-request-id"]
    uuid.UUID(generated)
    r = client.get("/api/v1/health/live", headers={"X-Request-ID": "demo-jury-0001"})
    assert r.headers["x-request-id"] == "demo-jury-0001"


def test_request_id_malforme_remplace(client):
    r = client.get("/api/v1/health/live", headers={"X-Request-ID": "<script>alert(1)</script>"})
    assert r.headers["x-request-id"] != "<script>alert(1)</script>"


def test_hote_non_autorise_refuse(client):
    r = client.get("/api/v1/health/live", headers={"Host": "evil.example"})
    assert r.status_code == 400


def test_erreur_404_au_format_problem_json(client):
    r = client.get("/api/v1/n-existe-pas")
    assert r.status_code == 404
    assert r.headers["content-type"].startswith("application/problem+json")
    body = r.json()
    assert body["status"] == 404 and "request_id" in body


def test_documentation_servie_localement(client):
    html = client.get("/api/docs").text
    assert "/api/docs/static/swagger-ui-bundle.js" in html
    assert "cdn.jsdelivr" not in html
    assert client.get("/api/docs/static/swagger-ui.css").status_code == 200
    assert client.get("/api/v1/openapi.json").json()["info"]["title"] == "RL EXPRESS BANK — API"
