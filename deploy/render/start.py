"""Lanceur de l'image Render : secrets dérivés, base préparée, puis Valkey, API, worker et Caddy supervisés.

Variables attendues (render.yaml) :
  RLBANK_MASTER_SECRET    secret maître généré par Render ; toutes les clés en sont dérivées (HKDF-SHA256)
  DATABASE_BOOTSTRAP_URL  URL du rôle propriétaire de la base Neon : crée et met à jour les rôles séparés
  LLM_API_KEY             facultatif : clé Groq de RL SOLUTION
  RENDER_EXTERNAL_HOSTNAME, PORT : fournis par Render

Aucun secret n'est écrit sur disque ni journalisé. Si un processus s'arrête, le conteneur s'arrête et Render le relance.
"""
from __future__ import annotations

import base64
import os
import signal
import subprocess
import sys
import time
from urllib.parse import parse_qs, urlparse

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

OWNER, APP = "rlbank_owner", "rlbank_app"


def log(msg: str) -> None:
    print(f"[render] {msg}", flush=True)


def derive(master: bytes, label: str, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=b"rl-express-bank", info=label.encode()).derive(master)


def configure() -> str:
    master = os.environ.get("RLBANK_MASTER_SECRET", "")
    bootstrap = os.environ.get("DATABASE_BOOTSTRAP_URL", "")
    if len(master) < 32 or not bootstrap:
        sys.exit("[render] RLBANK_MASTER_SECRET (32 caractères min.) et DATABASE_BOOTSTRAP_URL sont requis")
    m = master.encode()
    hexkey = lambda label: derive(m, label).hex()   # noqa: E731 - 64 caractères hexadécimaux
    url = urlparse(bootstrap)
    host = os.environ.get("RENDER_EXTERNAL_HOSTNAME", "localhost")
    os.environ.update({
        "APP_ENV": os.environ.get("APP_ENV", "demo"), "LAB_MODE": os.environ.get("LAB_MODE", "true"),
        "SEED_DEMO_DATA": "false", "DOCS_ENABLED": os.environ.get("DOCS_ENABLED", "true"),
        "PUBLIC_BASE_URL": f"https://{host}", "ALLOWED_HOSTS": f"{host},localhost,127.0.0.1",
        "POSTGRES_HOST": url.hostname or "", "POSTGRES_PORT": str(url.port or 5432),
        "POSTGRES_DB": url.path.lstrip("/") or "neondb",
        "POSTGRES_SSLMODE": parse_qs(url.query).get("sslmode", ["require"])[0],
        "RLBANK_OWNER_USER": OWNER, "RLBANK_OWNER_PASSWORD": hexkey("postgres-owner"),
        "RLBANK_APP_USER": APP, "RLBANK_APP_PASSWORD": hexkey("postgres-app"),
        "VALKEY_HOST": "127.0.0.1", "VALKEY_PORT": "6379", "VALKEY_PASSWORD": hexkey("valkey"),
        "APP_SECRET_KEY": hexkey("app-secret"),
        "DATA_ENCRYPTION_KEY": base64.b64encode(derive(m, "data-encryption")).decode(),   # AES-256 : 32 octets
        "CARDLESS_HMAC_KEY": hexkey("cardless-hmac"), "LAB_CONTEXT_HMAC_KEY": hexkey("lab-context-hmac"),
        "WAZUH_WEBHOOK_SECRET": hexkey("wazuh-webhook"),
        "JWT_PRIVATE_KEY_PATH": "/app/secrets/jwt_private.pem", "JWT_PUBLIC_KEY_PATH": "/app/secrets/jwt_public.pem",
        "SMTP_HOST": "localhost", "SMTP_PORT": "1025", "UVICORN_RELOAD": "false",
    })
    return bootstrap


def prepare_database(bootstrap: str) -> None:
    """Rôles séparés comme en local : propriétaire du schéma (migrations) et rôle applicatif (DML seulement)."""
    import psycopg
    from psycopg import sql

    with psycopg.connect(bootstrap, autocommit=True, connect_timeout=30) as conn:
        for role, pw_env in ((OWNER, "RLBANK_OWNER_PASSWORD"), (APP, "RLBANK_APP_PASSWORD")):
            ident, pw = sql.Identifier(role), sql.Literal(os.environ[pw_env])
            if conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone():
                conn.execute(sql.SQL("ALTER ROLE {} WITH LOGIN PASSWORD {}").format(ident, pw))
            else:
                conn.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE")
                             .format(ident, pw))
        o, a = sql.Identifier(OWNER), sql.Identifier(APP)
        db = sql.Identifier(os.environ["POSTGRES_DB"])
        for stmt in (
            sql.SQL("GRANT {} TO CURRENT_USER").format(o),          # requis pour transférer le schéma public
            sql.SQL("ALTER ROLE {} SET statement_timeout = '15s'").format(a),
            sql.SQL("ALTER ROLE {} SET idle_in_transaction_session_timeout = '30s'").format(a),
            sql.SQL("ALTER ROLE {} SET timezone = 'UTC'").format(a),
            sql.SQL("ALTER ROLE {} SET timezone = 'UTC'").format(o),
            sql.SQL("CREATE EXTENSION IF NOT EXISTS pgcrypto"),
            sql.SQL("CREATE EXTENSION IF NOT EXISTS citext"),
            sql.SQL("CREATE EXTENSION IF NOT EXISTS vector"),
            sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(db),
            sql.SQL("GRANT CONNECT, TEMPORARY ON DATABASE {} TO {}, {}").format(db, o, a),
            sql.SQL("ALTER SCHEMA public OWNER TO {}").format(o),
            sql.SQL("REVOKE CREATE ON SCHEMA public FROM PUBLIC"),
            sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(a),
            sql.SQL("ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA public "
                    "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {}").format(o, a),
            sql.SQL("ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {}")
            .format(o, a),
            sql.SQL("ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO {}")
            .format(o, a),
        ):
            conn.execute(stmt)
    log("base prête : rôles propriétaire et applicatif à jour")


# Toutes les commandes lancées ci-dessous sont des constantes de l'image (aucune entrée utilisateur) : les
# alertes S603/S607 de l'analyseur ne s'appliquent pas.
def start(cmd: list[str], **kwargs) -> subprocess.Popen:
    return subprocess.Popen(cmd, cwd="/app", **kwargs)  # noqa: S603


def run(*cmd: str, check: bool = True) -> None:
    if subprocess.run(cmd, cwd="/app").returncode != 0 and check:  # noqa: S603
        sys.exit(f"[render] échec : {' '.join(cmd)}")


def main() -> None:
    prepare_database(configure())
    procs: list[subprocess.Popen] = []
    # Configuration par l'entrée standard : le mot de passe n'apparaît pas dans la liste des processus
    valkey = start(["valkey-server", "-"], stdin=subprocess.PIPE, text=True)
    valkey.stdin.write(f"bind 127.0.0.1\nport 6379\nrequirepass {os.environ['VALKEY_PASSWORD']}\nsave \"\"\n"
                       "appendonly no\ndir /tmp\nmaxmemory 64mb\nmaxmemory-policy noeviction\n")
    valkey.stdin.close()
    procs.append(valkey)

    run("python", "scripts/wait_for_services.py")
    run("python", "scripts/generate_jwt_keys.py")
    run("alembic", "upgrade", "head")
    run("python", "-m", "app.seed")                       # base de la plateforme, aucun compte utilisateur
    run("python", "-m", "app.ai.behavior", "train", "--if-missing", check=False)

    procs.append(start(["python", "-m", "app.workers.main"]))
    procs.append(start(["uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000",
                        "--proxy-headers", "--forwarded-allow-ips=127.0.0.1", "--no-server-header"]))
    wait_api()                                            # le port public ne s'ouvre qu'une fois l'API prête
    procs.append(start(["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]))
    log(f"démarré sur le port {os.environ.get('PORT')} : https://{os.environ.get('RENDER_EXTERNAL_HOSTNAME')}")

    stopping = False

    def stop(*_):
        nonlocal stopping
        stopping = True
        for p in procs:
            if p.poll() is None:
                p.terminate()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while not stopping and all(p.poll() is None for p in procs):
        time.sleep(1)
    if stopping:
        log("arrêt demandé")
        return
    dead = next(p for p in procs if p.poll() is not None)
    stop()
    sys.exit(f"[render] processus arrêté ({dead.args[0]}, code {dead.returncode}) : redémarrage du conteneur")


def wait_api(timeout: float = 180) -> None:
    import urllib.request

    req = urllib.request.Request("http://127.0.0.1:8000/api/v1/health/live", headers={"Host": "localhost"})
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(req, timeout=3) as r:  # noqa: S310 - adresse locale fixe
                if r.status == 200:
                    return
        except OSError:
            pass
        time.sleep(1)
    sys.exit("[render] l'API n'a pas démarré à temps")


if __name__ == "__main__":
    main()
