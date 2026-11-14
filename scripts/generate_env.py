#!/usr/bin/env python3
"""Génère le fichier .env à partir de .env.example avec des secrets aléatoires.

Usage :
    python3 scripts/generate_env.py          # crée .env s'il n'existe pas
    python3 scripts/generate_env.py --force  # régénère (ATTENTION : invalide la base existante)

Uniquement la bibliothèque standard Python : exécutable sans dépendance.
"""
from __future__ import annotations

import argparse
import base64
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / ".env.example"
TARGET = ROOT / ".env"


def generate_value(marker: str) -> str:
    if marker == "__GENERATE_B64_32__":
        return base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    # 48 octets -> 64 caractères URL-safe, sans caractère spécial gênant pour les URL de connexion
    return secrets.token_urlsafe(48)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="écraser un .env existant")
    args = parser.parse_args()

    if not EXAMPLE.exists():
        print(f"Fichier introuvable : {EXAMPLE}", file=sys.stderr)
        return 1
    if TARGET.exists() and not args.force:
        print(".env existe déjà : rien n'a été modifié (utilisez --force pour régénérer).")
        return 0

    lines_out: list[str] = []
    generated = 0
    for line in EXAMPLE.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            if value in ("__GENERATE__", "__GENERATE_B64_32__"):
                line = f"{key}={generate_value(value)}"
                generated += 1
        lines_out.append(line)

    TARGET.write_text("\n".join(lines_out) + "\n", encoding="utf-8")
    try:
        TARGET.chmod(0o600)
    except OSError:
        pass  # systèmes de fichiers sans permissions POSIX (Windows)
    print(f".env créé avec {generated} secrets générés.")
    if args.force:
        print("Secrets régénérés : supprimez le volume PostgreSQL (make reset) avant de relancer.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
