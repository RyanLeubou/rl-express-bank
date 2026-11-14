"""Génère la paire de clés Ed25519 de signature des JWT (utilisée à partir de la phase 4).

Exécuté automatiquement au démarrage de l'API (idempotent) dans le volume Docker jwt_keys.
Rotation manuelle : make jwt-rotate  (invalide toutes les sessions existantes).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core.config import get_settings


def main() -> int:
    settings = get_settings()
    private_path = Path(settings.jwt_private_key_path)
    public_path = Path(settings.jwt_public_key_path)
    if private_path.exists() and "--force" not in sys.argv:
        print("Clés JWT déjà présentes : rien n'a été modifié (--force pour régénérer).")
        return 0
    private_path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    private_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                               serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
    os.chmod(private_path, 0o600)
    public_path.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                          serialization.PublicFormat.SubjectPublicKeyInfo))
    print(f"Clés Ed25519 écrites : {private_path} et {public_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
