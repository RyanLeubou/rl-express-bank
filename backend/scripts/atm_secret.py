#!/usr/bin/env python3
"""Affiche le secret du terminal d'un ATM simulé (à saisir dans le kiosque). Usage : atm_secret.py ATM-DLA-001"""
import sys

from app.security.crypto.terminal import derive_terminal_secret

if len(sys.argv) != 2:
    sys.exit("Usage : atm_secret.py ATM-XXX-000")
print(derive_terminal_secret(sys.argv[1]))
