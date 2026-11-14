"""Erreur d'authentification : toujours levée APRÈS validation (commit) des événements de sécurité."""
from __future__ import annotations


class AuthError(Exception):
    """Réponse d'échec contrôlée (RFC 9457). Le message est volontairement générique côté client :
    le détail (mauvais mot de passe, compte inactif…) n'est écrit que dans l'événement de sécurité."""

    def __init__(self, status: int, code: str, detail: str, *, headers: dict[str, str] | None = None,
                 clear_session: bool = False, clear_mfa: bool = False) -> None:
        super().__init__(detail)
        self.status = status
        self.code = code
        self.detail = detail
        self.headers = headers or {}
        self.clear_session = clear_session   # supprime les cookies de session
        self.clear_mfa = clear_mfa           # supprime le cookie de défi MFA
