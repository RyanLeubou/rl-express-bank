"""Schémas d'entrée/sortie de l'authentification. Entrées strictes : aucun champ inconnu accepté."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class LoginRequest(StrictModel):
    # Pas d'EmailStr : les domaines .test de la démo sont refusés par la validation stricte
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=256)


class RegisterRequest(StrictModel):
    first_name: str = Field(min_length=1, max_length=80)
    last_name: str = Field(min_length=1, max_length=80)
    address: str = Field(min_length=5, max_length=200)
    city: str = Field(min_length=2, max_length=80, description="Ville de résidence : détermine l'agence du RIB")
    phone: str = Field(max_length=32, pattern=r"^\+?[0-9 ]{6,31}$")
    email: str = Field(min_length=3, max_length=254, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    profession: str = Field(min_length=2, max_length=80)
    password: str = Field(min_length=12, max_length=256)


class MfaVerifyRequest(StrictModel):
    code: str = Field(min_length=6, max_length=16, description="Code TOTP à 6 chiffres ou code de secours")
    trust_device: bool = False


class MfaEnrollStartRequest(StrictModel):
    # Obligatoire pour un utilisateur déjà connecté (ré-authentification), ignoré à la première activation
    current_password: str | None = Field(default=None, max_length=256)


class MfaEnrollConfirmRequest(StrictModel):
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class UserOut(BaseModel):
    id: uuid.UUID
    email: str
    first_name: str
    last_name: str
    user_type: str
    roles: list[str]
    permissions: list[str]
    mfa_enabled: bool


class LoginResponse(BaseModel):
    status: Literal["authenticated", "mfa_required", "mfa_enrollment_required"]
    user: UserOut | None = None
    new_device: bool = False


class RegisterResponse(LoginResponse):
    # Affichés une seule fois : le PIN n'est stocké que haché
    card_pin: str
    iban: str
    agency: str
    branch_code: str


class MeResponse(BaseModel):
    user: UserOut
    aal: int
    amr: list[str]
    device_trusted: bool
    session_expires_at: datetime


class MfaEnrollStartResponse(BaseModel):
    secret: str
    otpauth_uri: str
    qr_code: str          # image data:image/svg+xml (CSP : img-src data:)


class MfaEnrollConfirmResponse(BaseModel):
    status: Literal["mfa_enabled", "authenticated"]
    recovery_codes: list[str]
    user: UserOut | None = None


class MfaVerifyResponse(BaseModel):
    status: Literal["authenticated"]
    user: UserOut
    recovery_codes_left: int | None = None


class SessionOut(BaseModel):
    id: uuid.UUID
    device: str | None
    ip: str | None
    created_at: datetime
    last_activity: datetime
    current: bool
