"""Reconnaissance des appareils : identifiant aléatoire en cookie HttpOnly (pas d'empreinte invasive).

Le cookie ne contient qu'un identifiant aléatoire ; en base, seul son hash (avec le navigateur et
le système, volontairement grossiers) est stocké. Un appareil n'est « de confiance » qu'après une
validation explicite (second facteur réussi + choix de l'utilisateur).
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from app.models.auth import Device
from app.models.enums import DeviceStatus
from app.security.auth.tokens import new_opaque_token

_DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")

_BROWSERS = (("Edg/", "Edge"), ("OPR/", "Opera"), ("Firefox/", "Firefox"), ("Chrome/", "Chrome"),
             ("CriOS/", "Chrome"), ("Safari/", "Safari"), ("curl/", "curl"), ("python-", "Python"))
_SYSTEMS = (("Windows", "Windows"), ("Android", "Android"), ("iPhone", "iOS"), ("iPad", "iOS"),
            ("Mac OS X", "macOS"), ("Macintosh", "macOS"), ("CrOS", "ChromeOS"), ("Linux", "Linux"))


def parse_user_agent(user_agent: str | None) -> tuple[str, str]:
    """(navigateur, système) grossiers : stables lors des mises à jour de version."""
    ua = user_agent or ""
    browser = next((name for marker, name in _BROWSERS if marker in ua), "Inconnu")
    system = next((name for marker, name in _SYSTEMS if marker in ua), "Inconnu")
    return browser, system


def sanitize_ip(ip: str | None) -> str | None:
    """Une IP valide ou None (la colonne INET refuse tout autre texte)."""
    if not ip:
        return None
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return None


def fingerprint(device_cookie: str, browser: str, system: str) -> str:
    return hashlib.sha256(f"{device_cookie}|{browser}|{system}".encode()).hexdigest()


@dataclass
class DeviceResolution:
    device: Device
    cookie_value: str      # valeur à (re)poser dans le cookie
    is_new: bool
    browser: str
    system: str

    @property
    def trusted(self) -> bool:
        return self.device.status == DeviceStatus.TRUSTED

    @property
    def blocked(self) -> bool:
        return self.device.status == DeviceStatus.BLOCKED


def resolve_device(db: DbSession, user_id: uuid.UUID, cookie_value: str | None, user_agent: str | None,
                   ip: str | None) -> DeviceResolution:
    browser, system = parse_user_agent(user_agent)
    cookie = cookie_value if cookie_value and _DEVICE_ID_RE.match(cookie_value) else new_opaque_token()
    fp = fingerprint(cookie, browser, system)
    now = datetime.now(UTC)
    clean_ip = sanitize_ip(ip)

    device = db.scalar(select(Device).where(Device.user_id == user_id, Device.fingerprint_hash == fp))
    if device is not None:
        device.last_seen = now
        device.last_ip = clean_ip or device.last_ip
        return DeviceResolution(device, cookie, False, browser, system)

    device = Device(user_id=user_id, fingerprint_hash=fp, name=f"{browser} sur {system}", os=system,
                    browser=browser, last_ip=clean_ip, status=DeviceStatus.NEW, first_seen=now, last_seen=now)
    try:
        with db.begin_nested():
            db.add(device)
            db.flush()
    except IntegrityError:                      # création concurrente du même appareil
        existing = db.scalar(select(Device).where(Device.user_id == user_id, Device.fingerprint_hash == fp))
        if existing is None:
            raise
        return DeviceResolution(existing, cookie, False, browser, system)
    return DeviceResolution(device, cookie, True, browser, system)
