"""Villes fictives du laboratoire et distances (formule de Haversine)."""
from __future__ import annotations

from math import asin, cos, radians, sin, sqrt

CITIES: dict[str, tuple[float, float, str]] = {
    "Douala": (4.0511, 9.7679, "CM"), "Yaoundé": (3.8480, 11.5021, "CM"), "Kribi": (2.9400, 9.9100, "CM"),
    "Bafoussam": (5.4778, 10.4176, "CM"), "Garoua": (9.3014, 13.3977, "CM"), "Bamenda": (5.9597, 10.1460, "CM"),
    "Paris": (48.8566, 2.3522, "FR"), "Lagos": (6.5244, 3.3792, "NG"), "Dubaï": (25.2048, 55.2708, "AE"),
    "Londres": (51.5072, -0.1276, "GB"), "New York": (40.7128, -74.0060, "US"),
}


def distance_km(a: str | None, b: str | None) -> float | None:
    if not a or not b or a not in CITIES or b not in CITIES:
        return None
    (la1, lo1, _), (la2, lo2, _) = CITIES[a], CITIES[b]
    p1, p2 = radians(la1), radians(la2)
    h = sin((p2 - p1) / 2) ** 2 + cos(p1) * cos(p2) * sin(radians(lo2 - lo1) / 2) ** 2
    return 2 * 6371 * asin(sqrt(h))


def country_of(city: str | None) -> str | None:
    return CITIES[city][2] if city in CITIES else None
