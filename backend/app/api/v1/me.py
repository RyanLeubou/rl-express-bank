"""Espace personnel : appareils, notifications, résumé de ses événements de sécurité."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, update
from sqlalchemy.orm import Session as DbSession

from app.core.database import get_db
from app.events.catalog import EventType as E
from app.events.logger import emit
from app.models import Device, Notification, SecurityEvent
from app.models import Session as AuthSession
from app.models.enums import DeviceStatus, SessionStatus
from app.security.auth.deps import AuthContext, check_origin, require_permission
from app.security.auth.errors import AuthError

router = APIRouter(tags=["Espace personnel"], dependencies=[Depends(check_origin)])


@router.get("/devices", summary="Mes appareils")
def devices(ctx: AuthContext = Depends(require_permission("device:read:own")), db: DbSession = Depends(get_db)):
    return [{"id": d.id, "name": d.name, "os": d.os, "browser": d.browser, "status": d.status, "city": d.last_city,
             "last_seen": d.last_seen, "current": d.id == ctx.session.device_id}
            for d in db.scalars(select(Device).where(Device.user_id == ctx.user.id).order_by(Device.last_seen.desc()))]


@router.delete("/devices/{device_id}", status_code=204, summary="Révoquer un appareil")
def revoke_device(device_id: uuid.UUID, ctx: AuthContext = Depends(require_permission("device:revoke:own")),
                  db: DbSession = Depends(get_db)):
    d = db.get(Device, device_id)
    if d is None or d.user_id != ctx.user.id:
        raise AuthError(404, "device_not_found", "Appareil introuvable.")
    if d.id == ctx.session.device_id:
        raise AuthError(409, "current_device", "Vous ne pouvez pas révoquer l'appareil en cours d'utilisation.")
    d.status = DeviceStatus.BLOCKED
    db.execute(update(AuthSession).where(AuthSession.device_id == d.id, AuthSession.status == SessionStatus.ACTIVE)
               .values(status=SessionStatus.REVOKED, revoked_at=datetime.now(UTC), revoked_reason="device_revoked"))
    emit(db, E.DEVICE_BLOCKED, user_id=ctx.user.id, device_id=d.id)
    db.commit()


@router.get("/notifications", summary="Mes notifications")
def notifications(ctx: AuthContext = Depends(require_permission("notification:read:own")),
                  db: DbSession = Depends(get_db), limit: int = Query(30, ge=1, le=100)):
    rows = db.scalars(select(Notification).where(Notification.user_id == ctx.user.id)
                      .order_by(Notification.created_at.desc()).limit(limit))
    return [{"id": n.id, "type": n.type, "title": n.title, "body": n.body, "severity": n.severity,
             "created_at": n.created_at, "read": n.read_at is not None} for n in rows]


@router.post("/notifications/{notification_id}/read", status_code=204, summary="Marquer comme lue")
def read_notification(notification_id: uuid.UUID,
                      ctx: AuthContext = Depends(require_permission("notification:read:own")),
                      db: DbSession = Depends(get_db)):
    n = db.get(Notification, notification_id)
    if n is None or n.user_id != ctx.user.id:
        raise AuthError(404, "notification_not_found", "Notification introuvable.")
    n.read_at = n.read_at or datetime.now(UTC)
    db.commit()


@router.get("/me/security-events", summary="Résumé de mes événements de sécurité")
def my_events(ctx: AuthContext = Depends(require_permission("security_event:read:own")),
              db: DbSession = Depends(get_db), limit: int = Query(30, ge=1, le=100)):
    rows = db.scalars(select(SecurityEvent).where(SecurityEvent.user_id == ctx.user.id,
                                                  SecurityEvent.category != "staff")
                      .order_by(SecurityEvent.timestamp.desc()).limit(limit))
    return [{"id": e.id, "type": e.event_type, "severity": e.severity, "date": e.timestamp,
             "location": e.location, "amount": e.amount} for e in rows]
