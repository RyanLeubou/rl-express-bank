"""Identité et contrôle d'accès : utilisateurs, rôles, permissions (RBAC évolutif en base)."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, ForeignKey, Integer, String, Text, Uuid, func
from sqlalchemy.dialects.postgresql import CITEXT
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base
from app.models.enums import UserStatus, UserType
from app.models.mixins import CreatedAt, Timestamps, UUIDPk, enum_col, tz


class Role(UUIDPk, CreatedAt, Base):
    __tablename__ = "roles"
    code: Mapped[str] = mapped_column(String(40), unique=True)
    name: Mapped[str] = mapped_column(String(80))
    description: Mapped[str | None] = mapped_column(Text)
    is_staff: Mapped[bool] = mapped_column(Boolean, default=False)

    permissions: Mapped[list[Permission]] = relationship(secondary="role_permissions", lazy="selectin")


class Permission(UUIDPk, CreatedAt, Base):
    __tablename__ = "permissions"
    # Format ressource:action:portée, ex. withdrawal:create:own
    code: Mapped[str] = mapped_column(String(80), unique=True)
    description: Mapped[str] = mapped_column(Text)
    requires_step_up: Mapped[bool] = mapped_column(Boolean, default=False)

    __table_args__ = (CheckConstraint("code ~ '^[a-z_]+:[a-z_]+:(own|any|assigned)$'", name="code_format"),)


class RolePermission(Base):
    __tablename__ = "role_permissions"
    role_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True)
    permission_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True)


class User(UUIDPk, Timestamps, Base):
    __tablename__ = "users"
    email: Mapped[str] = mapped_column(CITEXT, unique=True)
    password_hash: Mapped[str | None] = mapped_column(String(255))  # NULL : compte SYSTEM non connectable
    first_name: Mapped[str] = mapped_column(String(80))
    last_name: Mapped[str] = mapped_column(String(80))
    phone: Mapped[str | None] = mapped_column(String(32))
    city: Mapped[str | None] = mapped_column(String(80))
    address: Mapped[str | None] = mapped_column(String(200))  # adresse fictive
    profession: Mapped[str | None] = mapped_column(String(80))
    user_type: Mapped[UserType] = mapped_column(enum_col(UserType))
    status: Mapped[UserStatus] = mapped_column(enum_col(UserStatus), default=UserStatus.ACTIVE)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(tz())
    last_login_at: Mapped[datetime | None] = mapped_column(tz())
    password_changed_at: Mapped[datetime | None] = mapped_column(tz())
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)

    roles: Mapped[list[Role]] = relationship(
        secondary="user_roles",
        primaryjoin="User.id == UserRole.user_id",
        secondaryjoin="Role.id == UserRole.role_id",
        lazy="selectin",
        viewonly=True,
    )

    __table_args__ = (
        CheckConstraint("failed_login_count >= 0", name="failed_login_non_negative"),
        CheckConstraint("user_type = 'SYSTEM' OR password_hash IS NOT NULL", name="login_needs_password"),
    )

    @property
    def full_name(self) -> str:
        return f"{self.first_name} {self.last_name}"


class UserRole(Base):
    __tablename__ = "user_roles"
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    role_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("roles.id", ondelete="RESTRICT"), primary_key=True)
    granted_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id", ondelete="SET NULL"))
    granted_at: Mapped[datetime] = mapped_column(tz(), server_default=func.now())
