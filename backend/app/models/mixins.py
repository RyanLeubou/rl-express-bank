"""Colonnes communes : clé primaire UUID, horodatages UTC, énumérations en CHECK."""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import DateTime, Enum, Uuid, func, text
from sqlalchemy.orm import Mapped, mapped_column


class UUIDPk:
    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()")
    )


class CreatedAt:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class Timestamps(CreatedAt):
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


def enum_col(enum_cls: type[StrEnum], name: str | None = None) -> Enum:
    """VARCHAR(32) validé côté Python ; la contrainte CHECK est ajoutée par colonne
    (ck_<table>_<colonne>_values) par add_enum_check_constraints()."""
    return Enum(
        enum_cls,
        native_enum=False,
        create_constraint=False,
        length=32,
        name=name or f"{enum_cls.__name__.lower()}",
        values_callable=lambda e: [m.value for m in e],
        validate_strings=True,
    )


def add_enum_check_constraints(metadata) -> None:
    """Ajoute une contrainte CHECK nommée par colonne pour chaque énumération."""
    from sqlalchemy import CheckConstraint

    for table in metadata.tables.values():
        existing = {c.name for c in table.constraints if c.name}
        for column in table.columns:
            if isinstance(column.type, Enum) and column.type.enums:
                name = f"{column.name}_values"
                if name in existing:
                    continue
                values = ", ".join(f"'{v}'" for v in column.type.enums)
                table.append_constraint(CheckConstraint(f"{column.name} IN ({values})", name=name))


def tz() -> DateTime:
    return DateTime(timezone=True)
