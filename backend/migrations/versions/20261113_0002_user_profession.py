"""Profession du client, saisie à l'ouverture de compte en ligne.

Revision ID: 0002_user_profession
Revises: 0001_schema_initial
Create Date: 2026-11-13 19:10:00+00:00
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0002_user_profession'
down_revision: str | None = '0001_schema_initial'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column('users', sa.Column('profession', sa.String(length=80), nullable=True))


def downgrade() -> None:
    op.drop_column('users', 'profession')
