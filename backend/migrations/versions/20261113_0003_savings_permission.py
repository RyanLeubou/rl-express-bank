"""Permission client account:create:own (ouverture du livret épargne) pour les bases déjà initialisées.

Revision ID: 0003_savings_permission
Revises: 0002_user_profession
Create Date: 2026-11-13 19:30:00+00:00
"""
from collections.abc import Sequence

from alembic import op

revision: str = '0003_savings_permission'
down_revision: str | None = '0002_user_profession'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Sans effet sur une base vide : le seed crée alors la permission depuis le catalogue
    op.execute("""
        INSERT INTO permissions (code, description, requires_step_up)
        SELECT 'account:create:own', 'Ouvrir un livret épargne', false
        WHERE EXISTS (SELECT 1 FROM roles WHERE code = 'CLIENT')
        ON CONFLICT (code) DO NOTHING
    """)
    op.execute("""
        INSERT INTO role_permissions (role_id, permission_id)
        SELECT r.id, p.id FROM roles r, permissions p
        WHERE r.code = 'CLIENT' AND p.code = 'account:create:own'
        ON CONFLICT DO NOTHING
    """)


def downgrade() -> None:
    op.execute("DELETE FROM permissions WHERE code = 'account:create:own'")
