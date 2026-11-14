"""Base de connaissances de RL SOLUTION : fiches publiques ajoutées (RIB / IBAN, bonnes pratiques, comptes, cartes,
virements, sécurité) et fiches existantes corrigées (menus réels, fonction « Vérifier un appel » inexistante).

Sans effet sur une base vide : le seed crée alors les fiches depuis app.seed.reference.KNOWLEDGE.

Revision ID: 0005_knowledge_public_facts
Revises: 0004_drop_knowledge_chunks
Create Date: 2026-11-14 02:00:00+00:00
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from app.seed.reference import KNOWLEDGE

revision: str = '0005_knowledge_public_facts'
down_revision: str | None = '0004_drop_knowledge_chunks'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    if not bind.scalar(sa.text("SELECT EXISTS (SELECT 1 FROM roles)")):
        return                                  # base vide : le seed s'en charge
    upsert = sa.text("""
        INSERT INTO knowledge_documents (slug, title, body, audience, published, version)
        VALUES (:slug, :title, :body, 'CUSTOMER', true, 1)
        ON CONFLICT (slug) DO UPDATE
           SET title = EXCLUDED.title, body = EXCLUDED.body,
               version = knowledge_documents.version + 1, updated_at = now()
         WHERE knowledge_documents.body IS DISTINCT FROM EXCLUDED.body
            OR knowledge_documents.title IS DISTINCT FROM EXCLUDED.title
    """)
    for slug, title, body in KNOWLEDGE:
        bind.execute(upsert, {"slug": slug, "title": title, "body": body})


def downgrade() -> None:
    # Contenu éditorial : les fiches ajoutées ou corrigées sont conservées.
    pass
