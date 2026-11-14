"""RL SOLUTION passe à un LLM hébergé (Groq) : plus d'embeddings, la table vectorielle knowledge_chunks disparaît.

Les fiches (knowledge_documents) restent la seule source ; elles sont toutes transmises au modèle.
L'extension pgvector reste installée (sans effet) : la migration initiale en dépend.

Revision ID: 0004_drop_knowledge_chunks
Revises: 0003_savings_permission
Create Date: 2026-11-14 01:00:00+00:00
"""
from collections.abc import Sequence

import pgvector.sqlalchemy
import sqlalchemy as sa
from alembic import op

revision: str = '0004_drop_knowledge_chunks'
down_revision: str | None = '0003_savings_permission'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_index('ix_knowledge_chunks_embedding_hnsw', table_name='knowledge_chunks', postgresql_using='hnsw')
    op.drop_index(op.f('ix_knowledge_chunks_document_id'), table_name='knowledge_chunks')
    op.drop_table('knowledge_chunks')


def downgrade() -> None:
    op.create_table(
        'knowledge_chunks',
        sa.Column('document_id', sa.Uuid(), nullable=False),
        sa.Column('position', sa.Integer(), nullable=False),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('embedding', pgvector.sqlalchemy.vector.VECTOR(dim=768), nullable=True),
        sa.Column('id', sa.Uuid(), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['document_id'], ['knowledge_documents.id'],
                                name=op.f('fk_knowledge_chunks_document_id_knowledge_documents'), ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_knowledge_chunks')),
    )
    op.create_index(op.f('ix_knowledge_chunks_document_id'), 'knowledge_chunks', ['document_id'], unique=False)
    op.create_index('ix_knowledge_chunks_embedding_hnsw', 'knowledge_chunks', ['embedding'], unique=False,
                    postgresql_using='hnsw', postgresql_with={'m': 16, 'ef_construction': 64},
                    postgresql_ops={'embedding': 'vector_cosine_ops'})
