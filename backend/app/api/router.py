"""Routeur racine de l'API v1. Chaque phase y ajoute ses routeurs de domaine."""
from fastapi import APIRouter

from app.api.v1 import admin, atm_terminal, auth, banking, health, lab, me, soc, support

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(banking.router)
api_router.include_router(me.router)
api_router.include_router(atm_terminal.router)
api_router.include_router(soc.router)
api_router.include_router(admin.router)
api_router.include_router(support.router)
api_router.include_router(lab.router)
api_router.include_router(admin.audit_router)
# Phase 6 : accounts, rib, beneficiaries, transfers · Phase 7 : cards, payments
# Phase 8 : withdrawals, atms, atm_terminal · Phase 13 : alerts · Phase 13B : support …
