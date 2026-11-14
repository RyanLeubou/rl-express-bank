"""Modèles SQLAlchemy. Chaque module de modèles doit être importé ici pour être vu par Alembic."""
from app.models import analytics, auth, banking, cards, identity, security, support  # noqa: F401
from app.models.analytics import BehaviorProfile, MLModel, Notification, SimulationRun
from app.models.auth import (
                             Device,
                             IdempotencyKey,
                             MFAConfiguration,
                             PasskeyCredential,
                             RecoveryCode,
                             Session,
                             StepUpChallenge,
)
from app.models.banking import Account, AccountHold, Beneficiary, LedgerEntry, Transfer
from app.models.base import Base
from app.models.cards import ATM, Card, CardlessCode, CardPayment, Withdrawal
from app.models.identity import Permission, Role, RolePermission, User, UserRole
from app.models.mixins import add_enum_check_constraints
from app.models.security import (
                             AlertEvent,
                             AuditLog,
                             Investigation,
                             InvestigationNote,
                             OutboxEvent,
                             RiskAssessment,
                             RiskRule,
                             SecurityAction,
                             SecurityAlert,
                             SecurityEvent,
                             SecurityPolicy,
)
from app.models.support import (
                             BankContact,
                             KnowledgeDocument,
                             SupportConversation,
                             SupportMessage,
                             SupportTicket,
                             SupportToolCall,
)

add_enum_check_constraints(Base.metadata)

__all__ = [
    "ATM", "Account", "AccountHold", "AlertEvent", "AuditLog", "BankContact", "Base", "BehaviorProfile",
    "Beneficiary", "Card", "CardPayment", "CardlessCode", "Device", "IdempotencyKey", "Investigation",
    "InvestigationNote", "KnowledgeDocument", "LedgerEntry", "MFAConfiguration", "MLModel",
    "Notification", "OutboxEvent", "PasskeyCredential", "Permission", "RecoveryCode", "RiskAssessment",
    "RiskRule", "Role", "RolePermission", "SecurityAction", "SecurityAlert", "SecurityEvent", "SecurityPolicy",
    "Session", "SimulationRun", "StepUpChallenge", "SupportConversation", "SupportMessage", "SupportTicket",
    "SupportToolCall", "Transfer", "User", "UserRole", "Withdrawal",
]
