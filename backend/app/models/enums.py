"""Énumérations métier. Stockées en VARCHAR + contrainte CHECK (pas de type ENUM natif),
ce qui permet d'ajouter une valeur par une simple migration de contrainte."""
from enum import StrEnum


class UserType(StrEnum):
    CUSTOMER = "CUSTOMER"
    STAFF = "STAFF"
    SYSTEM = "SYSTEM"  # comptes techniques internes (compensation), jamais connectables


class UserStatus(StrEnum):
    ACTIVE = "ACTIVE"
    LOCKED = "LOCKED"
    DISABLED = "DISABLED"


class RoleCode(StrEnum):
    CLIENT = "CLIENT"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    AUDITOR = "AUDITOR"
    SUPPORT_AGENT = "SUPPORT_AGENT"
    SUPER_ADMIN = "SUPER_ADMIN"


class DeviceStatus(StrEnum):
    TRUSTED = "TRUSTED"
    NEW = "NEW"
    SUSPICIOUS = "SUSPICIOUS"
    BLOCKED = "BLOCKED"


class SessionStatus(StrEnum):
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class StepUpMethod(StrEnum):
    PASSWORD = "PASSWORD"
    TOTP = "TOTP"
    PASSKEY = "PASSKEY"


class ChallengeStatus(StrEnum):
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    CONSUMED = "CONSUMED"
    EXPIRED = "EXPIRED"
    FAILED = "FAILED"


class IdempotencyStatus(StrEnum):
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class AccountType(StrEnum):
    CURRENT = "CURRENT"
    SAVINGS = "SAVINGS"
    SECONDARY = "SECONDARY"
    INTERNAL = "INTERNAL"  # comptes techniques de la banque (compensation, ATM, cartes)


class AccountStatus(StrEnum):
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    BLOCKED = "BLOCKED"
    CLOSED = "CLOSED"


class LedgerOperation(StrEnum):
    OPENING = "OPENING"
    SALARY = "SALARY"
    TRANSFER = "TRANSFER"
    CARD_PAYMENT = "CARD_PAYMENT"
    WITHDRAWAL = "WITHDRAWAL"
    ADJUSTMENT = "ADJUSTMENT"


class HoldStatus(StrEnum):
    ACTIVE = "ACTIVE"
    RELEASED = "RELEASED"
    CAPTURED = "CAPTURED"
    EXPIRED = "EXPIRED"


class BeneficiaryStatus(StrEnum):
    PENDING_VERIFICATION = "PENDING_VERIFICATION"
    ACTIVE = "ACTIVE"
    DELETED = "DELETED"


class TransferStatus(StrEnum):
    PENDING = "PENDING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    CANCELLED = "CANCELLED"


class CardStatus(StrEnum):
    ACTIVE = "ACTIVE"
    BLOCKED = "BLOCKED"
    EXPIRED = "EXPIRED"


class CardType(StrEnum):
    DEBIT = "DEBIT"
    PREMIUM = "PREMIUM"


class MerchantCategory(StrEnum):
    FOOD = "FOOD"
    TRANSPORT = "TRANSPORT"
    TECHNOLOGY = "TECHNOLOGY"
    HOTEL = "HOTEL"
    RESTAURANT = "RESTAURANT"
    SHOPPING = "SHOPPING"
    TRAVEL = "TRAVEL"
    OTHER = "OTHER"


class PaymentStatus(StrEnum):
    APPROVED = "APPROVED"
    DECLINED = "DECLINED"
    BLOCKED = "BLOCKED"


class AtmStatus(StrEnum):
    ONLINE = "ONLINE"
    OFFLINE = "OFFLINE"
    MAINTENANCE = "MAINTENANCE"
    SUSPICIOUS = "SUSPICIOUS"


class WithdrawalType(StrEnum):
    CARD = "CARD"
    CARDLESS = "CARDLESS"


class WithdrawalStatus(StrEnum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DECLINED = "DECLINED"
    BLOCKED = "BLOCKED"
    CANCELLED = "CANCELLED"


class CardlessCodeStatus(StrEnum):
    ACTIVE = "ACTIVE"
    USED = "USED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"
    LOCKED = "LOCKED"


class RiskLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskOperation(StrEnum):
    LOGIN = "LOGIN"
    BENEFICIARY = "BENEFICIARY"
    TRANSFER = "TRANSFER"
    CARD_PAYMENT = "CARD_PAYMENT"
    WITHDRAWAL_CARD = "WITHDRAWAL_CARD"
    WITHDRAWAL_CARDLESS = "WITHDRAWAL_CARDLESS"
    SECURITY_SETTINGS = "SECURITY_SETTINGS"
    ADMIN_ACTION = "ADMIN_ACTION"
    SUPPORT_ACTION = "SUPPORT_ACTION"


class PolicyDecision(StrEnum):
    ALLOW = "ALLOW"
    ALLOW_AND_MONITOR = "ALLOW_AND_MONITOR"
    STEP_UP_TOTP = "STEP_UP_TOTP"
    STEP_UP_PASSKEY = "STEP_UP_PASSKEY"
    BLOCK = "BLOCK"


class Severity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ActorType(StrEnum):
    USER = "USER"
    SYSTEM = "SYSTEM"
    ATM = "ATM"
    SIMULATION = "SIMULATION"
    SUPPORT_BOT = "SUPPORT_BOT"


class OutboxStatus(StrEnum):
    PENDING = "PENDING"
    SENT = "SENT"
    FAILED = "FAILED"


class AlertStatus(StrEnum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class AlertSource(StrEnum):
    APP = "APP"
    WAZUH = "WAZUH"
    SUPPORT = "SUPPORT"


class SecurityActionType(StrEnum):
    REVOKE_SESSION = "REVOKE_SESSION"
    LOCK_CARD = "LOCK_CARD"
    BLOCK_DEVICE = "BLOCK_DEVICE"
    BLOCK_OPERATION = "BLOCK_OPERATION"
    CANCEL_CARDLESS_CODES = "CANCEL_CARDLESS_CODES"
    FREEZE_ACCOUNT = "FREEZE_ACCOUNT"
    NOTIFY_CUSTOMER = "NOTIFY_CUSTOMER"
    FORCE_PASSWORD_RESET = "FORCE_PASSWORD_RESET"


class SecurityActionStatus(StrEnum):
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"
    REVERTED = "REVERTED"


class InvestigationStatus(StrEnum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"


class ConversationStatus(StrEnum):
    BOT = "BOT"
    WAITING_HUMAN = "WAITING_HUMAN"
    HUMAN = "HUMAN"
    CLOSED = "CLOSED"


class MessageAuthor(StrEnum):
    CUSTOMER = "CUSTOMER"
    BOT = "BOT"
    AGENT = "AGENT"
    SYSTEM = "SYSTEM"


class ToolCallDecision(StrEnum):
    EXECUTED = "EXECUTED"
    DENIED = "DENIED"
    AWAITING_CONFIRMATION = "AWAITING_CONFIRMATION"
    CANCELLED = "CANCELLED"


class TicketStatus(StrEnum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


class TicketPriority(StrEnum):
    LOW = "LOW"
    NORMAL = "NORMAL"
    HIGH = "HIGH"
    URGENT = "URGENT"


class NotificationChannel(StrEnum):
    IN_APP = "IN_APP"
    EMAIL = "EMAIL"
    SMS = "SMS"


class SimulationStatus(StrEnum):
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
