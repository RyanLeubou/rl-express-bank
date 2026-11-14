"""Service d'authentification : connexion, second facteur, rafraîchissement à rotation, déconnexion.

Principes :
  - réponses d'échec génériques côté client ; le détail (raison réelle) n'existe que dans l'événement de sécurité ;
  - toute voie d'échec VALIDE (commit) ses événements avant de lever AuthError ;
  - temps de réponse constant face à un compte inconnu (hash factice) ;
  - jeton de rafraîchissement à usage unique : sa réutilisation révoque toute la famille de sessions.
"""
from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import redis
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session as DbSession

from app.core.config import Settings
from app.events.audit import record_audit
from app.events.catalog import EventType
from app.events.logger import emit
from app.models.auth import Device, MFAConfiguration, RecoveryCode
from app.models.auth import Session as AuthSession
from app.models.cards import Card
from app.models.enums import (
    AccountType,
    CardType,
    DeviceStatus,
    RoleCode,
    SessionStatus,
    Severity,
    UserStatus,
    UserType,
)
from app.models.identity import Role, User, UserRole
from app.security.auth.errors import AuthError
from app.security.auth.passwords import DUMMY_HASH, hash_secret, needs_rehash, verify_secret
from app.security.auth.tokens import (
    MfaPendingClaims,
    TokenService,
    hash_token,
    make_csrf,
    new_opaque_token,
)
from app.security.devices.service import DeviceResolution, parse_user_agent, resolve_device, sanitize_ip
from app.security.mfa import totp
from app.security.ratelimit.throttle import (
    ProgressiveThrottle,
    login_buckets,
    mfa_buckets,
    register_buckets,
)
from app.services.banking.opening import open_account
from app.services.banking.rib import CITY_AGENCY

REFRESH_RACE_GRACE = timedelta(seconds=10)     # deux onglets qui rafraîchissent en même temps
GENERIC_LOGIN_ERROR = "Identifiant ou mot de passe incorrect."
GENERIC_CODE_ERROR = "Code incorrect ou expiré."
PASSWORD_RULE = ("Le mot de passe doit contenir au moins 12 caractères, "  # noqa: S105 - message, pas un secret
                 "une majuscule, une minuscule et un chiffre.")


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass
class SessionBundle:
    session: AuthSession
    access: str
    access_expires: datetime
    refresh: str
    csrf: str
    refresh_max_age: int


@dataclass
class LoginOutcome:
    status: str                       # authenticated | mfa_required | mfa_enrollment_required
    user: User
    device: DeviceResolution
    bundle: SessionBundle | None = None
    pending_token: str | None = None


@dataclass
class Registration:
    card_pin: str                     # en clair une seule fois, pour l'affichage de confirmation
    iban: str
    agency: str
    branch_code: str


def user_permissions(user: User) -> set[str]:
    return {p.code for role in user.roles for p in role.permissions}


class AuthService:
    def __init__(self, db: DbSession, settings: Settings, valkey: redis.Redis, tokens: TokenService) -> None:
        self.db = db
        self.settings = settings
        self.valkey = valkey
        self.tokens = tokens
        self.throttle = ProgressiveThrottle(valkey, settings)

    # ------------------------------------------------------------------ utilitaires
    def _event(self, event_type: EventType, *, user: User | None = None, device: Device | None = None,
               session_id: uuid.UUID | None = None, ip: str | None = None, ua: str | None = None,
               severity: Severity | None = None, **metadata: object) -> None:
        browser, system = parse_user_agent(ua)
        emit(self.db, event_type, severity=severity, user_id=user.id if user else None, session_id=session_id,
             device_id=device.id if device else None, ip_address=sanitize_ip(ip),
             device=device.name if device else None, os=system, browser=browser, metadata=dict(metadata))

    def _mfa_config(self, user_id: uuid.UUID, *, lock: bool = False) -> MFAConfiguration | None:
        stmt = select(MFAConfiguration).where(MFAConfiguration.user_id == user_id)
        return self.db.scalar(stmt.with_for_update() if lock else stmt)

    def mfa_enabled(self, user_id: uuid.UUID) -> bool:
        cfg = self._mfa_config(user_id)
        return bool(cfg and cfg.enabled)

    def _primary_role(self, user: User) -> str | None:
        return user.roles[0].code if user.roles else None

    def _open_session(self, user: User, device: Device, ip: str | None, ua: str | None, *, aal: int,
                      amr: list[str], family_id: uuid.UUID | None = None,
                      family_started: datetime | None = None) -> SessionBundle:
        now = _now()
        started = family_started or now
        expires = min(now + timedelta(seconds=self.settings.refresh_idle_ttl_seconds),
                      started + timedelta(seconds=self.settings.session_absolute_ttl_seconds))
        refresh = new_opaque_token()
        session = AuthSession(
            user_id=user.id, device_id=device.id, refresh_token_hash=hash_token(refresh),
            family_id=family_id or uuid.uuid4(), aal=aal, amr=amr, ip=sanitize_ip(ip),
            user_agent=(ua or "")[:300] or None, expires_at=expires, status=SessionStatus.ACTIVE,
        )
        self.db.add(session)
        self.db.flush()
        access, access_exp = self.tokens.issue_access(user.id, session.id, aal, amr)
        csrf = make_csrf(self.settings.app_secret_key.get_secret_value(), session.id)
        return SessionBundle(session, access, access_exp, refresh, csrf,
                             max(int((expires - now).total_seconds()), 1))

    def _revoke_family(self, family_id: uuid.UUID, reason: str) -> int:
        result = self.db.execute(
            update(AuthSession)
            .where(AuthSession.family_id == family_id, AuthSession.status == SessionStatus.ACTIVE)
            .values(status=SessionStatus.REVOKED, revoked_at=_now(), revoked_reason=reason))
        return result.rowcount or 0

    def _valkey_guard(self, fn):
        try:
            return fn()
        except redis.RedisError as exc:
            raise AuthError(503, "service_unavailable",
                            "Service temporairement indisponible. Réessayez plus tard.") from exc

    # ------------------------------------------------------------------ connexion
    def login(self, *, email: str, password: str, ip: str | None, ua: str | None,
              device_cookie: str | None) -> LoginOutcome:
        email_n = email.strip().lower()
        ident = hashlib.sha256(email_n.encode()).hexdigest()[:16]
        buckets = login_buckets(self.settings, email_n, ip)

        retry_after, scope = self.throttle.check(buckets)
        if retry_after:
            self._event(EventType.LOGIN_FAILED, ip=ip, ua=ua, reason="throttled", scope=scope,
                        identifier_hash=ident, retry_after=retry_after)
            self.db.commit()
            raise AuthError(429, "too_many_attempts",
                            "Trop de tentatives. Patientez avant de réessayer.",
                            headers={"Retry-After": str(retry_after)})

        user = self.db.scalar(select(User).where(User.email == email_n))
        stored = user.password_hash if user and user.password_hash else DUMMY_HASH
        password_ok = verify_secret(stored, password)       # toujours exécuté : temps constant

        reason: str | None = None
        if user is None or user.user_type == UserType.SYSTEM:
            reason = "unknown_account"
        elif not password_ok:
            reason = "bad_password"
        elif user.status != UserStatus.ACTIVE:
            reason = "account_inactive"
        elif user.locked_until and user.locked_until > _now():
            reason = "account_locked"

        if reason or user is None:
            delay = self.throttle.fail(buckets)
            if user is not None:
                user.failed_login_count += 1
            self._event(EventType.LOGIN_FAILED, user=user, ip=ip, ua=ua, reason=reason, identifier_hash=ident,
                        failed_count=user.failed_login_count if user else None, delay_applied=delay)
            self.db.commit()
            raise AuthError(401, "invalid_credentials", GENERIC_LOGIN_ERROR)

        if needs_rehash(user.password_hash):                 # paramètres Argon2 renforcés depuis la création
            user.password_hash = hash_secret(password)

        resolution = resolve_device(self.db, user.id, device_cookie, ua, ip)
        device = resolution.device
        if resolution.blocked:
            self._event(EventType.LOGIN_FAILED, user=user, device=device, ip=ip, ua=ua, reason="device_blocked",
                        severity=Severity.HIGH)
            self.db.commit()
            raise AuthError(403, "device_blocked", "Cet appareil n'est pas autorisé. Contactez le support.")
        if resolution.is_new:
            self._event(EventType.NEW_DEVICE_LOGIN, user=user, device=device, ip=ip, ua=ua, stage="password")

        is_staff = user.user_type == UserType.STAFF
        mfa_on = self.mfa_enabled(user.id)

        if is_staff and not mfa_on:
            purpose, status = "enroll", "mfa_enrollment_required"
        elif is_staff or (mfa_on and not resolution.trusted):
            purpose, status = "login", "mfa_required"
        else:
            purpose, status = "", "authenticated"

        if purpose:
            token, _ = self.tokens.issue_mfa_pending(user.id, device.id, purpose)
            self.db.commit()
            return LoginOutcome(status, user, resolution, pending_token=token)

        self.throttle.reset([b for b in buckets if b.name == "pair"])
        user.failed_login_count = 0
        user.last_login_at = _now()
        bundle = self._open_session(user, device, ip, ua, aal=1, amr=["pwd"])
        self._event(EventType.USER_LOGIN, user=user, device=device, session_id=bundle.session.id, ip=ip, ua=ua,
                    aal=1, new_device=resolution.is_new, trusted_device=resolution.trusted)
        self.db.commit()
        return LoginOutcome("authenticated", user, resolution, bundle=bundle)

    # ------------------------------------------------------------------ ouverture de compte en ligne
    def register(self, *, first_name: str, last_name: str, address: str, city: str, phone: str, email: str,
                 profession: str, password: str, ip: str | None,
                 ua: str | None) -> Registration:
        """Crée le client (rôle CLIENT), son compte courant avec RIB et sa carte de débit.

        L'agence (code guichet du RIB) découle de la ville. Le PIN de la carte est tiré au hasard, stocké
        haché, et rendu une seule fois à l'appelant. La connexion suit via login().
        """
        email_n = email.strip().lower()
        buckets = register_buckets(self.settings, ip)
        retry_after, _ = self.throttle.check(buckets)
        if retry_after:
            raise AuthError(429, "too_many_attempts", "Trop de tentatives. Patientez avant de réessayer.",
                            headers={"Retry-After": str(retry_after)})
        self.throttle.fail(buckets)

        agency = CITY_AGENCY.get(city)
        if agency is None:
            raise AuthError(422, "unknown_city", "Ville non desservie : choisissez une ville de la liste.")
        if not (any(c.islower() for c in password) and any(c.isupper() for c in password)
                and any(c.isdigit() for c in password)) or email_n.split("@")[0] in password.lower():
            raise AuthError(422, "weak_password", PASSWORD_RULE)
        if self.db.scalar(select(User.id).where(User.email == email_n)):
            raise AuthError(409, "email_taken", "Un compte existe déjà avec cette adresse e-mail. Connectez-vous.")

        now = _now()
        user = User(email=email_n, first_name=first_name, last_name=last_name, phone=phone, city=city,
                    address=address, profession=profession, user_type=UserType.CUSTOMER,
                    password_hash=hash_secret(password), password_changed_at=now)
        self.db.add(user)
        self.db.flush()
        role = self.db.scalar(select(Role).where(Role.code == RoleCode.CLIENT))
        self.db.add(UserRole(user_id=user.id, role_id=role.id))
        account = open_account(self.db, user, AccountType.CURRENT)

        pin = f"{secrets.randbelow(10**4):04d}"
        last4 = f"{secrets.randbelow(10**4):04d}"
        card = Card(user_id=user.id, account_id=account.id, card_token=secrets.token_hex(24),
                    masked_pan=f"**** **** **** {last4}", last4=last4,
                    holder_name=f"{first_name} {last_name}".upper()[:80], card_type=CardType.DEBIT,
                    expiry_month=now.month, expiry_year=now.year + 3, pin_hash=hash_secret(pin))
        self.db.add(card)
        self.db.flush()

        self._event(EventType.USER_REGISTERED, user=user, ip=ip, ua=ua, city=city, agency=agency)
        record_audit(self.db, action="USER_REGISTERED", target_type="user", target_id=user.id, actor_id=user.id,
                     actor_role=RoleCode.CLIENT, after={"email": email_n, "account_id": str(account.id),
                                                        "card_id": str(card.id), "branch_code": account.branch_code},
                     ip_address=sanitize_ip(ip))
        self.db.commit()
        return Registration(card_pin=pin, iban=account.iban, agency=agency, branch_code=account.branch_code)

    # ------------------------------------------------------------------ défi MFA en attente
    def read_pending(self, token: str | None, *, purpose: str) -> tuple[MfaPendingClaims, User, Device]:
        """Valide le cookie de défi : signature, finalité, usage unique, nombre d'essais."""
        from app.security.auth.tokens import TokenError

        invalid = AuthError(401, "mfa_session_invalid", "Session de vérification expirée. Reconnectez-vous.",
                            clear_mfa=True)
        if not token:
            raise invalid
        try:
            claims = self.tokens.decode_mfa_pending(token)
        except TokenError as exc:
            raise invalid from exc
        if claims.purpose != purpose:
            raise invalid
        if self._valkey_guard(lambda: self.valkey.exists(f"rlbank:mfa:used:{claims.jti}")):
            raise invalid
        key = f"rlbank:mfa:att:{claims.jti}"
        count = self._valkey_guard(lambda: self.valkey.incr(key))
        if count == 1:
            self._valkey_guard(lambda: self.valkey.expire(key, self.settings.mfa_pending_ttl_seconds))
        if count > self.settings.mfa_max_attempts_per_challenge:
            raise invalid
        user = self.db.get(User, claims.user_id)
        device = self.db.get(Device, claims.device_id)
        if user is None or device is None or user.status != UserStatus.ACTIVE:
            raise invalid
        return claims, user, device

    def _consume_pending(self, claims: MfaPendingClaims) -> None:
        self._valkey_guard(lambda: self.valkey.set(f"rlbank:mfa:used:{claims.jti}", "1",
                                                   ex=self.settings.mfa_pending_ttl_seconds))

    # ------------------------------------------------------------------ second facteur
    def verify_mfa(self, *, pending_token: str | None, code: str, trust_device: bool, ip: str | None,
                   ua: str | None) -> tuple[LoginOutcome, int | None]:
        claims, user, device = self.read_pending(pending_token, purpose="login")
        code = code.strip()

        buckets = mfa_buckets(self.settings, str(user.id), ip)
        retry_after, scope = self.throttle.check(buckets)
        if retry_after:
            self._event(EventType.MFA_FAILURE, user=user, device=device, ip=ip, ua=ua, reason="throttled",
                        scope=scope, retry_after=retry_after)
            self.db.commit()
            raise AuthError(429, "too_many_attempts", "Trop de tentatives. Patientez avant de réessayer.",
                            headers={"Retry-After": str(retry_after)})

        cfg = self._mfa_config(user.id, lock=True)
        if cfg is None or not cfg.enabled or cfg.totp_secret_encrypted is None:
            raise AuthError(401, "mfa_session_invalid", "Session de vérification expirée. Reconnectez-vous.",
                            clear_mfa=True)

        method: str | None = None
        if totp.is_totp_format(code):
            secret = totp.decrypt_secret(self.settings, cfg.totp_secret_encrypted, user.id)
            step = totp.verify_totp(secret, code, cfg.last_used_step)
            if step is not None:
                cfg.last_used_step = step
                method = "otp"
        elif totp.is_recovery_format(code):
            hashed = totp.hash_recovery_code(self.settings, code)
            row = self.db.scalar(select(RecoveryCode).where(
                RecoveryCode.user_id == user.id, RecoveryCode.code_hash == hashed,
                RecoveryCode.used_at.is_(None)).with_for_update())
            if row is not None:
                row.used_at = _now()
                method = "rcv"

        if method is None:
            delay = self.throttle.fail(buckets)
            cfg.failed_attempts += 1
            self._event(EventType.MFA_FAILURE, user=user, device=device, ip=ip, ua=ua, reason="bad_code",
                        failed_attempts=cfg.failed_attempts, delay_applied=delay)
            if delay and cfg.failed_attempts >= 5:
                cfg.locked_until = _now() + timedelta(seconds=delay)
                self._event(EventType.MFA_LOCKOUT, user=user, device=device, ip=ip, ua=ua,
                            failed_attempts=cfg.failed_attempts, delay_seconds=delay)
            self.db.commit()
            raise AuthError(401, "invalid_code", GENERIC_CODE_ERROR)

        # ---- succès ----
        cfg.failed_attempts = 0
        cfg.locked_until = None
        self.throttle.reset(buckets)
        self._consume_pending(claims)
        if trust_device and method == "otp" and device.status != DeviceStatus.TRUSTED:
            device.status = DeviceStatus.TRUSTED
            device.trusted_at = _now()
        user.failed_login_count = 0
        user.last_login_at = _now()
        bundle = self._open_session(user, device, ip, ua, aal=2, amr=["pwd", method])
        self._event(EventType.MFA_SUCCESS, user=user, device=device, session_id=bundle.session.id, ip=ip, ua=ua,
                    method=method)
        left: int | None = None
        if method == "rcv":
            left = self.db.scalar(select(func.count()).select_from(RecoveryCode).where(
                RecoveryCode.user_id == user.id, RecoveryCode.used_at.is_(None)))
            self._event(EventType.RECOVERY_CODE_USED, user=user, device=device, ip=ip, ua=ua,
                        session_id=bundle.session.id, codes_left=left)
        self._event(EventType.USER_LOGIN, user=user, device=device, session_id=bundle.session.id, ip=ip, ua=ua,
                    aal=2, method=method, trusted_device=device.status == DeviceStatus.TRUSTED)
        self.db.commit()
        resolution = DeviceResolution(device, "", False, *parse_user_agent(ua))
        return LoginOutcome("authenticated", user, resolution, bundle=bundle), left

    # ------------------------------------------------------------------ activation du TOTP
    def enroll_start(self, user: User, *, password: str | None, pending: bool, ip: str | None,
                     ua: str | None) -> tuple[str, str]:
        if not pending:
            # utilisateur déjà connecté : ré-authentification par mot de passe (le second facteur n'existe pas encore)
            if not password or not verify_secret(user.password_hash or DUMMY_HASH, password):
                self._event(EventType.MFA_FAILURE, user=user, ip=ip, ua=ua, reason="reauth_failed", stage="enroll")
                self.db.commit()
                raise AuthError(401, "invalid_credentials", GENERIC_LOGIN_ERROR)
        cfg = self._mfa_config(user.id, lock=True)
        if cfg is not None and cfg.enabled:
            raise AuthError(409, "mfa_already_enabled", "L'authentification à deux facteurs est déjà active.")
        secret = totp.generate_secret()
        blob = totp.encrypt_secret(self.settings, secret, user.id)
        if cfg is None:
            self.db.add(MFAConfiguration(user_id=user.id, totp_secret_encrypted=blob, enabled=False))
        else:
            cfg.totp_secret_encrypted = blob
            cfg.last_used_step = None
        self.db.commit()
        return secret, totp.provisioning_uri(secret, user.email, self.settings.totp_issuer)

    def enroll_confirm(self, user: User, *, code: str, ip: str | None, ua: str | None,
                       device: Device | None) -> list[str]:
        buckets = mfa_buckets(self.settings, str(user.id), ip)
        retry_after, _ = self.throttle.check(buckets)
        if retry_after:
            raise AuthError(429, "too_many_attempts", "Trop de tentatives. Patientez avant de réessayer.",
                            headers={"Retry-After": str(retry_after)})
        cfg = self._mfa_config(user.id, lock=True)
        if cfg is None or cfg.enabled or cfg.totp_secret_encrypted is None:
            raise AuthError(409, "mfa_enrollment_not_started", "Aucune activation en cours.")
        secret = totp.decrypt_secret(self.settings, cfg.totp_secret_encrypted, user.id)
        step = totp.verify_totp(secret, code, None)
        if step is None:
            self.throttle.fail(buckets)
            self._event(EventType.MFA_FAILURE, user=user, device=device, ip=ip, ua=ua, reason="bad_code",
                        stage="enroll")
            self.db.commit()
            raise AuthError(401, "invalid_code", GENERIC_CODE_ERROR)

        cfg.enabled = True
        cfg.confirmed_at = _now()
        cfg.last_used_step = step
        cfg.failed_attempts = 0
        self.db.execute(RecoveryCode.__table__.delete().where(RecoveryCode.user_id == user.id))
        plain = totp.generate_recovery_codes()
        for item in plain:
            self.db.add(RecoveryCode(user_id=user.id, code_hash=totp.hash_recovery_code(self.settings, item)))
        self.throttle.reset(buckets)
        self._event(EventType.MFA_ENABLED, user=user, device=device, ip=ip, ua=ua)
        record_audit(self.db, action="MFA_ENABLED", target_type="user", target_id=user.id, actor_id=user.id,
                     actor_role=self._primary_role(user), after={"enabled": True, "method": "totp"},
                     ip_address=sanitize_ip(ip))
        return [totp.format_recovery_code(c) for c in plain]

    def finish_enrollment_login(self, claims: MfaPendingClaims, user: User, device: Device, ip: str | None,
                                ua: str | None) -> SessionBundle:
        """Première activation du personnel : la preuve de possession du TOTP vaut second facteur."""
        self._consume_pending(claims)
        user.last_login_at = _now()
        user.failed_login_count = 0
        bundle = self._open_session(user, device, ip, ua, aal=2, amr=["pwd", "otp"])
        self._event(EventType.USER_LOGIN, user=user, device=device, session_id=bundle.session.id, ip=ip, ua=ua,
                    aal=2, method="otp", first_enrollment=True)
        return bundle

    # ------------------------------------------------------------------ rafraîchissement
    def refresh(self, refresh_token: str | None, ip: str | None, ua: str | None) -> tuple[SessionBundle, User]:
        gone = AuthError(401, "not_authenticated", "Authentification requise.", clear_session=True)
        if not refresh_token:
            raise gone
        old = self.db.scalar(select(AuthSession).where(
            AuthSession.refresh_token_hash == hash_token(refresh_token)).with_for_update())
        if old is None:
            raise gone
        now = _now()

        if old.status == SessionStatus.REVOKED and old.revoked_reason == "rotated":
            if old.revoked_at and now - old.revoked_at <= REFRESH_RACE_GRACE:
                raise AuthError(401, "refresh_race", "Session en cours de renouvellement, réessayez.")
            # Jeton déjà utilisé et hors tolérance : probable vol -> toute la famille est révoquée
            user = self.db.get(User, old.user_id)
            revoked = self._revoke_family(old.family_id, "refresh_reuse")
            self._event(EventType.SESSION_REVOKED, user=user, session_id=old.id, ip=ip, ua=ua,
                        severity=Severity.HIGH, reason="refresh_token_reuse", sessions_revoked=revoked)
            self.db.commit()
            raise AuthError(401, "session_revoked", "Session révoquée par mesure de sécurité. Reconnectez-vous.",
                            clear_session=True)
        if old.status != SessionStatus.ACTIVE:
            raise gone
        if old.expires_at <= now:
            old.status = SessionStatus.EXPIRED
            self.db.commit()
            raise gone

        user = self.db.get(User, old.user_id)
        if user is None or user.status != UserStatus.ACTIVE:
            self._revoke_family(old.family_id, "user_inactive")
            self.db.commit()
            raise gone
        device = self.db.get(Device, old.device_id) if old.device_id else None
        if device is None or device.status == DeviceStatus.BLOCKED:
            self._revoke_family(old.family_id, "device_blocked")
            self.db.commit()
            raise gone

        started = self.db.scalar(select(func.min(AuthSession.created_at)).where(
            AuthSession.family_id == old.family_id)) or old.created_at
        if now >= started + timedelta(seconds=self.settings.session_absolute_ttl_seconds):
            self._revoke_family(old.family_id, "absolute_lifetime")
            self.db.commit()
            raise gone

        bundle = self._open_session(user, device, ip, ua, aal=old.aal, amr=list(old.amr),
                                    family_id=old.family_id, family_started=started)
        old.status = SessionStatus.REVOKED
        old.revoked_at = now
        old.revoked_reason = "rotated"
        device.last_seen = now
        self.db.commit()
        return bundle, user

    # ------------------------------------------------------------------ déconnexion et sessions
    def logout(self, session: AuthSession, user: User, ip: str | None, ua: str | None) -> None:
        self._revoke_family(session.family_id, "logout")
        self._event(EventType.USER_LOGOUT, user=user, session_id=session.id, ip=ip, ua=ua)
        self.db.commit()

    def list_sessions(self, user: User) -> list[tuple[AuthSession, str | None]]:
        rows = self.db.execute(
            select(AuthSession, Device.name).outerjoin(Device, Device.id == AuthSession.device_id)
            .where(AuthSession.user_id == user.id, AuthSession.status == SessionStatus.ACTIVE,
                   AuthSession.expires_at > _now())
            .order_by(AuthSession.last_activity.desc())).all()
        return [(s, name) for s, name in rows]

    def revoke_own_session(self, user: User, session_id: uuid.UUID, ip: str | None, ua: str | None) -> None:
        target = self.db.scalar(select(AuthSession).where(
            AuthSession.id == session_id, AuthSession.user_id == user.id,
            AuthSession.status == SessionStatus.ACTIVE).with_for_update())
        if target is None:
            raise AuthError(404, "session_not_found", "Session introuvable.")
        self._revoke_family(target.family_id, "user_revoked")
        self._event(EventType.SESSION_REVOKED, user=user, session_id=target.id, ip=ip, ua=ua,
                    reason="user_revoked")
        self.db.commit()
