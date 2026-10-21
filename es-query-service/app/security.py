"""Пароли, сессии и защита от перебора паролей."""

import hashlib
import hmac
import secrets
import time
from datetime import timedelta

from sqlalchemy import delete, select

from .config import settings
from .db import SessionLocal, utcnow
from .models import AuthSession, User

SESSION_COOKIE = "esqs_session"
USERNAME_RE = r"^[A-Za-z0-9][A-Za-z0-9._@-]{1,63}$"
MIN_PASSWORD_LEN = 8

# --- пароли (scrypt из стандартной библиотеки) ---

_N, _R, _P = 2 ** 14, 8, 1


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return f"scrypt${_N}${_R}${_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, digest = stored.split("$")
        if algo != "scrypt":
            return False
        calc = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p),
                              dklen=len(digest) // 2)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(calc.hex(), digest)


_DUMMY_HASH = hash_password(secrets.token_hex(8))  # для выравнивания времени ответа при неизвестном логине


def check_password_policy(password: str) -> None:
    if len(password) < MIN_PASSWORD_LEN:
        raise ValueError(f"Пароль должен быть не короче {MIN_PASSWORD_LEN} символов")


# --- сессии ---

def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    with SessionLocal() as s:
        s.add(AuthSession(token_hash=_hash_token(token), user_id=user_id,
                          expires_at=utcnow() + timedelta(hours=settings.session_ttl_hours)))
        s.execute(delete(AuthSession).where(AuthSession.expires_at <= utcnow()))
        s.commit()
    return token


def user_by_session(token: str | None) -> User | None:
    if not token:
        return None
    with SessionLocal() as s:
        sess = s.get(AuthSession, _hash_token(token))
        if sess is None or sess.expires_at <= utcnow():
            return None
        user = s.get(User, sess.user_id)
        return user if user and user.is_active else None


def drop_session(token: str | None) -> None:
    if token:
        with SessionLocal() as s:
            s.execute(delete(AuthSession).where(AuthSession.token_hash == _hash_token(token)))
            s.commit()


def drop_user_sessions(s, user_id: int) -> None:
    s.execute(delete(AuthSession).where(AuthSession.user_id == user_id))


# --- вход и защита от перебора ---

_failures: dict[str, list[float]] = {}
_WINDOW = 15 * 60
_MAX_FAILURES = 5


def login_blocked(username: str) -> bool:
    now = time.time()
    attempts = [t for t in _failures.get(username.lower(), []) if now - t < _WINDOW]
    _failures[username.lower()] = attempts
    return len(attempts) >= _MAX_FAILURES


def authenticate(username: str, password: str) -> User | None:
    with SessionLocal() as s:
        user = s.scalar(select(User).where(User.username == username))
        ok = verify_password(password, user.password_hash if user else _DUMMY_HASH)
        if not (user and ok and user.is_active):
            _failures.setdefault(username.lower(), []).append(time.time())
            return None
        _failures.pop(username.lower(), None)
        user.last_login_at = utcnow()
        s.commit()
        return user
