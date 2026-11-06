"""Server-side sessions and scoped roles; browser never receives application credentials."""

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request

ROLES = {"viewer": 0, "analyst": 1, "approver": 2, "admin": 3}


def password_hash(password):
    salt = secrets.token_hex(16)
    value = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 310000).hex()
    return salt + "$" + value


def check_password(password, stored):
    salt, expected = stored.split("$", 1)
    actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 310000).hex()
    return hmac.compare_digest(actual, expected)


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


@dataclass
class Actor:
    username: str
    role: str
    csrf: str


def bootstrap(store, settings):
    with store.connect() as db:
        db.execute("BEGIN IMMEDIATE")
        if not db.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            db.execute(
                "INSERT INTO users(username,password_hash,role,created) VALUES(?,?,'admin',?)",
                (
                    settings.admin_username,
                    password_hash(settings.admin_password or settings.approve_key),
                    time.time(),
                ),
            )
            store.audit("system", "user.bootstrap", settings.admin_username, "created", db=db)


def principal(request: Request):
    token = request.cookies.get("agentsoc_session", "")
    with request.app.state.service.store.connect() as db:
        row = db.execute(
            "SELECT u.username,u.role,s.csrf FROM sessions s JOIN users u ON u.username=s.username WHERE s.token_hash=? AND s.expires>? AND u.disabled=0",
            (token_hash(token), time.time()),
        ).fetchone()
    if not row:
        raise HTTPException(401, "Login required")
    actor = Actor(**dict(row))
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        csrf = request.headers.get("X-CSRF-Token", "")
        if not csrf or not hmac.compare_digest(csrf, actor.csrf):
            request.app.state.service.store.audit(actor.username, "csrf.denied", request.url.path, "denied")
            raise HTTPException(403, "CSRF token required")
        origin = request.headers.get("Origin")
        if origin:
            from urllib.parse import urlsplit

            if urlsplit(origin).netloc != request.headers.get("host"):
                request.app.state.service.store.audit(
                    actor.username, "origin.denied", request.url.path, "denied"
                )
                raise HTTPException(403, "Cross-origin write refused")
    return actor


def require(role):
    def authorized(request: Request, actor=Depends(principal)):
        if ROLES.get(actor.role, -1) < ROLES[role]:
            request.app.state.service.store.audit(
                actor.username, "permission.denied", request.url.path, "denied"
            )
            raise HTTPException(403, "Insufficient permissions")
        return actor

    return authorized
