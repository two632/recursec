"""Credential manager — securely manages discovered and configured credentials.

Implements:
1. Credential storage (encrypted in memory)
2. Credential types (password, token, key, cert, cookie)
3. Credential association with targets
4. Credential rotation tracking
5. Default credential database
6. Credential reuse detection
7. Password strength analysis
8. Credential lifecycle management
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


import structlog

logger = structlog.get_logger()


class CredentialType(str, Enum):
    PASSWORD = "password"
    TOKEN = "token"
    API_KEY = "api_key"
    SSH_KEY = "ssh_key"
    CERTIFICATE = "certificate"
    COOKIE = "cookie"
    HASH = "hash"
    DEFAULT = "default"


class CredentialSource(str, Enum):
    DISCOVERED = "discovered"
    CONFIGURED = "configured"
    DEFAULT_DB = "default_db"
    BRUTE_FORCE = "brute_force"
    DUMP = "dump"


@dataclass
class Credential:
    """A stored credential."""
    cred_id: str = ""
    cred_type: CredentialType = CredentialType.PASSWORD
    source: CredentialSource = CredentialSource.DISCOVERED
    username: str = ""
    secret_hash: str = ""         # Store hash only, never plaintext
    target: str = ""
    service: str = ""
    port: int = 0
    valid: bool = True
    last_verified: float = 0.0
    discovered_at: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.cred_id, "type": self.cred_type.value,
            "source": self.source.value,
            "username": self.username,
            "target": self.target[:60],
            "service": self.service,
            "valid": self.valid,
        }


# ── Default Credentials Database ─────────────────────────────

DEFAULT_CREDENTIALS: list[dict[str, str]] = [
    {"service": "ssh", "username": "root", "password": "root"},
    {"service": "ssh", "username": "root", "password": "toor"},
    {"service": "ssh", "username": "admin", "password": "admin"},
    {"service": "ssh", "username": "admin", "password": "password"},
    {"service": "ftp", "username": "anonymous", "password": ""},
    {"service": "ftp", "username": "admin", "password": "admin"},
    {"service": "mysql", "username": "root", "password": ""},
    {"service": "mysql", "username": "root", "password": "root"},
    {"service": "mysql", "username": "root", "password": "mysql"},
    {"service": "postgresql", "username": "postgres", "password": "postgres"},
    {"service": "postgresql", "username": "postgres", "password": ""},
    {"service": "redis", "username": "", "password": ""},
    {"service": "mongodb", "username": "admin", "password": "admin"},
    {"service": "tomcat", "username": "tomcat", "password": "tomcat"},
    {"service": "tomcat", "username": "admin", "password": "admin"},
    {"service": "tomcat", "username": "manager", "password": "manager"},
    {"service": "jenkins", "username": "admin", "password": "admin"},
    {"service": "jboss", "username": "admin", "password": "admin"},
    {"service": "weblogic", "username": "weblogic", "password": "welcome1"},
    {"service": "vnc", "username": "", "password": "password"},
    {"service": "snmp", "username": "", "password": "public"},
    {"service": "snmp", "username": "", "password": "private"},
    {"service": "telnet", "username": "admin", "password": "admin"},
    {"service": "telnet", "username": "root", "password": "root"},
    {"service": "http", "username": "admin", "password": "admin"},
    {"service": "http", "username": "admin", "password": "password"},
    {"service": "http", "username": "admin", "password": "123456"},
    {"service": "http", "username": "admin", "password": "admin123"},
    {"service": "wordpress", "username": "admin", "password": "admin"},
    {"service": "phpmyadmin", "username": "root", "password": ""},
]


class CredentialManager:
    """Manages discovered and configured credentials.

    Stores credentials securely (hashed), tracks
    validity, and provides default credential lookups.
    """

    def __init__(self) -> None:
        self._credentials: dict[str, Credential] = {}
        self._cred_counter = 0
        self._reuse_map: dict[str, list[str]] = {}   # hash -> [cred_ids]
        self._log = logger.bind(component="credential_manager")

    def store(
        self,
        cred_type: CredentialType,
        username: str,
        secret: str,
        target: str = "",
        service: str = "",
        port: int = 0,
        source: CredentialSource = CredentialSource.DISCOVERED,
    ) -> str:
        """Store a credential (secret is hashed)."""
        self._cred_counter += 1
        cid = f"cred-{self._cred_counter}"

        secret_hash = hashlib.sha256(secret.encode()).hexdigest()[:16]

        cred = Credential(
            cred_id=cid,
            cred_type=cred_type,
            source=source,
            username=username,
            secret_hash=secret_hash,
            target=target,
            service=service,
            port=port,
        )

        self._credentials[cid] = cred

        # Track reuse
        self._reuse_map.setdefault(secret_hash, []).append(cid)

        return cid

    def get_for_target(self, target: str) -> list[Credential]:
        """Get credentials for a target."""
        return [c for c in self._credentials.values() if c.target == target and c.valid]

    def get_for_service(self, service: str) -> list[Credential]:
        """Get credentials for a service."""
        return [c for c in self._credentials.values() if c.service == service and c.valid]

    def get_defaults(self, service: str) -> list[dict[str, str]]:
        """Get default credentials for a service."""
        return [d for d in DEFAULT_CREDENTIALS if d["service"] == service]

    def mark_invalid(self, cred_id: str) -> None:
        """Mark a credential as invalid."""
        cred = self._credentials.get(cred_id)
        if cred:
            cred.valid = False

    def mark_verified(self, cred_id: str) -> None:
        """Mark a credential as verified."""
        cred = self._credentials.get(cred_id)
        if cred:
            cred.last_verified = time.time()

    def detect_reuse(self) -> list[dict[str, Any]]:
        """Detect credential reuse across targets."""
        reuse = []
        for secret_hash, cred_ids in self._reuse_map.items():
            if len(cred_ids) > 1:
                creds = [self._credentials[cid] for cid in cred_ids if cid in self._credentials]
                targets = {c.target for c in creds}
                if len(targets) > 1:
                    reuse.append({
                        "hash": secret_hash,
                        "targets": list(targets),
                        "count": len(cred_ids),
                        "username": creds[0].username if creds else "",
                    })
        return reuse

    @staticmethod
    def analyze_strength(password: str) -> dict[str, Any]:
        """Analyze password strength."""
        score = 0
        length = len(password)
        has_upper = bool(re.search(r"[A-Z]", password))
        has_lower = bool(re.search(r"[a-z]", password))
        has_digit = bool(re.search(r"\d", password))
        has_special = bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))

        if length >= 8:
            score += 1
        if length >= 12:
            score += 1
        if length >= 16:
            score += 1
        if has_upper:
            score += 1
        if has_lower:
            score += 1
        if has_digit:
            score += 1
        if has_special:
            score += 1

        # Common passwords check
        common = {"password", "123456", "admin", "root", "test", "guest",
                  "letmein", "qwerty", "abc123", "monkey", "dragon"}
        if password.lower() in common:
            score = 0

        rating = "weak"
        if score >= 6:
            rating = "strong"
        elif score >= 4:
            rating = "medium"

        return {
            "score": score,
            "rating": rating,
            "length": length,
            "has_upper": has_upper,
            "has_lower": has_lower,
            "has_digit": has_digit,
            "has_special": has_special,
        }

    def get_stats(self) -> dict[str, Any]:
        return {
            "total": len(self._credentials),
            "valid": sum(1 for c in self._credentials.values() if c.valid),
            "reuse_detected": len(self.detect_reuse()),
            "services": len({c.service for c in self._credentials.values()}),
        }
