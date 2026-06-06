"""Defensive secret scanner with masked evidence."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class SecretPattern:
    name: str
    pattern: re.Pattern[str]
    risk: str
    recommendation: str


SECRET_PATTERNS = [
    SecretPattern("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "High", "Rotate the key and remove it from public content."),
    SecretPattern("GitHub Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"), "High", "Revoke the token and store it in a secret manager."),
    SecretPattern("Slack Token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"), "High", "Revoke the Slack token and audit usage."),
    SecretPattern("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "Medium", "Restrict and rotate the API key."),
    SecretPattern("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"), "Medium", "Avoid exposing bearer tokens in client content."),
    SecretPattern("Database URI", re.compile(r"\b(?:postgres|mysql|mongodb)://[^\s\"']+", re.I), "High", "Move database credentials to protected configuration."),
    SecretPattern("Hardcoded Password", re.compile(r"(?i)\bpassword\s*[:=]\s*[\"'][^\"']{6,}[\"']"), "High", "Remove hardcoded passwords and rotate affected credentials."),
    SecretPattern("Generic API Key", re.compile(r"(?i)\bapi[_-]?key\s*[:=]\s*[\"'][A-Za-z0-9_\-]{16,}[\"']"), "Medium", "Move API keys to protected server-side configuration."),
    SecretPattern("Token", re.compile(r"(?i)\btoken\s*[:=]\s*[\"'][A-Za-z0-9_\-.]{20,}[\"']"), "Medium", "Avoid exposing tokens and rotate if public."),
]


def scan_text(content: str, *, source: str = "inline") -> dict[str, Any]:
    """Scan text and return masked secret findings."""
    findings = []
    for secret_pattern in SECRET_PATTERNS:
        for match in secret_pattern.pattern.finditer(content):
            findings.append(
                {
                    "type": secret_pattern.name,
                    "source": source,
                    "risk": secret_pattern.risk,
                    "evidence": mask_secret(match.group(0)),
                    "recommendation": secret_pattern.recommendation,
                }
            )
    return {"module": "secret_scanner", "ok": True, "findings": findings}


def scan_path(path: str | Path) -> dict[str, Any]:
    """Scan one authorized local file."""
    file_path = Path(path)
    content = file_path.read_text(encoding="utf-8", errors="ignore")
    return scan_text(content, source=str(file_path))


def mask_secret(value: str) -> str:
    """Mask a detected value while preserving enough context for triage."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * max(4, len(value) - 8)}{value[-4:]}"
