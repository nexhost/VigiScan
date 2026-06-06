"""Optional VirusTotal threat intelligence integration."""

from __future__ import annotations

import base64
import hashlib
from typing import Any, Literal, NotRequired, TypedDict
from urllib.parse import urlparse

import requests


VTKind = Literal["url", "domain", "ip"]


class VirusTotalResult(TypedDict):
    """Normalized VirusTotal response."""

    enabled: bool
    ok: bool
    kind: str
    target: str
    malicious: int
    suspicious: int
    harmless: int
    undetected: int
    stats: dict[str, int]
    permalink: NotRequired[str | None]
    message: str


def query_reputation(
    target: str,
    api_key: str | None,
    *,
    kind: VTKind = "url",
    requester: Any = requests.get,
) -> VirusTotalResult:
    """Query VirusTotal v3 only when an API key exists."""
    if not api_key:
        return _empty_result(kind, target, "VirusTotal no configurado.", enabled=False)

    endpoint = _endpoint_for(kind, target)
    try:
        response = requester(
            url=endpoint,
            headers={"x-apikey": api_key},
            timeout=15,
        )
        if response.status_code >= 400:
            return _empty_result(
                kind,
                target,
                f"VirusTotal respondio HTTP {response.status_code}.",
                enabled=True,
            )
        payload = response.json()
    except Exception as exc:
        return _empty_result(kind, target, str(exc), enabled=True)

    stats = (
        payload.get("data", {})
        .get("attributes", {})
        .get("last_analysis_stats", {})
    )
    return {
        "enabled": True,
        "ok": True,
        "kind": kind,
        "target": target,
        "malicious": int(stats.get("malicious", 0)),
        "suspicious": int(stats.get("suspicious", 0)),
        "harmless": int(stats.get("harmless", 0)),
        "undetected": int(stats.get("undetected", 0)),
        "stats": {
            "malicious": int(stats.get("malicious", 0)),
            "suspicious": int(stats.get("suspicious", 0)),
            "harmless": int(stats.get("harmless", 0)),
            "undetected": int(stats.get("undetected", 0)),
        },
        "permalink": _permalink_for(kind, target),
        "message": "Consulta completada.",
    }


def detect_kind(target: str) -> VTKind:
    """Infer whether a target is URL, IP or domain."""
    parsed = urlparse(target)
    if parsed.scheme in {"http", "https"}:
        return "url"
    if all(part.isdigit() and 0 <= int(part) <= 255 for part in target.split(".") if part):
        if target.count(".") == 3:
            return "ip"
    return "domain"


def _endpoint_for(kind: VTKind, target: str) -> str:
    if kind == "url":
        url_id = _virustotal_url_id(target)
        return f"https://www.virustotal.com/api/v3/urls/{url_id}"
    if kind == "domain":
        return f"https://www.virustotal.com/api/v3/domains/{target}"
    return f"https://www.virustotal.com/api/v3/ip_addresses/{target}"


def _permalink_for(kind: VTKind, target: str) -> str:
    if kind == "url":
        return f"https://www.virustotal.com/gui/url/{_virustotal_url_id(target)}"
    if kind == "domain":
        return f"https://www.virustotal.com/gui/domain/{target}"
    return f"https://www.virustotal.com/gui/ip-address/{target}"


def _virustotal_url_id(target: str) -> str:
    return (
        base64.urlsafe_b64encode(target.encode("utf-8"))
        .decode("ascii")
        .strip("=")
    )


def _empty_result(
    kind: str,
    target: str,
    message: str,
    *,
    enabled: bool,
) -> VirusTotalResult:
    return {
        "enabled": enabled,
        "ok": False,
        "kind": kind,
        "target": target,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "stats": {
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
        },
        "permalink": None,
        "message": message,
    }


def encrypt_api_key(api_key: str, secret: str) -> str:
    """Lightweight reversible at-rest protection using the Flask secret."""
    if not api_key:
        return ""
    key = hashlib.sha256(secret.encode("utf-8")).digest()
    data = api_key.encode("utf-8")
    encrypted = bytes(byte ^ key[index % len(key)] for index, byte in enumerate(data))
    return base64.urlsafe_b64encode(encrypted).decode("ascii")


def decrypt_api_key(value: str | None, secret: str) -> str | None:
    """Reverse ``encrypt_api_key``."""
    if not value:
        return None
    key = hashlib.sha256(secret.encode("utf-8")).digest()
    data = base64.urlsafe_b64decode(value.encode("ascii"))
    plain = bytes(byte ^ key[index % len(key)] for index, byte in enumerate(data))
    return plain.decode("utf-8")
