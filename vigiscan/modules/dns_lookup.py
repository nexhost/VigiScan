"""Defensive DNS and domain lookup helpers."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse


DNS_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA")


@dataclass(frozen=True)
class DomainLookupResult:
    """Normalized DNS lookup result for the web UI."""

    ok: bool
    target: str
    hostname: str
    records: dict[str, list[str]]
    reverse_dns: list[str]
    canonical_name: str | None
    ip_addresses: list[str]
    message: str
    resolver: str


def normalize_lookup_target(value: str) -> str:
    """Extract a hostname or IP address from user input."""
    raw = (value or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    host = parsed.hostname or raw.split("/", 1)[0].split(":", 1)[0]
    return host.strip().strip(".").lower()


def lookup_domain(value: str, timeout: float = 3.0) -> DomainLookupResult:
    """Run a DNS/domain lookup with dnspython when available, stdlib otherwise."""
    hostname = normalize_lookup_target(value)
    if not hostname:
        return DomainLookupResult(
            ok=False,
            target=value,
            hostname="",
            records={record_type: [] for record_type in DNS_RECORD_TYPES},
            reverse_dns=[],
            canonical_name=None,
            ip_addresses=[],
            message="Ingresa un dominio, URL o IP valida.",
            resolver="stdlib",
        )

    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False

    records = {record_type: [] for record_type in DNS_RECORD_TYPES}
    reverse_dns: list[str] = []
    canonical_name: str | None = None
    resolver_name = "stdlib"

    try:
        canonical_name = socket.getfqdn(hostname)
    except OSError:
        canonical_name = None

    if is_ip:
        records["A"].append(hostname)
        try:
            reverse_dns.append(socket.gethostbyaddr(hostname)[0])
        except OSError:
            reverse_dns = []
        return DomainLookupResult(
            ok=True,
            target=value,
            hostname=hostname,
            records=records,
            reverse_dns=reverse_dns,
            canonical_name=canonical_name,
            ip_addresses=[hostname],
            message="Consulta completada.",
            resolver=resolver_name,
        )

    try:
        import dns.resolver  # type: ignore[import-not-found]

        resolver_name = "dnspython"
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        resolver.timeout = timeout
        for record_type in DNS_RECORD_TYPES:
            try:
                answers = resolver.resolve(hostname, record_type, raise_on_no_answer=False)
            except Exception:
                continue
            records[record_type] = sorted(
                {
                    _format_dns_answer(record_type, answer)
                    for answer in answers
                    if str(answer).strip()
                }
            )
    except ImportError:
        records["A"] = _stdlib_addresses(hostname, socket.AF_INET)
        records["AAAA"] = _stdlib_addresses(hostname, socket.AF_INET6)

    ip_addresses = sorted(set(records["A"] + records["AAAA"]))
    if not ip_addresses:
        try:
            ip_addresses = sorted({item[4][0] for item in socket.getaddrinfo(hostname, None)})
            records["A"] = sorted(
                {item for item in ip_addresses if _is_ip_version(item, 4)}
            )
            records["AAAA"] = sorted(
                {item for item in ip_addresses if _is_ip_version(item, 6)}
            )
        except OSError:
            ip_addresses = []

    return DomainLookupResult(
        ok=bool(ip_addresses or any(records.values())),
        target=value,
        hostname=hostname,
        records=records,
        reverse_dns=reverse_dns,
        canonical_name=canonical_name,
        ip_addresses=ip_addresses,
        message="Consulta completada." if ip_addresses or any(records.values()) else "No se encontraron registros DNS.",
        resolver=resolver_name,
    )


def _stdlib_addresses(hostname: str, family: socket.AddressFamily) -> list[str]:
    try:
        return sorted({item[4][0] for item in socket.getaddrinfo(hostname, None, family)})
    except OSError:
        return []


def _is_ip_version(value: str, version: int) -> bool:
    try:
        return ipaddress.ip_address(value).version == version
    except ValueError:
        return False


def _format_dns_answer(record_type: str, answer: object) -> str:
    text = str(answer).strip().strip('"')
    if record_type == "MX":
        parts = text.split()
        if len(parts) >= 2:
            return f"{parts[1].rstrip('.')} (priority {parts[0]})"
    if record_type in {"NS", "SOA"}:
        return text.rstrip(".")
    return text
