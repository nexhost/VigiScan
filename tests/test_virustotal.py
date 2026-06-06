from __future__ import annotations

from vigiscan.modules.virustotal import (
    decrypt_api_key,
    detect_kind,
    encrypt_api_key,
    query_reputation,
)


class FakeVTResponse:
    status_code = 200

    def json(self):
        return {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 1,
                        "suspicious": 2,
                        "harmless": 30,
                        "undetected": 4,
                    }
                }
            }
        }


def test_detect_kind_classifies_urls_ips_and_domains():
    assert detect_kind("https://example.com") == "url"
    assert detect_kind("203.0.113.10") == "ip"
    assert detect_kind("example.com") == "domain"


def test_query_reputation_is_disabled_without_api_key():
    result = query_reputation("example.com", None, kind="domain")

    assert result["enabled"] is False
    assert result["ok"] is False
    assert result["message"] == "VirusTotal no configurado."
    assert result["stats"]["malicious"] == 0


def test_query_reputation_normalizes_virustotal_stats():
    calls = []

    def requester(**kwargs):
        calls.append(kwargs)
        return FakeVTResponse()

    result = query_reputation(
        "example.com",
        "vt-key",
        kind="domain",
        requester=requester,
    )

    assert result["ok"] is True
    assert result["malicious"] == 1
    assert result["stats"]["suspicious"] == 2
    assert result["permalink"] == "https://www.virustotal.com/gui/domain/example.com"
    assert calls[0]["headers"]["x-apikey"] == "vt-key"


def test_api_key_encryption_roundtrip():
    encrypted = encrypt_api_key("secret-vt-key", "flask-secret")

    assert encrypted != "secret-vt-key"
    assert decrypt_api_key(encrypted, "flask-secret") == "secret-vt-key"
