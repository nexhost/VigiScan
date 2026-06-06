"""Passive edge protection detection from headers and cookies."""

from __future__ import annotations

from typing import Any


SIGNATURES = {
    "Cloudflare": ["cf-ray", "cf-cache-status", "__cf_bm"],
    "Akamai": ["akamai", "aka_"],
    "AWS edge protection": ["x-amzn", "awselb"],
    "Imperva": ["incap_ses", "visid_incap"],
    "SafeLine": ["safeline"],
    "ModSecurity": ["mod_security", "modsecurity"],
    "FortiWeb": ["fortiwaf", "fortiweb"],
    "F5 BIG-IP ASM": ["bigip", "f5"],
    "Nginx App Protect": ["nginx-app-protect"],
}


def detect_waf(scan_result: dict[str, Any]) -> dict[str, Any]:
    """Detect likely edge protection from passive response metadata."""
    response = scan_result.get("response", {}) if isinstance(scan_result, dict) else {}
    headers = response.get("headers", {}) if isinstance(response, dict) else {}
    cookies = response.get("cookies", {}) if isinstance(response, dict) else {}
    haystack = " ".join(
        [f"{key}:{value}" for key, value in headers.items()]
        + [f"{key}:{value}" for key, value in cookies.items()]
    ).lower()
    detections = []
    for vendor, needles in SIGNATURES.items():
        evidence = [needle for needle in needles if needle.lower() in haystack]
        if evidence:
            detections.append(
                {
                    "waf": vendor,
                    "evidence": evidence,
                    "confidence": "High" if len(evidence) > 1 else "Medium",
                }
            )
    return {"module": "waf_detect", "ok": True, "detections": detections}
