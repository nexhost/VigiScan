from __future__ import annotations

from typing import cast

from modules.cve_checker import (
    CVERecord,
    check_tech_report,
    check_technologies,
    load_cve_database,
    search_cves,
)
from modules.tech_detect import TechDetectReport, TechnologyFinding


def test_load_cve_database_contains_required_examples():
    records = load_cve_database()
    products = {(record["product"], record["version"]) for record in records}

    assert ("Apache", "2.4.49") in products
    assert ("WordPress", None) in products
    assert ("OpenSSL", "1.0.1") in products
    assert all("cvss" in record for record in records)
    assert all("cwe" in record for record in records)
    assert all(record["impact"] for record in records)
    assert all(record["recommendation"] for record in records)
    assert all(record["references"] for record in records)


def test_search_cves_finds_exact_product_version_match():
    matches = search_cves("Apache", "2.4.49")

    assert len(matches) == 1
    assert matches[0]["product"] == "Apache"
    assert matches[0]["matched_version"] == "2.4.49"
    assert matches[0]["affected_version"] == "Apache HTTP Server 2.4.49"
    assert matches[0]["cve"] == "CVE-2021-41773"
    assert matches[0]["cve_id"] == "CVE-2021-41773"
    assert matches[0]["match_type"] == "exact_version"
    assert matches[0]["cvss"] == 7.5
    assert matches[0]["cwe"] == "CWE-22"
    assert matches[0]["impact"]
    assert matches[0]["recommendation"]
    assert matches[0]["references"]


def test_search_cves_returns_generic_product_matches():
    matches = search_cves("WordPress")

    assert len(matches) == 1
    assert matches[0]["product"] == "WordPress"
    assert matches[0]["matched_version"] is None
    assert matches[0]["match_type"] == "product"


def test_search_cves_is_case_insensitive():
    matches = search_cves("openssl", "1.0.1")

    assert matches[0]["product"] == "OpenSSL"
    assert matches[0]["cve"] == "CVE-2014-0160"


def test_check_technologies_uses_detected_products_and_versions():
    technologies = cast(
        list[TechnologyFinding],
        [
            {
                "name": "Apache",
                "version": "2.4.49",
                "confidence": 95,
                "confidence_level": "Alto",
                "evidence": ["Header Server contiene Apache."],
            },
            {
                "name": "WordPress",
                "version": None,
                "confidence": 90,
                "confidence_level": "Alto",
                "evidence": ["Meta generator contiene WordPress."],
            },
        ],
    )

    report = check_technologies(technologies)
    cves = {match["cve"] for match in report["matches"]}

    assert report["module"] == "cve_checker"
    assert "CVE-2021-41773" in cves
    assert "CVE-2017-5487" in cves
    assert report["checked"] == [
        {"product": "Apache", "version": "2.4.49"},
        {"product": "WordPress", "version": None},
    ]


def test_check_tech_report_accepts_custom_database():
    database = cast(
        tuple[CVERecord, ...],
        (
            {
                "product": "ExampleCMS",
                "version": "1.0.0",
                "affected_version": "ExampleCMS 1.0.0",
                "cve": "CVE-2099-0001",
                "cve_id": "CVE-2099-0001",
                "severity": "Low",
                "cvss": 3.1,
                "cwe": "CWE-200",
                "description": "Synthetic local test record.",
                "impact": "Synthetic impact.",
                "recommendation": "Synthetic recommendation.",
                "references": ["https://example.com/cve"],
            },
        ),
    )
    tech_report = cast(
        TechDetectReport,
        {
            "module": "tech_detect",
            "ok": True,
            "target_url": "https://example.com",
            "technologies": [
                {
                    "name": "ExampleCMS",
                    "version": "1.0.0",
                    "confidence": 95,
                    "confidence_level": "Alto",
                    "evidence": ["Synthetic evidence."],
                },
            ],
        },
    )

    report = check_tech_report(tech_report, database=database)

    assert report["matches"][0]["cve"] == "CVE-2099-0001"
    assert report["matches"][0]["cvss"] == 3.1
    assert report["matches"][0]["references"] == ["https://example.com/cve"]
