from __future__ import annotations

from typing import cast

import cli
from scanner import ScanResult


class FakeScanner:
    def __init__(self, timeout_seconds: float) -> None:
        self.timeout_seconds = timeout_seconds

    def scan(self, request):
        assert request.url == "https://example.com"
        return cast(
            ScanResult,
            {
                "ok": True,
                "target": {
                    "url": "https://example.com",
                    "scheme": "https",
                    "hostname": "example.com",
                    "port": None,
                    "path": "/",
                },
                "request": {
                    "method": "GET",
                    "timeout_seconds": self.timeout_seconds,
                    "max_body_bytes": 65536,
                    "allow_redirects": False,
                },
                "response": {
                    "status_code": 200,
                    "reason": "OK",
                    "final_url": "https://example.com",
                    "elapsed_ms": 10,
                    "headers": {
                        "Content-Security-Policy": "default-src 'self'",
                        "Server": "Apache/2.4.49",
                    },
                    "body_sample": "",
                    "body_truncated": False,
                },
                "error": None,
            },
        )


def test_build_parser_accepts_final_command_options():
    args = cli.build_parser().parse_args(
        [
            "--url",
            "https://example.com",
            "--report",
            "html",
            "--timeout",
            "2.5",
            "--output",
            "out",
            "--verbose",
        ],
    )

    assert args.url == "https://example.com"
    assert args.report == "html"
    assert args.timeout == 2.5
    assert args.output == "out"
    assert args.verbose is True


def test_main_generates_selected_report(monkeypatch, tmp_path):
    def fake_create_scanner(config):
        return FakeScanner(config.timeout_seconds)

    def fake_analyze_directories(scan_result, config):
        return {
            "module": "directories",
            "ok": True,
            "target_url": "https://example.com",
            "wordlist_size": 1,
            "exposed_count": 0,
            "findings": [],
        }

    monkeypatch.setattr(cli, "create_scanner", fake_create_scanner)
    monkeypatch.setattr(cli, "analyze_directories", fake_analyze_directories)

    exit_code = cli.main(
        [
            "--url",
            "https://example.com",
            "--report",
            "html",
            "--output",
            str(tmp_path),
            "--timeout",
            "3",
        ],
    )

    assert exit_code == 0
    html_reports = list(tmp_path.glob("*.html"))
    assert len(html_reports) == 1
    assert "VigiScan Security Report" in html_reports[0].read_text(encoding="utf-8")
