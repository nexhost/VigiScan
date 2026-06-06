from __future__ import annotations

from requests.exceptions import SSLError

from vigiscan.modules.uptime import check_url, summarize_checks


class FakeResponse:
    def __init__(self, status_code: int):
        self.status_code = status_code
        self.closed = False

    def close(self) -> None:
        self.closed = True


def test_check_url_returns_availability_and_ssl_status():
    response = FakeResponse(204)

    def requester(**kwargs):
        assert kwargs["url"] == "https://example.com"
        assert kwargs["verify"] is True
        return response

    result = check_url("https://example.com", requester=requester)

    assert result["up"] is True
    assert result["status_code"] == 204
    assert result["ssl_enabled"] is True
    assert result["ssl_valid"] is True
    assert response.closed is True


def test_check_url_handles_ssl_errors_without_raising():
    def requester(**kwargs):
        raise SSLError("certificate verify failed")

    result = check_url("https://expired.example", requester=requester)

    assert result["up"] is False
    assert result["ssl_enabled"] is True
    assert result["ssl_valid"] is False
    assert "certificate verify failed" in str(result["error"])


def test_summarize_checks_calculates_uptime_and_response_time():
    summary = summarize_checks(
        [
            {
                "url": "https://a.example",
                "up": True,
                "status_code": 200,
                "response_time_ms": 100,
                "ssl_enabled": True,
                "ssl_valid": True,
                "error": None,
            },
            {
                "url": "https://b.example",
                "up": False,
                "status_code": 500,
                "response_time_ms": 300,
                "ssl_enabled": True,
                "ssl_valid": True,
                "error": None,
            },
        ]
    )

    assert summary["total"] == 2
    assert summary["up"] == 1
    assert summary["down"] == 1
    assert summary["uptime_percentage"] == 50.0
    assert summary["avg_response_time"] == 200.0
