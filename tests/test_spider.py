from __future__ import annotations

from requests import Response

from vigiscan.modules.spider import SpiderConfig, crawl_site


def response_for(url: str, body: str, status: int = 200) -> Response:
    response = Response()
    response.status_code = status
    response._content = body.encode("utf-8")
    response.headers["Content-Type"] = "text/html"
    response.url = url
    return response


def test_spider_discovers_same_origin_links_only():
    pages = {
        "https://example.com": "<a href='/a'>A</a><a href='https://evil.test/x'>X</a>",
        "https://example.com/a": "<a href='/b'>B</a>",
        "https://example.com/b": "<p>End</p>",
    }

    def requester(**kwargs):
        url = str(kwargs["url"])
        return response_for(url, pages[url])

    report = crawl_site(
        "https://example.com",
        config=SpiderConfig(max_depth=2, max_urls=10),
        requester=requester,
    )

    urls = {page["url"] for page in report["pages"]}

    assert "https://example.com" in urls
    assert "https://example.com/a" in urls
    assert "https://example.com/b" in urls
    assert "https://evil.test/x" not in urls


def test_spider_respects_max_urls():
    def requester(**kwargs):
        url = str(kwargs["url"])
        return response_for(url, "<a href='/a'>A</a><a href='/b'>B</a>")

    report = crawl_site(
        "https://example.com",
        config=SpiderConfig(max_depth=2, max_urls=1),
        requester=requester,
    )

    assert report["discovered_count"] == 1
