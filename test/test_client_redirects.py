# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import httpx
import pytest

from pyscitt.client import BaseClient


def make_client(handler, url="https://primary.example.com") -> BaseClient:
    client = BaseClient(url, auth_token="secret")
    client.session = httpx.Client(
        base_url=url,
        headers={"Authorization": "Bearer secret"},
        transport=httpx.MockTransport(handler),
    )
    return client


def redirect_to(location: str, status: int = 307):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/start":
            return httpx.Response(status, headers={"location": location})
        return httpx.Response(200, json={"host": request.url.host})

    return handler


def test_follows_redirect_to_another_https_node():
    client = make_client(redirect_to("https://node2.example.com/final"))
    response = client.request("POST", "/start", content=b"body")
    assert response.json() == {"host": "node2.example.com"}


def test_follows_relative_redirect():
    client = make_client(redirect_to("/final"))
    response = client.request("POST", "/start", content=b"body")
    assert response.json() == {"host": "primary.example.com"}


@pytest.mark.parametrize(
    "location",
    [
        "http://169.254.169.254/latest/meta-data",
        "https://user:pass@node2.example.com/final",
        "file:///etc/passwd",
    ],
)
@pytest.mark.parametrize("status", [307, 308])
def test_refuses_unsafe_redirect(location, status):
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return redirect_to(location, status)(request)

    client = make_client(handler)
    with pytest.raises(ValueError, match="Refusing redirect"):
        client.request("POST", "/start", content=b"body")
    assert seen == ["https://primary.example.com/start"]


def test_stops_after_too_many_redirects():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(307, headers={"location": "/start"})

    client = make_client(handler)
    with pytest.raises(ValueError, match="Too many redirects"):
        client.request("POST", "/start", content=b"body")
