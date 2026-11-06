# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import httpx
import pytest

from pyscitt.client import Client


@pytest.mark.parametrize("api_version", [None, "2025-01-31-preview"])
@pytest.mark.parametrize(
    "submit",
    [
        "submit_signed_statement",
        "submit_signed_statement_and_wait",
        "submit_signed_statement_and_wait_for_receipt",
    ],
)
def test_async_submission_rejects_unsupported_api_version(api_version, submit):
    sent: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(str(request.url))
        return httpx.Response(202)

    url = "https://ledger.example.com"
    client = Client(url, api_version=api_version)
    client.session = httpx.Client(base_url=url, transport=httpx.MockTransport(handler))

    with pytest.raises(ValueError, match="requires api_version"):
        getattr(client, submit)(b"statement")
    assert sent == []
