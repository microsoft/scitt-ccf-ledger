# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import re

from pyscitt.client import Client

REQUEST_ID_HEADER = "x-ms-request-id"
CLIENT_REQUEST_ID_HEADER = "x-ms-client-request-id"
REQUEST_ID_REGEX = re.compile(r"[0-9a-f]+")


def test_tracing_headers(client: Client):
    response = client.get("/version")
    assert CLIENT_REQUEST_ID_HEADER not in response.headers
    assert REQUEST_ID_REGEX.match(response.headers[REQUEST_ID_HEADER])

    response = client.get("/version", headers={CLIENT_REQUEST_ID_HEADER: "123 456"})
    assert response.headers[CLIENT_REQUEST_ID_HEADER] == "123 456"
