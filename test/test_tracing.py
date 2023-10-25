# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import re

from pyscitt.client import Client

from .infra.assertions import service_error

REQUEST_ID_HEADER = "x-ms-request-id"
CLIENT_REQUEST_ID_HEADER = "x-ms-client-request-id"
REQUEST_ID_REGEX = re.compile(r"[0-9a-f]+")


def test_tracing_headers(client: Client):
    response = client.get("/version")
    assert CLIENT_REQUEST_ID_HEADER not in response.headers
    assert REQUEST_ID_REGEX.match(response.headers[REQUEST_ID_HEADER])

    response = client.get("/version", headers={CLIENT_REQUEST_ID_HEADER: "123"})
    assert response.headers[CLIENT_REQUEST_ID_HEADER] == "123"
    assert REQUEST_ID_REGEX.match(response.headers[REQUEST_ID_HEADER])

    with service_error("InvalidInput: Invalid client request id") as exc_info:
        client.get("/version", headers={CLIENT_REQUEST_ID_HEADER: "123 456"})

    error = exc_info.value
    assert CLIENT_REQUEST_ID_HEADER not in error.headers
    assert REQUEST_ID_REGEX.match(error.headers[REQUEST_ID_HEADER])
