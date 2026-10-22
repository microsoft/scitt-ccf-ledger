# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
import re
import time
from uuid import uuid4

import pytest

from pyscitt.client import Client

from .infra.cchost import CCHost

REQUEST_ID_HEADER = "x-ms-request-id"
CLIENT_REQUEST_ID_HEADER = "x-ms-client-request-id"
REQUEST_ID_REGEX = re.compile(r"[0-9a-f]+")
JSON_ENDPOINTS = ["/version", "/configuration", "/entries/txIds"]
INDEXING_RETRY = [(503, "IndexingInProgressRetryLater")]


def test_tracing_headers(client: Client):
    response = client.get("/version")
    assert CLIENT_REQUEST_ID_HEADER not in response.headers
    assert REQUEST_ID_REGEX.match(response.headers[REQUEST_ID_HEADER])

    response = client.get("/version", headers={CLIENT_REQUEST_ID_HEADER: "123 456"})
    assert response.headers[CLIENT_REQUEST_ID_HEADER] == "123 456"


@pytest.mark.parametrize("path", JSON_ENDPOINTS)
def test_tracing_json_content_negotiation_error(client: Client, path):
    client.get(path, retry_on=INDEXING_RETRY)
    response = client.session.get(
        path,
        headers={
            "accept": "application/cbor",
            CLIENT_REQUEST_ID_HEADER: "json-adapter-error",
        },
    )

    assert response.status_code == 406
    assert response.headers["content-type"] == "application/json"
    error = response.json()["error"]
    assert error["code"] == "UnsupportedContentType"
    assert "No supported content type in accept header" in error["message"]
    assert REQUEST_ID_REGEX.fullmatch(response.headers[REQUEST_ID_HEADER])
    assert response.headers[CLIENT_REQUEST_ID_HEADER] == "json-adapter-error"


@pytest.mark.isolated_test(log_level="debug")
class TestJsonAdapterLogging:
    @pytest.mark.parametrize("path", JSON_ENDPOINTS)
    def test_json_error_logging(self, client: Client, cchost: CCHost, path):
        client.get(path, retry_on=INDEXING_RETRY)
        client_request_id = uuid4().hex
        response = client.session.get(
            path,
            headers={
                "accept": "application/cbor",
                CLIENT_REQUEST_ID_HEADER: client_request_id,
            },
        )
        assert response.status_code == 406
        assert response.headers["content-type"] == "application/json"
        assert response.json()["error"]["code"] == "UnsupportedContentType"
        assert response.headers[CLIENT_REQUEST_ID_HEADER] == client_request_id
        request_id = response.headers[REQUEST_ID_HEADER]
        assert REQUEST_ID_REGEX.fullmatch(request_id)

        deadline = time.monotonic() + 5
        while True:
            # Host logs arrive asynchronously and may end with a partial line.
            entries = [
                json.loads(line)
                for line in (cchost.workspace / "std.out")
                .read_text()
                .splitlines(keepends=True)
                if line.endswith("\n")
            ]
            request_logs = [
                entry
                for entry in entries
                if f"ClientRequestId={client_request_id} " in entry["msg"]
            ]
            end_logs = [
                entry for entry in request_logs if "::END:: Stage=MAIN " in entry["msg"]
            ]
            if end_logs:
                break
            assert (
                time.monotonic() < deadline
            ), f"No request-end log for {request_id}: {request_logs}"
            time.sleep(0.05)

        error_logs = [
            entry
            for entry in request_logs
            if entry["level"].upper() == "DEBUG"
            and "Code=UnsupportedContentType " in entry["msg"]
        ]
        assert len(error_logs) == 1, request_logs
        assert len(end_logs) == 1, request_logs
        assert end_logs[0]["level"].upper() == "INFO"
        assert f"Verb=GET Path={path} " in end_logs[0]["msg"]
        assert "Status=406 Code=UnsupportedContentType " in end_logs[0]["msg"]
        assert all(f"RequestId={request_id} " in entry["msg"] for entry in request_logs)
        assert all(
            entry["level"].upper() not in ("FAIL", "FATAL")
            and "Unhandled exception in endpoint" not in entry["msg"]
            for entry in request_logs
        )
