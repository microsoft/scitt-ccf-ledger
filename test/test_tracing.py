# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
import re
import time
from uuid import uuid4

import pytest

from pyscitt import crypto
from pyscitt.client import Client

from .infra.cchost import CCHost
from .infra.jwt_issuer import JwtIssuer

REQUEST_ID_HEADER = "x-ms-request-id"
CLIENT_REQUEST_ID_HEADER = "x-ms-client-request-id"
REQUEST_ID_REGEX = re.compile(r"[0-9a-f]+")
JSON_ENDPOINTS = ["/version", "/configuration"]


def wait_for_request_logs(cchost, client_request_id, *, postcommit=False):
    deadline = time.monotonic() + 5
    while True:
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
        stage = "POSTCOMMIT" if postcommit else "MAIN"
        if any(f"::END:: Stage={stage} " in entry["msg"] for entry in request_logs):
            return request_logs
        assert time.monotonic() < deadline, request_logs
        time.sleep(0.05)


def assert_completion(response, request_logs, *, started, postcommit=False):
    request_id = response.headers[REQUEST_ID_HEADER]
    assert REQUEST_ID_REGEX.fullmatch(request_id)
    starts = [entry for entry in request_logs if "::START::" in entry["msg"]]
    ends = [entry for entry in request_logs if "::END:: Stage=MAIN " in entry["msg"]]
    commits = [
        entry for entry in request_logs if "::END:: Stage=POSTCOMMIT " in entry["msg"]
    ]
    assert len(starts) == int(started), request_logs
    assert len(ends) == 1, request_logs
    assert len(commits) == int(postcommit), request_logs
    for entry in ends + commits:
        assert entry["level"].upper() == "INFO"
        assert f" Status={response.status_code} " in entry["msg"]
        assert re.search(r" TimeMs=-?\d+ ", entry["msg"])
    assert all(f"RequestId={request_id} " in entry["msg"] for entry in request_logs)


def test_tracing_headers(client: Client):
    response = client.get("/version")
    assert CLIENT_REQUEST_ID_HEADER not in response.headers
    assert REQUEST_ID_REGEX.match(response.headers[REQUEST_ID_HEADER])

    response = client.get("/version", headers={CLIENT_REQUEST_ID_HEADER: "123 456"})
    assert response.headers[CLIENT_REQUEST_ID_HEADER] == "123 456"


@pytest.mark.parametrize("path", JSON_ENDPOINTS)
def test_tracing_json_content_negotiation_error(client: Client, path):
    client.get(path)
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
        client.get(path)
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


@pytest.mark.isolated_test(log_level="debug")
class TestRequestLogging:
    @pytest.mark.parametrize(
        "verb,path,status,started",
        [
            ("GET", "/missing-route", 404, False),
            ("POST", "/version", 405, False),
            ("OPTIONS", "/version", 204, False),
            ("GET", "/app/commit", 200, True),
            ("GET", "/app/tx", 400, True),
        ],
    )
    def test_routing_and_builtin_endpoints(
        self, client: Client, cchost: CCHost, verb, path, status, started
    ):
        client_request_id = uuid4().hex
        response = client.session.request(
            verb, path, headers={CLIENT_REQUEST_ID_HEADER: client_request_id}
        )
        assert response.status_code == status, response.text
        assert response.headers[CLIENT_REQUEST_ID_HEADER] == client_request_id
        request_logs = wait_for_request_logs(cchost, client_request_id)
        assert_completion(response, request_logs, started=started)

    @pytest.mark.parametrize(
        "credential", ["missing", "malformed", "untrusted", "claims"]
    )
    def test_authentication_rejection(
        self, client: Client, cchost: CCHost, configure_service, credential
    ):
        issuer = JwtIssuer()
        client.governance.propose(issuer.create_proposal(), must_pass=True)
        configure_service(
            {
                "authentication": {
                    "allowUnauthenticated": False,
                    "jwt": {"requiredClaims": {"aud": "scitt"}},
                }
            }
        )
        try:
            headers = {CLIENT_REQUEST_ID_HEADER: uuid4().hex}
            if credential != "missing":
                token = {
                    "malformed": "not-a-jwt",
                    "untrusted": JwtIssuer().create_token({"aud": "scitt"}),
                    "claims": issuer.create_token({"aud": "wrong"}),
                }[credential]
                headers["authorization"] = f"Bearer {token}"
            response = client.session.post("/entries", headers=headers, content=b"")
            assert response.status_code == 401
            assert response.json()["error"]["code"] == "InvalidAuthenticationInfo"
            request_logs = wait_for_request_logs(
                cchost, headers[CLIENT_REQUEST_ID_HEADER]
            )
            assert_completion(response, request_logs, started=False)
            ends = [entry for entry in request_logs if "::END::" in entry["msg"]]
            assert "Code=InvalidAuthenticationInfo " in ends[0]["msg"]
            assert not any("Reason=" in entry["msg"] for entry in request_logs)
        finally:
            configure_service({})

    @pytest.mark.parametrize("wait_for_commit", [False, True])
    @pytest.mark.parametrize("api_version", ["", "2026-03-26"])
    def test_registration_final_status(
        self,
        client: Client,
        cchost: CCHost,
        cert_authority,
        configure_service,
        wait_for_commit,
        api_version,
    ):
        configure_service(
            {"policy": {"policyScript": "export function apply(phdr) { return true; }"}}
        )
        identity = cert_authority.create_identity(
            alg="ES256", kty="ec", ec_curve="P-256", add_eku="2.999"
        )
        statement = crypto.sign_json_statement(identity, {"foo": "bar"}, cwt=True)
        client_request_id = uuid4().hex
        response = client.session.post(
            "/entries",
            params={
                "waitForCommit": str(wait_for_commit).lower(),
                "api-version": api_version,
            },
            content=statement,
            headers={
                "content-type": "application/cose",
                CLIENT_REQUEST_ID_HEADER: client_request_id,
            },
        )
        expected_status = 201 if wait_for_commit else (303 if api_version else 202)
        assert response.status_code == expected_status, response.text
        request_logs = wait_for_request_logs(cchost, client_request_id, postcommit=True)
        assert_completion(response, request_logs, started=True, postcommit=True)
        if wait_for_commit:
            assert response.headers["content-type"] == (
                "application/scitt-receipt+cose" if api_version else "application/cose"
            )
        tx_id = response.headers["x-ms-ccf-transaction-id"]
        commits = [
            entry for entry in request_logs if "Stage=POSTCOMMIT" in entry["msg"]
        ]
        assert f" TxId={tx_id} " in commits[0]["msg"]

    def test_large_metadata_does_not_change_echoed_header(
        self, client: Client, cchost: CCHost
    ):
        client_request_id = uuid4().hex + "x" * 200
        logged_client_id = client_request_id[:114] + "...[truncated]"
        response = client.session.get(
            "/missing-route",
            params={"q": "a" * 1500},
            headers={CLIENT_REQUEST_ID_HEADER: client_request_id},
        )
        assert response.status_code == 404
        assert response.headers[CLIENT_REQUEST_ID_HEADER] == client_request_id
        request_logs = wait_for_request_logs(cchost, logged_client_id)
        assert_completion(response, request_logs, started=False)
        message = next(
            entry["msg"] for entry in request_logs if "::END::" in entry["msg"]
        )
        assert re.search(r"Query=\S{1024} URL=", message)
