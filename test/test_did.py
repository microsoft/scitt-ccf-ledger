# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import pytest

from pyscitt.did import did_web_document_url, format_did_web


@pytest.mark.parametrize(
    "host, port, path, expected",
    [
        ("w3c-ccg.github.io", None, None, "did:web:w3c-ccg.github.io"),
        (
            "w3c-ccg.github.io",
            None,
            "user/alice",
            "did:web:w3c-ccg.github.io:user:alice",
        ),
        ("example.com", 3000, "user/alice", "did:web:example.com%3A3000:user:alice"),
        ("example.com", 3000, None, "did:web:example.com%3A3000"),
    ],
)
def test_format_did_web(host, port, path, expected):
    assert format_did_web(host, port, path) == expected


@pytest.mark.parametrize(
    "did, expected",
    [
        ("did:web:w3c-ccg.github.io", "https://w3c-ccg.github.io/.well-known/did.json"),
        (
            "did:web:w3c-ccg.github.io:user:alice",
            "https://w3c-ccg.github.io/user/alice/did.json",
        ),
        (
            "did:web:example.com%3A3000:user:alice",
            "https://example.com:3000/user/alice/did.json",
        ),
        ("did:web:example.com%3A3000", "https://example.com:3000/.well-known/did.json"),
    ],
)
def test_did_web_document_url(did, expected):
    assert did_web_document_url(did) == expected
