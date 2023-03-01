# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from typing import Optional, Tuple
from urllib.parse import quote, unquote

import httpx
from loguru import logger as LOG

from .crypto import Pem, Signer, get_public_key_fingerprint, jwk_from_public_key

DID_FILENAME = "did.json"
DID_WEB_DOC_URL_SCHEME = "https"
DID_WEB_DOC_WELLKNOWN_PATH = ".well-known"
DID_WEB_PREFIX = "did:web:"


def format_did_web(
    host: str,
    port: Optional[int],
    path: Optional[str] = None,
) -> str:
    did = DID_WEB_PREFIX + host
    if port:
        did += quote(f":{port}")
    if path:
        assert not path.startswith("/")
        did += ":" + path.replace("/", ":")

    return did


def did_web_parse(did: str) -> Tuple[str, Optional[str]]:
    parts = did.split(":")

    if len(parts) < 3:
        raise ValueError("Malformed DID-web")

    prefix, method, location = parts[:3]
    if prefix != "did" or method != "web":
        raise ValueError("Malformed DID-web")

    if len(parts) == 3:
        path = None
    else:
        path = "/".join(parts[3:])

    return unquote(location), path


def did_web_document_url(did: str) -> str:
    (location, path) = did_web_parse(did)
    if path is None:
        path = DID_WEB_DOC_WELLKNOWN_PATH

    return f"{DID_WEB_DOC_URL_SCHEME}://{location}/{path}/{DID_FILENAME}"


def find_assertion_method(did_doc: dict, kid: Optional[str]):
    # TODO: support non-inline verification methods
    assertion_methods = did_doc["assertionMethod"]
    if kid is None:
        if len(assertion_methods) > 1:
            raise ValueError("found more than one assertion method")
        elif len(assertion_methods) == 0:
            raise ValueError("no assertion method found")
        else:
            return assertion_methods[0]

    else:
        matches = [
            m for m in assertion_methods if get_verification_method_kid(m) == kid
        ]
        if len(matches) > 1:
            raise ValueError("found more than one assertion method with given kid")
        elif len(matches) == 0:
            raise ValueError("no assertion method found with given kid")
        return matches[0]


# The "kid" COSE header parameter refers
# to the fragment of the verification method's ID.
# The part before the fragment is the DID itself
# and stored in "issuer".
def get_verification_method_kid(obj: dict) -> str:
    return "#" + obj["id"].split("#")[1]


def get_signer(private_key: Pem, did_doc: dict, kid: Optional[str] = None) -> Signer:
    assertion_method = find_assertion_method(did_doc, kid)
    kid = get_verification_method_kid(assertion_method)
    algorithm = assertion_method["publicKeyJwk"]["alg"]

    return Signer(private_key, did_doc["id"], kid, algorithm)


def create_assertion_method(
    *,
    did: str,
    public_key: Pem,
    alg: Optional[str] = None,
    kid: Optional[str] = None,
):
    if kid is None:
        kid = "#" + get_public_key_fingerprint(public_key)
    if not kid.startswith("#"):
        raise ValueError("kid must start with '#'")

    return {
        "id": f"{did}{kid}",
        "type": "JsonWebKey2020",
        "controller": did,
        "publicKeyJwk": jwk_from_public_key(public_key, alg, kid[1:]),
    }


def create_document(
    *,
    did: str,
    assertion_methods: Optional[list] = None,
    public_key: Optional[Pem] = None,
) -> dict:
    if not did.startswith("did:"):
        raise ValueError("did must start with 'did:'")

    if assertion_methods is None:
        if public_key is None:
            raise ValueError(
                "Either a public key or assertion methods must be provided"
            )
        assertion_methods = [create_assertion_method(did=did, public_key=public_key)]

    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ],
        "id": did,
        "assertionMethod": assertion_methods,
    }


class Resolver:
    def __init__(self, *, verify: bool = True):
        self.verify = verify

    def resolve(self, did: str) -> dict:
        parts = did.split(":", 3)
        if len(parts) < 3:
            raise ValueError("Malformed DID")

        if parts[0] != "did":
            raise ValueError("Malformed DID")
        if parts[1] != "web":
            raise ValueError(f"Unsupported DID method {parts[1]!r}")

        url = did_web_document_url(did)

        LOG.debug(f"Resolving {did!r} at {url!r}")
        r = httpx.get(url, verify=self.verify)
        r.raise_for_status()
        return r.json()
