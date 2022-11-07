# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from typing import Optional
from urllib.parse import quote, unquote

from .crypto import Pem, Signer

DID_FILENAME = "did.json"
DID_WEB_DOC_URL_SCHEME = "https"
DID_WEB_DOC_WELLKNOWN_PATH = ".well-known"
DID_WEB_PREFIX = "did:web:"


def format_did_web(
    host: str,
    port: Optional[int],
    path: Optional[str],
) -> str:
    did = DID_WEB_PREFIX + host
    if port:
        did += quote(f":{port}")
    if path:
        assert not path.startswith("/")
        did += ":" + path.replace("/", ":")

    return did


def did_web_document_url(did: str) -> str:
    parts = did.split(":")

    if len(parts) < 3:
        raise ValueError("Malformed DID-web")

    prefix, method, location = parts[:3]
    if prefix != "did" or method != "web":
        raise ValueError("Malformed DID-web")

    if len(parts) == 3:
        path = DID_WEB_DOC_WELLKNOWN_PATH
    else:
        path = "/".join(parts[3:])

    return f"{DID_WEB_DOC_URL_SCHEME}://{unquote(location)}/{path}/{DID_FILENAME}"


def find_assertion_method(did_doc: dict, kid: Optional[str]):
    assertion_methods = did_doc["assertionMethod"]
    if kid is None:
        assertion_method = assertion_methods[0]
    else:
        matches = [
            m for m in assertion_methods if get_verification_method_kid(m) == kid
        ]
        if len(matches) > 1:
            raise ValueError("found more than one assertion method with given kid")
        if len(matches) == 0:
            raise ValueError("no assertion method found with given kid")
        assertion_method = matches[0]
    return assertion_method


# The "kid" COSE header parameter refers
# to the fragment of the verification method's ID.
# The part before the fragment is the DID itself
# and stored in "issuer".
def get_verification_method_kid(obj: dict) -> str:
    return obj["id"].split("#")[1]


def get_signer(private_key: Pem, did_doc: dict, kid: Optional[str] = None) -> Signer:
    assertion_method = find_assertion_method(did_doc, kid)
    kid = get_verification_method_kid(assertion_method)
    algorithm = assertion_method["publicKeyJwk"]["alg"]

    return Signer(private_key, did_doc["id"], kid, algorithm)
