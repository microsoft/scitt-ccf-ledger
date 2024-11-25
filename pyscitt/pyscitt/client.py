# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import base64
import hashlib
import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from http import HTTPStatus
from typing import Any, Dict, Iterable, Literal, Optional, TypeVar, Union, overload
from urllib.parse import urlencode

import httpx
from loguru import logger as LOG

from . import crypto
from .governance import GovernanceClient
from .receipt import Receipt
from .verify import ServiceParameters

CCF_TX_ID_HEADER = "x-ms-ccf-transaction-id"


class SigningType(Enum):
    """Types of signatures supported by CCF.

    https://microsoft.github.io/CCF/main/governance/hsm_keys.html#signing-governance-requests
    """

    COSE = "COSE"
    HTTP = "HTTP"


class ReceiptType(Enum):
    """Receipt types supported by the ledger."""

    EMBEDDED = "embedded"
    RAW = "raw"


class MemberAuthenticationMethod(ABC):
    cert: str

    @abstractmethod
    def http_sign(self, data: bytes) -> bytes:
        """
        Generates a HTTP signing payload for the specified request with the specified headers.

        https://microsoft.github.io/CCF/main/use_apps/issue_commands.html#signing

        :param data: The intended body for the HTTP request.
        :type data: bytes

        :return: The full payload, with signature, to be sent to CCF.
        :rtype: bytes
        """

    @abstractmethod
    def cose_sign(self, data: bytes, cose_headers: Optional[Dict] = None) -> bytes:
        """Generates a COSE payload for the specified request with the specified headers.

        https://microsoft.github.io/CCF/main/use_apps/issue_commands.html#signing

        :param data: The intended body for the HTTP request.
        :type data: bytes
        :param cose_headers: The headers to include in the COSE payload.
        :type cose_headers: Optional[Dict]

        :return: The full payload, with signature, to be sent to CCF.
        :rtype: bytes
        """


# copied from CCF/tests/infra/clients.py
class HttpSig(httpx.Auth):
    member_auth_client: MemberAuthenticationMethod
    requires_request_body = True

    def __init__(self, member_auth_client: MemberAuthenticationMethod):
        self.member_auth_client = member_auth_client
        self.key_id = crypto.get_cert_fingerprint(member_auth_client.cert)

    def auth_flow(self, request):
        body_digest = base64.b64encode(hashlib.sha256(request.content).digest()).decode(
            "ascii"
        )
        request.headers["digest"] = f"SHA-256={body_digest}"
        string_to_sign = "\n".join(
            [
                f"(request-target): {request.method.lower()} {request.url.raw_path.decode('utf-8')}",
                f"digest: SHA-256={body_digest}",
                f"content-length: {len(request.content)}",
            ]
        ).encode("utf-8")

        signature = self.member_auth_client.http_sign(string_to_sign)
        b64signature = base64.b64encode(signature).decode("ascii")
        request.headers["authorization"] = (
            f'Signature keyId="{self.key_id}",algorithm="hs2019",headers="(request-target) digest content-length",signature="{b64signature}"'
        )
        yield request


@dataclass
class ServiceError(Exception):
    headers: httpx.Headers
    code: str
    message: str

    def __str__(self):
        return f"{self.code}: {self.message}"


SelfClient = TypeVar("SelfClient", bound="BaseClient")


# When running functional tests, we may send identical proposals that,
# if signed within the same second, they may hit the ProposalReplay
# protection error from CCF.
# We use a custom clock that can be manually advanced, same as
# implemented by CCF, to avoid sleeping for 1 second between
# identical proposals.
# Source: https://github.com/microsoft/CCF/blob/d6efe6664045968dc4f191b9ae672e686f05279b/tests/infra/clients.py#L40
class OffSettableSecondsSinceEpoch:
    offset = 0

    def count(self):
        return self.offset + int(datetime.now().timestamp())

    def advance(self, amount=1):
        LOG.info(f"Advancing clock by {amount} seconds")
        self.offset += amount


CLOCK = OffSettableSecondsSinceEpoch()


def cose_protected_headers(request_path: str, method: str):
    """
    Generate the COSE protected headers for CCF governance given a request path and HTTP method.

    :param request_path: The path of the request.
    :type request_path: str
    :param method: The method of the request.
    :type method: str

    :return: The COSE protected headers.
    :rtype: dict
    """

    cose_headers: Dict[str, Any] = {}

    # Set the created_at header to the current time
    cose_headers = {
        "ccf.gov.msg.created_at": CLOCK.count(),
    }

    # Set headers based on the request path and method
    if request_path.endswith("gov/ack/update_state_digest"):
        cose_headers["ccf.gov.msg.type"] = "state_digest"
    elif request_path.endswith("gov/ack"):
        cose_headers["ccf.gov.msg.type"] = "ack"
    elif request_path.endswith("gov/proposals"):
        cose_headers["ccf.gov.msg.type"] = "proposal"
    elif request_path.endswith("/ballots"):
        pid = request_path.split("/")[-2]
        cose_headers["ccf.gov.msg.type"] = "ballot"
        cose_headers["ccf.gov.msg.proposal_id"] = pid
    elif request_path.endswith("/withdraw"):
        pid = request_path.split("/")[-2]
        cose_headers["ccf.gov.msg.type"] = "withdrawal"
        cose_headers["ccf.gov.msg.proposal_id"] = pid
    elif request_path.endswith("gov/recovery_share"):
        if method == "GET":
            cose_headers["ccf.gov.msg.type"] = "encrypted_recovery_share"
        if method == "POST":
            cose_headers["ccf.gov.msg.type"] = "recovery_share"

    return cose_headers


def get_content_data(body: Optional[Union[dict, str, bytes]]) -> bytes:
    """
    Get the request body from the body parameter

    :param body: The body of the request. Can be a string, bytes, or dict.
    :type body: Optional[Union[dict, str, bytes]]

    :return: The request body
    :rtype: bytes
    """

    if isinstance(body, str):
        request_body = body.encode()
    elif isinstance(body, dict):
        request_body = json.dumps(body).encode()
    elif isinstance(body, bytes):
        request_body = body
    else:
        raise ValueError(f"Invalid body type: {type(body)}")

    return request_body


class BaseClient:
    """
    Wrapper around an HTTP client, with facilities to interact with a CCF-based
    service.

    Provides support for authentication, request signing, logging, configurable
    retry conditions, etc...
    """

    url: str
    auth_token: Optional[str]
    member_auth: Optional[MemberAuthenticationMethod]
    member_signing_type: SigningType
    wait_time: Optional[float]
    development: bool
    cacert: Optional[str]

    session: httpx.Client
    member_http_sig: Optional[HttpSig]

    def __init__(
        self,
        url: str,
        *,
        auth_token: Optional[str] = None,
        member_auth: Optional[MemberAuthenticationMethod] = None,
        member_signing_type: SigningType = SigningType.COSE,
        wait_time: Optional[float] = None,
        development: bool = False,
        cacert: Optional[str] = None,
    ):
        """
        Create a new BaseClient instance.

        auth_token:
            A bearer token for all requests made by this instance.

        member_auth:
            MemberAuthenticationMethod include A pair of certificate and private key in PEM format or AKV login identity, used to sign requests.
            Each request that needs signing must also be given the `sign_request=True` parameter.

        wait_time:
            The time to wait between retries. If None, the default wait time is used.

        member_signing_type:
            The type of signing to use for member authentication. Currently, only COSE and HTTP signing are supported.

        development:
            If true, the TLS certificate of the server will not be verified.

        cacert:
            If set and development is False, will be used in TLS verification instead of the default bundle.
        """

        # Even though these are passed to the httpx.Client and not used
        # directly, we save them so we can create a new Client with modified
        # settings in the `replace` method.
        self.url = url
        self.auth_token = auth_token
        self.member_auth = member_auth
        self.member_signing_type = member_signing_type
        self.wait_time = wait_time
        self.development = development
        self.cacert = cacert

        headers = {}
        if auth_token:
            headers["Authorization"] = "Bearer " + auth_token

        # We only create a custom HTTPX authentication instance for HTTP signing
        # because COSE signing cannot be handled that way and requires re-writing
        # the response payload.
        if member_auth and member_signing_type == SigningType.HTTP:
            self.member_http_sig = HttpSig(member_auth)
        else:
            self.member_http_sig = None

        tls_verification: Union[str, bool] = (
            cacert if cacert is not None else not development
        )

        self.session = httpx.Client(
            base_url=url, headers=headers, verify=tls_verification
        )

    def replace(self: SelfClient, **kwargs) -> SelfClient:
        """
        Create a new instance with certain parameters modified. Any parameters
        that weren't specified will be inherited from the current instance.

        The accepted keyword arguments are the same as those of the constructor.
        """
        values: dict = {
            "url": self.url,
            "auth_token": self.auth_token,
            "member_auth": self.member_auth,
            "member_signing_type": self.member_signing_type,
            "wait_time": self.wait_time,
            "development": self.development,
            "cacert": self.cacert,
        }
        values.update(kwargs)
        return self.__class__(**values)

    def request(
        self,
        method,
        url,
        *,
        retry_on=[],
        sign_request=False,
        wait_for_confirmation=False,
        **kwargs,
    ) -> httpx.Response:
        """
        Issue a request to the server.

        retry_on: a list of predicates on the response.
            Each predicate can be one of an HTTP status code, a pair of a status code and a error
            code or a callable that accepts a response object and returns True if the request
            should be retried. If any predicate matches, the request is retried after a short delay.

        sign_request:
            Sign the request with the member private key. A key and certificate must have been
            provided to the constructor.

        wait_for_confirmation:
            Wait for the transaction created by this request to be globally committed. If True, the
            client will wait for confirmation and raise an error if the transaction was rolled-back.
            Otherwise, any write to the key-value store caused by this request could be silently
            rolled-back.

        Other keyword-arguments are passed to httpx.
        """
        if sign_request:
            # Check that the request is not already signed
            if "auth" in kwargs:
                raise ValueError("Cannot use `auth` with `sign_request`")

            # Sign with COSE
            if self.member_signing_type == SigningType.COSE and self.member_auth:
                # Advance the clock to avoid ProposalReplay protection errors
                if self.development:
                    CLOCK.advance()

                # Get the COSE headers
                cose_headers = cose_protected_headers(url, method)

                def _get_data():
                    """Get the data to sign from the request keywords"""

                    # The data is either in `content` or `json` kwarg.
                    # We assume that other keywords used to pass the
                    # content for HTTPX requests are not used
                    # (e.g., such as the deprecated `data`).
                    content = kwargs.get("content")
                    if content:
                        content = get_content_data(content)

                    json_data = kwargs.get("json")
                    if json_data:
                        json_data = get_content_data(json_data)

                    # If both are specified, raise an error
                    if content and json_data:
                        raise ValueError("Cannot use both `content` and `json`")

                    # Return the data to sign
                    # If both are not specified, return an empty bytes string
                    # (e.g., for GET requests)
                    return content or json_data or b""

                # Sign the data
                payload = self.member_auth.cose_sign(_get_data(), cose_headers)

                # Set the request data and the content-type header
                kwargs["content"] = payload
                kwargs.setdefault("headers", {})["content-type"] = "application/cose"

            # Sign with HTTP signing
            elif self.member_signing_type == SigningType.HTTP and self.member_http_sig:
                kwargs["auth"] = self.member_http_sig

                if method == "GET":
                    # Content-length is necessary for signing, even on GET requests.
                    kwargs.setdefault("headers", {}).setdefault("Content-Length", "0")

            else:
                raise ValueError(f"Cannot sign request with {self.member_signing_type}")

        default_wait_time = 2
        timeout = 30
        deadline = time.monotonic() + timeout
        attempt = 1
        while True:
            response = self.session.request(method, url, **kwargs)

            log_parts = [method, url]
            if attempt > 1:
                log_parts.append(f"(attempt #{attempt})")
            log_parts.append(response.status_code)
            if not response.is_success:
                log_parts.append(response.json().get("error", {}).get("code"))
            LOG.debug(" ".join(str(p) for p in log_parts))

            for code in retry_on:
                if isinstance(code, tuple):
                    if (
                        response.status_code == code[0]
                        and response.json().get("error", {}).get("code") == code[1]
                    ):
                        break
                elif callable(code):
                    if code(response):
                        break
                else:
                    if response.status_code == code:
                        break
            else:
                break

            if self.wait_time is not None:
                wait = self.wait_time
            else:
                wait = int(response.headers.get("retry-after", default_wait_time))
            if time.monotonic() + wait > deadline:
                raise ValueError("Too many retries")

            time.sleep(wait)
            attempt += 1

        if not response.is_success:
            error = response.json()["error"]
            LOG.error(f"Request failed: {error}")
            raise ServiceError(response.headers, error["code"], error["message"])

        if wait_for_confirmation:
            self.wait_for_confirmation(response.headers[CCF_TX_ID_HEADER])

        return response

    def wait_for_confirmation(self, tx: str):
        """
        Wait until a transaction has either been globally committed or was rolled back.

        In the latter case, an exception is raised.
        """
        response = self.get(
            "/node/tx",
            params={"transaction_id": tx},
            retry_on=[lambda r: r.is_success and r.json()["status"] == "Pending"],
        )

        status = response.json()["status"]
        if status != "Committed":
            raise RuntimeError(
                f"Transaction {tx} was not committed. Status is {status}"
            )

    def get(self, *args, **kwargs) -> httpx.Response:
        return self.request("GET", *args, **kwargs)

    def post(self, *args, **kwargs) -> httpx.Response:
        return self.request("POST", *args, **kwargs)

    def get_historical(self, *args, retry_on=[], **kwargs):
        """
        Issue a request, retrying on codes commonly used by CCF applications to indicate that a
        historical query to the KV is in progress and needs to be retried.
        """
        return self.get(
            *args,
            **kwargs,
            retry_on=[
                (HTTPStatus.SERVICE_UNAVAILABLE, "TransactionNotCached"),
            ]
            + retry_on,
        )


@dataclass
class PendingSubmission:
    """
    The pending result of submitting a claim to the service.
    """

    operation_tx: str


@dataclass
class Submission(PendingSubmission):
    """
    The result of submitting a statement to the service.
    """

    tx: str
    response_bytes: bytes
    is_receipt_embedded: bool

    @property
    def seqno(self) -> int:
        """Extract the sequence number from the transaction ID."""
        view, seqno = self.tx.split(".")
        return int(seqno)

    @property
    def receipt(self) -> Receipt:
        """Parse the receipt bytes and return a Receipt object."""
        if self.is_receipt_embedded:
            embedded_receipt = crypto.get_last_embedded_receipt_from_cose(
                self.response_bytes
            )
            if embedded_receipt:
                return Receipt.decode(embedded_receipt)
            raise ValueError("No embedded receipt found in COSE message header")
        return Receipt.decode(self.response_bytes)


class Client(BaseClient):
    """
    Specialization of the BaseClient, aimed at interacting with a SCITT CCF ledger instance.
    """

    def get_parameters(self) -> ServiceParameters:
        return ServiceParameters.from_dict(self.get("/parameters").json())

    def get_constitution(self) -> str:
        # The endpoint returns the value as a JSON-encoded string, ie. wrapped
        # in double quotes and with all special characters escaped.
        return self.get("/gov/kv/constitution").json()

    def get_version(self) -> dict:
        return self.get("/version").json()

    def get_did_document(self, did: str) -> dict:
        # Note: This endpoint only returns data for did:web DIDs.
        return self.get(f"/did/{did}").json()["did_document"]

    def submit_claim(
        self,
        claim: bytes,
    ) -> PendingSubmission:
        headers = {"Content-Type": "application/cose"}
        response = self.post(
            "/entries",
            headers=headers,
            content=claim,
        ).json()
        operation_id = response["operationId"]
        return PendingSubmission(operation_id)

    def submit_claim_and_confirm(
        self,
        claim: bytes,
        *,
        receipt_type: ReceiptType = ReceiptType.RAW,
    ) -> Submission:
        headers = {"Content-Type": "application/cose"}
        response = self.post(
            "/entries",
            headers=headers,
            content=claim,
        ).json()
        operation_id = response["operationId"]
        tx = self.wait_for_operation(operation_id)
        if receipt_type == ReceiptType.EMBEDDED:
            receipt = self.get_claim(tx, embed_receipt=True)
            return Submission(operation_id, tx, receipt, True)

        receipt = self.get_receipt(tx)
        return Submission(operation_id, tx, receipt, False)

    def submit_and_confirm(
        self,
        claim: bytes,
    ) -> Submission:
        headers = {"Content-Type": "application/cose"}
        response = self.post(
            "/entries",
            headers=headers,
            content=claim,
        ).json()
        operation_id = response["operationId"]
        tx = self.wait_for_operation(operation_id)
        statement = self.get_transparent_statement(tx)
        return Submission(operation_id, tx, statement, False)

    def register_signed_statement(
        self,
        signed_statement: bytes,
    ) -> Submission:
        headers = {"Content-Type": "application/cose"}
        response = self.post(
            "/entries",
            headers=headers,
            content=signed_statement,
        ).json()
        operation_id = response["operationId"]
        tx = self.wait_for_operation(operation_id)
        statement = self.get_transparent_statement(tx)
        return Submission(operation_id, tx, statement, False)

    def wait_for_operation(self, operation: str) -> str:
        response = self.get(
            f"/operations/{operation}",
            retry_on=[lambda r: r.is_success and r.json()["status"] == "running"],
        )
        payload = response.json()

        if payload["status"] == "succeeded":
            return payload["entryId"]
        elif payload["status"] == "failed":
            error = payload["error"]
            raise ServiceError(response.headers, error["code"], error["message"])
        else:
            raise ValueError("Invalid status {}".format(payload["status"]))

    def get_operations(self):
        return self.get("/operations").json()["operations"]

    def get_claim(self, tx: str, *, embed_receipt=False) -> bytes:
        response = self.get_historical(
            f"/entries/{tx}", params={"embedReceipt": embed_receipt}
        )
        return response.content

    def get_receipt(self, tx: str, *, operation: bool = False) -> bytes:
        """
        Get a receipt from the ledger.

        If `operation` is true, the tx is treated as an operation ID and is
        first waited on in order to obtain the actual entry ID.
        """
        if operation:
            tx = self.wait_for_operation(tx)

        response = self.get_historical(f"/entries/{tx}/receipt")
        return response.content

    def get_transparent_statement(self, tx: str, *, operation: bool = False) -> bytes:
        """
        Get a transparent statement from the ledger.

        If `operation` is true, the tx is treated as an operation ID and is
        first waited on in order to obtain the actual entry ID.
        """
        if operation:
            tx = self.wait_for_operation(tx)

        response = self.get_historical(f"/entries/{tx}/statement")
        return response.content

    def enumerate_claims(
        self, *, start: Optional[int] = None, end: Optional[int] = None
    ) -> Iterable[str]:
        """
        Enumerate all claims on the ledger, with an optional start and end range.

        Yields a sequence of transaction numbers. The contents and/or receipt for a given claim can
        be fetched using the `get_claim` and `get_receipt` methods.
        """
        params = {}
        if start is not None:
            params["from"] = start
        if end is not None:
            params["to"] = end

        link = f"/entries/txIds?{urlencode(params)}"

        while link:
            response = self.get(
                link,
                params=params,
                retry_on=[
                    (HTTPStatus.SERVICE_UNAVAILABLE, "IndexingInProgressRetryLater")
                ],
            )
            body = response.json()
            for tx in body["transactionIds"]:
                yield tx

            link = body.get("nextLink")

    def wait_for_network_open(self):
        self.get(
            "/node/network",
            retry_on=[lambda r: r.is_success and r.json()["service_status"] != "Open"],
        )

    def get_service_certificate(self) -> crypto.Pem:
        return self.get("/node/network").json()["service_certificate"]

    def get_previous_service_identity(self) -> crypto.Pem:
        return self.get("/node/service/previous_identity").json()[
            "previous_service_identity"
        ]

    @property
    def governance(self):
        return GovernanceClient(self)
