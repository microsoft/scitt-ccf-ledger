# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import base64
import hashlib
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from http import HTTPStatus
from typing import Iterable, Literal, Optional, TypeVar, Union, overload
from urllib.parse import urlencode

import httpx
from loguru import logger as LOG

from . import crypto
from .governance import GovernanceClient
from .prefix_tree import PrefixTreeClient
from .receipt import Receipt
from .verify import ServiceParameters

CCF_TX_ID_HEADER = "x-ms-ccf-transaction-id"


class MemberAuthenticationMethod(ABC):
    cert: str

    @abstractmethod
    def sign(self, data: bytes) -> bytes:
        pass


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

        signature = self.member_auth_client.sign(string_to_sign)
        b64signature = base64.b64encode(signature).decode("ascii")
        request.headers[
            "authorization"
        ] = f'Signature keyId="{self.key_id}",algorithm="hs2019",headers="(request-target) digest content-length",signature="{b64signature}"'
        yield request


@dataclass
class ServiceError(Exception):
    headers: httpx.Headers
    code: str
    message: str

    def __str__(self):
        return f"{self.code}: {self.message}"


SelfClient = TypeVar("SelfClient", bound="BaseClient")


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
    wait_time: Optional[float]
    tcp_nodelay_patch: bool
    development: bool

    session: httpx.Client
    member_http_sig: Optional[HttpSig]

    def __init__(
        self,
        url: str,
        *,
        auth_token: Optional[str] = None,
        member_auth: Optional[MemberAuthenticationMethod] = None,
        wait_time: Optional[float] = None,
        tcp_nodelay_patch: bool = False,
        development: bool = False,
    ):
        """
        Create a new BaseClient instance.

        auth_token:
            A bearer token for all requests made by this instance.

        member_auth:
            MemberAuthenticationMethod include A pair of certificate and private key in PEM format or AKV login idenity, used to sign requests.
            Each request that needs signing must also be given the `sign_request=True` parameter.

        wait_time:
            The time to wait between retries. If None, the default wait time is used.

        development:
            If true, the TLS certificate of the server will not be verified.
        """

        # Even though these are passed to the httpx.Client and not used
        # directly, we save them so we can create a new Client with modified
        # settings in the `replace` method.
        self.url = url
        self.auth_token = auth_token
        self.member_auth = member_auth
        self.wait_time = wait_time
        self.tcp_nodelay_patch = tcp_nodelay_patch
        self.development = development

        headers = {}
        if auth_token:
            headers["Authorization"] = "Bearer " + auth_token

        if member_auth:
            self.member_http_sig = HttpSig(member_auth)
        else:
            self.member_http_sig = None

        if tcp_nodelay_patch:
            # Work-around until https://github.com/encode/httpcore/pull/651 is merged.
            # This is necessary to set TCP_NODELAY on the sockets used by httpx.
            # Without it we get issues with Nagle + delayed ACK,
            # leading to 40ms pauses when sending requests.
            # Note that many libraries do this by default, but httpx does not.
            import socket

            import httpcore

            class NoDelayBackend(httpcore.backends.sync.SyncBackend):
                def connect_tcp(
                    self, host: str, port: int, timeout=None, local_address=None
                ):
                    s = super().connect_tcp(host, port, timeout, local_address)
                    s._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)  # type: ignore
                    return s

            transport = httpx.HTTPTransport(verify=not development)
            transport._pool = httpcore.ConnectionPool(
                network_backend=NoDelayBackend(),
                ssl_context=transport._pool._ssl_context,
            )
        else:
            transport = None

        self.session = httpx.Client(
            base_url=url, headers=headers, verify=not development, transport=transport
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
            "wait_time": self.wait_time,
            "tcp_nodelay_patch": self.tcp_nodelay_patch,
            "development": self.development,
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
            if not self.member_http_sig:
                raise ValueError("Cannot sign request: no member key configured")
            elif "auth" in kwargs:
                raise ValueError("Cannot use `auth` with `sign_request`")
            else:
                kwargs["auth"] = self.member_http_sig

            if method == "GET":
                # Content-length is necessary for signing, even on GET requests.
                kwargs.setdefault("headers", {}).setdefault("Content-Length", "0")

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
    The result of submitting a claim to the service.
    """

    operation_tx: str


@dataclass
class Submission(PendingSubmission):
    tx: str
    raw_receipt: bytes

    @property
    def seqno(self) -> int:
        view, seqno = self.tx.split(".")
        return int(seqno)

    @property
    def receipt(self) -> Receipt:
        return Receipt.decode(self.raw_receipt)


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

    @overload
    def submit_claim(
        self, claim: bytes, *, skip_confirmation: Literal[False] = False
    ) -> Submission:
        ...

    @overload
    def submit_claim(
        self, claim: bytes, *, skip_confirmation: Literal[True]
    ) -> PendingSubmission:
        ...

    def submit_claim(
        self, claim: bytes, *, skip_confirmation=False
    ) -> Union[Submission, PendingSubmission]:
        headers = {"Content-Type": "application/cose"}

        response = self.post(
            "/entries",
            headers=headers,
            content=claim,
        ).json()

        operation_id = response["operationId"]
        if skip_confirmation:
            return PendingSubmission(operation_id)
        else:
            tx = self.wait_for_operation(operation_id)
            receipt = self.get_receipt(tx, decode=False)
            return Submission(operation_id, tx, receipt)

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

    @overload
    def get_receipt(
        self,
        tx: str,
        *,
        operation: bool = False,
        decode: Literal[True] = True,
    ) -> Receipt:
        ...

    @overload
    def get_receipt(
        self, tx: str, *, operation: bool = False, decode: Literal[False]
    ) -> bytes:
        ...

    def get_receipt(
        self, tx: str, *, operation: bool = False, decode: bool = True
    ) -> Union[bytes, Receipt]:
        """
        Get a receipt from the ledger.

        If `operation` is true, the tx is treated as an operation ID and is
        first waited on in order to obtain the actual entry ID.
        """
        if operation:
            tx = self.wait_for_operation(tx)

        response = self.get_historical(f"/entries/{tx}/receipt")
        if decode:
            return Receipt.decode(response.content)
        else:
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

    @property
    def prefix_tree(self):
        return PrefixTreeClient(self)
