# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
import os.path
import ssl
import tempfile
import threading
from contextlib import AbstractContextManager, contextmanager
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from typing import Generator, Optional
from uuid import uuid4

from loguru import logger as LOG

from pyscitt import crypto, did
from pyscitt.did import format_did_web


def _create_tls_context(cert: str, key: str):
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

    # Unfortunately load_cert_chain insists on reading from the filesystem, so
    # we need to write down the cert and key temporarily.
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "cert.pem"), "w") as f:
            f.write(cert)
        with open(os.path.join(d, "key.pem"), "w") as f:
            f.write(key)

        context.load_cert_chain(os.path.join(d, "cert.pem"), os.path.join(d, "key.pem"))
    return context


class Metrics:
    request_count: int

    def __init__(self):
        self.request_count = 0


class DIDWebServer(AbstractContextManager):
    host: str
    port: Optional[int]
    data_dir: Path
    tls_cert_pem: str
    base_url: str

    httpd: HTTPServer
    allow_requests: threading.Event
    metrics: Optional[Metrics]
    metrics_lock: threading.Lock

    def __init__(
        self,
        data_dir: Path,
        host: str = "localhost",
        listen: str = "127.0.0.1",
        use_default_port: bool = False,
    ):
        """
        Sets up a HTTP server which can be started and stopped. Once started, the server
        runs as a daemon thread until the server is stopped, or the thread responsible for
        starting it ends, at which point the server's thread is automatically killed.

        If use_default_port is True, the server will listen on port 443, and the
        issued DIDs will not contain a port component. Otherwise, a random port
        is assigned by the operating system.

        data_dir: Represents the path to the directory which this server will serve.
        """
        self.host = host
        self.data_dir = data_dir
        self.allow_requests = threading.Event()
        self.allow_requests.set()

        # Create a Handler class which specifically serves the directory, data_dir,
        # to avoid needing to change directory, as the default is to serve cwd.
        class Handler(SimpleHTTPRequestHandler):
            def __init__(handler_self, *args, **kwargs):
                super().__init__(directory=self.data_dir, *args, **kwargs)

            def do_GET(handler_self):
                self.allow_requests.wait()
                super().do_GET()

                with self.metrics_lock:
                    if self.metrics is not None:
                        self.metrics.request_count += 1

        if use_default_port:
            self.httpd = HTTPServer((listen, 443), Handler)
            self.port = None
            self.base_url = f"https://{self.host}"
        else:
            # This will let the OS choose a random suitable port.
            self.httpd = HTTPServer((listen, 0), Handler)
            self.port = self.httpd.server_address[1]
            self.base_url = f"https://{self.host}:{self.port}"

        tls_key_pem, _ = crypto.generate_rsa_keypair(2048)
        self.tls_cert_pem = crypto.generate_cert(tls_key_pem, cn=host)

        context = _create_tls_context(self.tls_cert_pem, tls_key_pem)
        self.httpd.socket = context.wrap_socket(self.httpd.socket, server_side=True)

        self.metrics = None
        self.metrics_lock = threading.Lock()

    @property
    def cert_bundle(self) -> str:
        return self.tls_cert_pem

    def start(self):
        self.thread = threading.Thread(None, self.httpd.serve_forever, daemon=True)
        self.thread.start()
        LOG.info(f"DIDWebServer {self.base_url} started, serving {self.data_dir}.")

    def __enter__(self):
        self.start()
        return self

    def stop(self):
        self.allow_requests.set()
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join()
        LOG.info("DIDWebServer stopped.")

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop()

    @contextmanager
    def suspend(self):
        """
        Context manager which suspends all request processing.

        While the context manager is active, the server keeps accepting new
        connections but will block on requests and not send any responses back.

        The server is unblocked and all held up requests are completed when the
        context manager exits.
        """
        self.allow_requests.clear()
        try:
            yield
        finally:
            self.allow_requests.set()

    @contextmanager
    def monitor(self) -> Generator[Metrics, None, None]:
        """
        A context manager which tracks requests made to the server.

        It yields a `Metrics` object, which can be inspected after the context
        manager's scope.
        """
        with self.metrics_lock:
            if self.metrics is not None:
                raise RuntimeError("DIDWebServer is already being monitored")

            metrics = Metrics()
            self.metrics = metrics

        try:
            yield metrics
        finally:
            with self.metrics_lock:
                self.metrics = None

    def generate_identifier(self) -> str:
        """
        Generate a random did:web identifier hosted on this server.
        """
        path = str(uuid4())
        return format_did_web(host=self.host, port=self.port, path=path)

    def create_identity(
        self,
        identifier: Optional[str] = None,
        *,
        alg: Optional[str] = None,
        kid: Optional[str] = None,
        **kwargs,
    ) -> crypto.Signer:
        """
        Create a new identity on the server.

        If no `identifier` is passed, a randomly generated UUID is used
        instead, providing a new unique identity.

        The kwargs are used to configure the key generation.
        """
        if identifier is None:
            identifier = self.generate_identifier()

        kwargs.setdefault("kty", "ec")
        private_key, public_key = crypto.generate_keypair(**kwargs)

        assertion_method = did.create_assertion_method(
            did=identifier,
            public_key=public_key,
            alg=alg,
            kid=kid,
        )
        document = did.create_document(
            did=identifier, assertion_methods=[assertion_method]
        )

        self.write_did_document(document)
        return did.get_signer(private_key, document, kid=kid)

    def write_did_document(self, document, *, identifier=None):
        """
        Store a DID document on the server.

        The path of the JSON file is determined from the identifier found in the
        document, or the `identifier` argument if supplied.
        """

        if identifier is None:
            identifier = document["id"]

        _, path = did.did_web_parse(identifier)
        if did.format_did_web(self.host, self.port, path) != identifier:
            raise ValueError(f"Invalid DID {identifier}")

        out_dir = self.data_dir / path
        out_dir.mkdir(parents=True, exist_ok=True)

        with open(out_dir / "did.json", "w") as f:
            json.dump(document, f)
