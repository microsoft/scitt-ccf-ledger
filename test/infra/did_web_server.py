# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
import os.path
import ssl
import tempfile
import threading
from contextlib import AbstractContextManager
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from typing import Optional
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


class DIDWebServer(AbstractContextManager):
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

        # Create a Handler class which specifically serves the directory, data_dir,
        # to avoid needing to change directory, as the default is to serve cwd.
        class Handler(SimpleHTTPRequestHandler):
            def __init__(handler_self, *args, **kwargs):
                super().__init__(directory=self.data_dir, *args, **kwargs)

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
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join()
        LOG.info("DIDWebServer stopped.")

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop()

    def create_identity(
        self, path: Optional[str] = None, *, alg: Optional[str] = None, **kwargs
    ) -> crypto.Signer:
        """
        Create a new identity on the server.

        If no path is specified, a randomly generated UUID is used instead,
        providing a new unique identity.

        The kwargs are used to configure the key generation.
        """
        if path is None:
            path = str(uuid4())

        kwargs.setdefault("kty", "ec")
        private_key, public_key = crypto.generate_keypair(**kwargs)

        identifier = format_did_web(host=self.host, port=self.port, path=path)

        did_doc = crypto.create_did_document(
            identifier,
            pub_key_pem=public_key,
            alg=alg,
        )

        out_dir = self.data_dir / path
        out_dir.mkdir(parents=True, exist_ok=True)

        with open(out_dir / "did.json", "w") as f:
            json.dump(did_doc, f)

        return did.get_signer(private_key, did_doc)
