# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# type: ignore

import random
import subprocess
import sys
import tempfile
import traceback
from pathlib import Path

from locust import FastHttpUser, events, task

from infra.fixtures import (
    DIDWebServer,
    configure_did_web_trust_anchors,
    configure_oidc_issuer_and_create_token,
    create_issuer,
    create_service_trust_store,
    create_tls_key_pair,
)
from pyscitt import crypto
from pyscitt.cli.retrieve_signed_claims import retrieve_signed_claimsets
from pyscitt.cli.submit_signed_claims import submit_signed_claimset

# NOTE: The following currently does not support multiple locust workers.
# This is because trust bootstrapping for local DID resolution is not done on the master.

USER_CLASS = FastHttpUser

ISSUERS = []
TMP_DIR_OBJ = tempfile.TemporaryDirectory(prefix="scitt-test")
TMP_DIR = Path(TMP_DIR_OBJ.name)
print(f"Temp dir: {TMP_DIR}")
DID_WEB_SERVE_PROCESS: subprocess.Popen
SERVICE_TRUST_STORE = {}
AUTH_TOKEN = ""


@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    try:
        if environment.host is None:
            raise RuntimeError("-H must be specified")
        service_url = environment.host

        global SERVICE_TRUST_STORE
        SERVICE_TRUST_STORE = create_service_trust_store(TMP_DIR, service_url)

        # Create DIDs
        for i in range(1, 10):
            ISSUERS.append(create_issuer(base_dir=TMP_DIR, idx=i))

        # Serve DID documents on a local web server
        tls_cert_path = TMP_DIR / "tls_cert.pem"
        tls_key_path = TMP_DIR / "tls_key.pem"
        create_tls_key_pair(key_path=tls_key_path, cert_path=tls_cert_path)
        global DID_WEB_SERVER
        DID_WEB_SERVER = DIDWebServer(
            host="0.0.0.0",
            port=8128,
            data_dir=TMP_DIR,
            tls_key_pem=tls_key_path,
            tls_cert_pem=tls_cert_path,
        )
        DID_WEB_SERVER.start()

        # Trust TLS certificate of local web server for DID resolution of did:web
        configure_did_web_trust_anchors(
            ca_cert_path=tls_cert_path, service_url=service_url
        )

        # Create auth token for write endpoint
        global AUTH_TOKEN
        AUTH_TOKEN = configure_oidc_issuer_and_create_token(service_url)
    except:
        traceback.print_exc()
        sys.exit(1)


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    DID_WEB_SERVER.stop()


class Submitter(USER_CLASS):
    def on_start(self):
        issuer = random.choice(ISSUERS)
        size = random.randint(1, 1024 * 1024)
        claims = {"foo": "b" * size}
        content_type = "application/x-foo"
        self.signed_claimset = crypto.sign_claimset(
            issuer.private_key_pem, issuer.did_doc, claims, content_type
        )

    @task
    def submit_signed_claimset(self):
        assert self.host
        submit_signed_claimset(
            self.signed_claimset,
            self.host,
            auth_token=AUTH_TOKEN,
            return_receipt=True,
            development=True,
            session=self.client,
            is_locust_session=True,
        )


class Crawler(USER_CLASS):
    fixed_count = 10

    @task
    def get_entries(self):
        assert self.host
        for _ in retrieve_signed_claimsets(
            from_seqno=None,
            to_seqno=None,
            ccf_url=self.host,
            development=True,
            session=self.client,
            is_locust_session=True,
        ):
            pass


class Operator(USER_CLASS):
    fixed_count = 1

    @task
    def get_endpoint_statistics(self):
        self.client.get("/app/api/metrics")

    @task
    def get_node_statistics(self):
        r = self.client.get("/node/memory")
        print(r.json())
        r = self.client.get("/node/commit")
        print(r.json())
        self.client.get("/node/metrics")
