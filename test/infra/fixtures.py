# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import os
from pathlib import Path
from typing import Optional

from pyscitt import governance
from pyscitt.client import Client

from .did_web_server import DIDWebServer
from .x5chain_certificate_authority import X5ChainCertificateAuthority


def _get_member_auth():
    workspace_dir = Path("workspace") / "sandbox_common"
    cert = workspace_dir.joinpath("member0_cert.pem").read_text()
    key = workspace_dir.joinpath("member0_privk.pem").read_text()
    return cert, key


class SCITTFixture:
    service_url: str
    service_parameters: dict
    client: Client
    trust_store: dict
    did_web_server: DIDWebServer
    x5c_ca: Optional[X5ChainCertificateAuthority]

    def __init__(
        self,
        path: Path,
        use_default_did_port: bool = False,
        x5c_ca: X5ChainCertificateAuthority = None,
    ):
        self.service_url = os.environ.get("CCF_URL", "https://127.0.0.1:8000")
        self.client = Client(
            self.service_url, development=True, member_auth=_get_member_auth()
        )

        self.service_parameters = self.client.get_parameters()
        self.trust_store = {
            self.service_parameters["serviceId"]: self.service_parameters,
        }
        self.did_web_server = DIDWebServer(
            use_default_port=use_default_did_port, data_dir=path
        )
        self.x5c_ca = x5c_ca

    def __enter__(self):
        self.did_web_server.__enter__()

        # Reset the configuration to a known good default. This cleans up any left
        # over configuration a previous test may have left.
        self.configure_service({})

        cert_bundle = self.did_web_server.cert_bundle
        self.client.governance.propose(
            governance.set_ca_bundle_proposal("did_web_tls_roots", cert_bundle),
            must_pass=True,
        )
        if self.x5c_ca:
            self.client.governance.propose(
                governance.set_ca_bundle_proposal(
                    "x509_roots", self.x5c_ca.cert_bundle
                ),
                must_pass=True,
            )

        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.did_web_server.__exit__(exc_type, exc_value, traceback)

    def configure_service(self, configuration: dict):
        # Since most tests don't care about authentication and won't set the
        # authentication field. In those cases, default to an open service.
        configuration.setdefault("authentication", {"allow_unauthenticated": True})
        proposal = governance.set_scitt_configuration_proposal(configuration)
        self.client.governance.propose(proposal, must_pass=True)
