# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import os
from http import HTTPStatus
from pathlib import Path

import pytest

from pyscitt import governance
from pyscitt.client import Client

from .did_web_server import DIDWebServer

# This file defines a collection of pytest fixtures used to manage and
# interact with the SCITT ledger.


@pytest.fixture(scope="session")
def service_url():
    return os.environ.get("CCF_URL", "https://127.0.0.1:8000")


@pytest.fixture(scope="session")
def member_auth_path():
    workspace_dir = Path("workspace") / "sandbox_common"
    return (
        workspace_dir.joinpath("member0_cert.pem"),
        workspace_dir.joinpath("member0_privk.pem"),
    )


@pytest.fixture(scope="session")
def member_auth(member_auth_path):
    return (member_auth_path[0].read_text(), member_auth_path[1].read_text())


@pytest.fixture(scope="class")
def base_client(service_url, member_auth):
    """
    Create a Client instance to connect to the test SCITT service.

    Most tests will want to use the `client` fixture instead, which resets the
    service to a known good state.
    """
    return Client(service_url, development=True, member_auth=member_auth)


@pytest.fixture(scope="class")
def configure_service(base_client: Client):
    """
    Change the service configuration.

    The fixture returns a function which may be called with the new
    configuration dictionary. It applies some good defaults for configuration
    entries that have not been specified.
    """

    def f(configuration):
        if "authentication" not in configuration:
            configuration = {
                "authentication": {"allow_unauthenticated": True},
                **configuration,
            }

        proposal = governance.set_scitt_configuration_proposal(configuration)
        base_client.governance.propose(proposal, must_pass=True)

    return f


@pytest.fixture(scope="class")
def client(base_client, configure_service):
    """
    Resets the service to a known good state and return a Client instance.

    This is the fixture most test will want to use to interact with the
    service. It is re-executed for each test class.
    """
    configure_service({})
    return base_client


@pytest.fixture(scope="class")
def did_web(client, tmp_path_factory):
    """
    Create a DIDWebServer and add its TLS root to the SCITT service.

    The server is shared across all tests of the same class.
    """
    with DIDWebServer(data_dir=tmp_path_factory.mktemp("did_web")) as did_web_server:
        cert_bundle = did_web_server.cert_bundle
        client.governance.propose(
            governance.set_ca_bundle_proposal("did_web_tls_roots", cert_bundle),
            must_pass=True,
        )

        yield did_web_server


@pytest.fixture(scope="class")
def trust_store(client) -> dict:
    """
    Get the trust store associated with the service.
    """
    return client.get_trust_store()
