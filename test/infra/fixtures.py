# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import itertools
import os
import time
from contextlib import contextmanager
from http import HTTPStatus
from pathlib import Path

import pytest

from pyscitt import governance
from pyscitt.client import Client

from .cchost import CCHost, get_enclave_path
from .did_web_server import DIDWebServer

# This file defines a collection of pytest fixtures used to manage and
# interact with the SCITT ledger.
#
# It defines three pytest plugins, ManagedCCHostFixtures, ExternalLedgerFixtures
# and Fixtures. The first two provide the same functionality, but one starts a
# cchost process whereas the other connects to an already running service.


class ManagedCCHostFixtures:
    def __init__(self, binary, enclave_type, enclave_file, constitution):
        self.binary = binary
        self.enclave_type = enclave_type
        self.enclave_file = enclave_file
        self.constitution = constitution

    @pytest.fixture(scope="session")
    def cchost(self, tmp_path_factory):
        """
        Start a managed SCITT service, using cchost.

        The service will keep running for the entire test session, and therefore
        shared among tests.
        """
        workspace = tmp_path_factory.mktemp("workspace")
        cchost = CCHost(
            self.binary,
            self.enclave_type,
            self.enclave_file,
            workspace=workspace,
            constitution=self.constitution,
        )
        with cchost:
            # There's a bit of setup involved before we can use this service.
            # When using an external ledger we assume this has been done already,
            # but in this case we need to do it here.
            client = Client(
                f"https://127.0.0.1:{cchost.rpc_port}",
                development=True,
                member_auth=(cchost.member_cert, cchost.member_private_key),
            )
            client.governance.activate_member()

            network = client.get("node/network").json()
            proposal = governance.transition_service_to_open_proposal(
                network["service_certificate"]
            )
            client.governance.propose(proposal, must_pass=True)
            client.get(
                "/app/parameters",
                retry_on=[(HTTPStatus.NOT_FOUND, "FrontendNotOpen")],
            )

            yield cchost

    @pytest.fixture(scope="session")
    def service_url(self, cchost):
        return f"https://127.0.0.1:{cchost.rpc_port}"

    @pytest.fixture(scope="session")
    def member_auth(self, cchost):
        return (cchost.member_cert, cchost.member_private_key)

    @pytest.fixture(scope="session")
    def member_auth_path(self, member_auth, tmp_path_factory):
        path = tmp_path_factory.mktemp("member")
        path.joinpath("member0_cert.pem").write_text(member_auth[0])
        path.joinpath("member0_privk.pem").write_text(member_auth[1])
        return (path.joinpath("member0_cert.pem"), path.joinpath("member0_privk.pem"))


class ExternalLedgerFixtures:
    @pytest.fixture(scope="session")
    def service_url(self):
        return os.environ.get("CCF_URL", "https://127.0.0.1:8000")

    @pytest.fixture(scope="session")
    def member_auth_path(self):
        workspace_dir = Path("workspace")
        return (
            workspace_dir.joinpath("member0_cert.pem"),
            workspace_dir.joinpath("member0_privk.pem"),
        )

    @pytest.fixture(scope="session")
    def member_auth(self, member_auth_path):
        return (member_auth_path[0].read_text(), member_auth_path[1].read_text())


def pytest_addoption(parser):
    parser.addoption(
        "--start-cchost",
        action="store_true",
        help="Start a cchost process managed by the test framework",
    )
    parser.addoption(
        "--cchost-binary",
        default="/opt/ccf/bin/cchost",
        help="Path to the cchost binary. Requires --start-cchost.",
    )
    parser.addoption(
        "--enclave-type",
        default="virtual",
        help="Type of enclave used when starting cchost. Requires --start-cchost.",
    )
    parser.addoption(
        "--enclave-package",
        default="/tmp/scitt/lib/libscitt",
        help="The enclave package to load. Requires --start-cchost.",
    )
    parser.addoption(
        "--constitution",
        type=Path,
        default="/tmp/scitt/share/scitt/constitution",
        help="Path to the directory containing the constitution. Requires --start-cchost.",
    )


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "needs_cchost: only run test if cchost is managed by the test framework.",
    )

    if config.getoption("--start-cchost"):
        binary = config.getoption("--cchost-binary")
        enclave_package = config.getoption("--enclave-package")
        enclave_type = config.getoption("--enclave-type")
        constitution = config.getoption("--constitution")
        enclave_file = get_enclave_path(enclave_type, enclave_package)
        config.pluginmanager.register(
            ManagedCCHostFixtures(binary, enclave_type, enclave_file, constitution)
        )
    else:
        config.pluginmanager.register(ExternalLedgerFixtures())


def pytest_collection_modifyitems(config, items):
    if not config.getoption("--start-cchost"):
        needs_cchost_skip = pytest.mark.skip(
            reason="Test requires a managed cchost process"
        )
        for item in items:
            if "needs_cchost" in item.keywords:
                item.add_marker(needs_cchost_skip)


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
