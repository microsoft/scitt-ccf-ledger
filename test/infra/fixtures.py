# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import os
from contextlib import contextmanager
from http import HTTPStatus
from pathlib import Path
from urllib.parse import urlparse

import pytest
from loguru import logger as LOG

from pyscitt import governance
from pyscitt.client import Client
from pyscitt.did import format_did_web
from pyscitt.local_key_sign_client import LocalKeySignClient
from pyscitt.verify import StaticTrustStore

from .cchost import CCHost, get_default_cchost_path, get_enclave_path
from .did_web_server import DIDWebServer
from .proxy import Proxy
from .x5chain_certificate_authority import X5ChainCertificateAuthority

# This file defines a collection of pytest fixtures used to manage and
# interact with the SCITT ledger.
#
# It defines three pytest plugins, ManagedCCHostFixtures, ExternalLedgerFixtures
# and Fixtures. The first two provide the same functionality, but one starts a
# cchost process whereas the other connects to an already running service.


class ManagedCCHostFixtures:
    def __init__(self, binary, platform, enclave_file, constitution, enable_faketime):
        self.binary = binary
        self.platform = platform
        self.enclave_file = enclave_file
        self.constitution = constitution
        self.enable_faketime = enable_faketime

    def pytest_collection_modifyitems(self, config, items):
        faketime_skip = pytest.mark.skip(reason="faketime support was not enabled")

        for item in items:
            for m in item.own_markers:
                if m.name == "isolated_test":
                    # The isolated_test marker cannot be used on functions, only on classes.
                    # The reason is that the `cchost` fixture has a class scope, therefore
                    # only has access to class markers.
                    #
                    # Functions which are defined directly at the module level are an
                    # exception: the class-scoped fixture will have access to markers set on
                    # the function.
                    if isinstance(item.parent, pytest.Class):
                        raise pytest.UsageError(
                            f"'isolated_test' marker may not be used on class method {item.nodeid!r}"
                        )

                    if m.kwargs.get("enable_faketime") and not self.enable_faketime:
                        item.add_marker(faketime_skip)

    @pytest.fixture(scope="session")
    def start_cchost(self, tmp_path_factory):
        """
        Start a managed SCITT service, using cchost.

        This fixture returns a function, which creates a new service everytime
        it is called. Tests should not use this fixture directly. Instead the
        cchost (or client) fixture should be used, which provides access to an
        already running instance.
        """

        constitution_files = [
            self.constitution / "validate.js",
            self.constitution / "apply.js",
            self.constitution / "resolve.js",
            self.constitution / "actions.js",
            self.constitution / "scitt.js",
        ]

        @contextmanager
        def f(**kwargs):
            workspace = tmp_path_factory.mktemp("workspace")

            cchost = CCHost(
                self.binary,
                self.platform,
                self.enclave_file,
                workspace=workspace,
                constitution=constitution_files,
                **kwargs,
            )

            with cchost:
                # There's a bit of setup involved before we can use this service.
                # When using an external ledger we assume this has been done already,
                # but in this case we need to do it here.
                client = Client(
                    f"https://127.0.0.1:{cchost.rpc_port}",
                    development=True,
                    member_auth=LocalKeySignClient(
                        cchost.member_cert, cchost.member_private_key
                    ),
                )
                client.governance.activate_member()

                network = client.get("node/network").json()
                proposal = governance.transition_service_to_open_proposal(
                    network["service_certificate"]
                )
                client.governance.propose(proposal, must_pass=True)
                client.get(
                    "/parameters",
                    retry_on=[(HTTPStatus.NOT_FOUND, "FrontendNotOpen")],
                )

                yield cchost

        return f

    @pytest.fixture(scope="session")
    def shared_cchost(self, start_cchost):
        """
        Create a cchost process, scoped to the entire test session.

        This fixture should not be used directly in tests. Instead the cchost
        fixture should be used along with a isolated_test marker.
        """

        LOG.info("Starting shared cchost process")
        with start_cchost() as cchost:
            yield cchost

    @pytest.fixture(scope="class")
    def cchost(self, start_cchost, request):
        """
        Get a reference to the cchost instance associated with the current test.

        If the test class has an `isolated_test` marker, the returned instance
        is only shared with other tests of the same class. Otherwise an instance
        shared by all non-isolated tests is returned.
        """
        marker = request.node.get_closest_marker("isolated_test")
        if marker is not None:
            LOG.info(f"Starting isolated cchost process for {request.node.nodeid!r}")
            with start_cchost(**marker.kwargs) as cchost:
                yield cchost
        else:
            yield request.getfixturevalue("shared_cchost")

    @pytest.fixture(scope="class")
    def proxy(self, cchost, request):
        """
        Creates a Proxy instance that is pointed at the currently running
        cchost instance's RPC port.

        The proxy provides a stable port on which the service can be reached
        at, even as the service is restarted and its port changes.
        """
        if "disable_proxy" in request.keywords:
            raise RuntimeError(
                "Proxy is disabled for this test, cannot use the `proxy` fixture"
            )

        with Proxy("localhost", cchost.rpc_port) as proxy:
            yield proxy

    @pytest.fixture(scope="class")
    def service_url(self, request):
        # The proxy allows us to later restart the cchost process,
        # listening on a different port number, while still providing a
        # stable hostname and port number for the service.
        #
        # While the proxy is completely transparent, some tests may want
        # to disable this feature, as it may affect performance.
        if "disable_proxy" in request.keywords:
            cchost = request.getfixturevalue("cchost")
            return f"https://127.0.0.1:{cchost.rpc_port}"
        else:
            proxy = request.getfixturevalue("proxy")
            return f"https://127.0.0.1:{proxy.port}"

    @pytest.fixture(scope="class")
    def member_auth(self, cchost):
        return LocalKeySignClient(cchost.member_cert, cchost.member_private_key)

    @pytest.fixture(scope="class")
    def member_auth_path(self, member_auth, tmp_path_factory):
        path = tmp_path_factory.mktemp("member")
        path.joinpath("member0_cert.pem").write_text(member_auth.cert)
        path.joinpath("member0_privk.pem").write_text(member_auth.key)
        return (path.joinpath("member0_cert.pem"), path.joinpath("member0_privk.pem"))

    @pytest.fixture(scope="class")
    def restart_service(self, cchost, proxy, client):
        """
        Restart the cchost process and perform recovery on the process.

        The proxy is updated to point to the new process.
        """

        def f():
            cchost.restart()
            proxy.set_upstream("localhost", cchost.rpc_port)
            client.governance.recover_service(cchost.encryption_private_key)

        return f


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
        return LocalKeySignClient(
            member_auth_path[0].read_text(), member_auth_path[1].read_text()
        )


def pytest_addoption(parser):
    parser.addoption(
        "--start-cchost",
        action="store_true",
        help="Start a cchost process managed by the test framework",
    )
    parser.addoption(
        "--cchost-binary",
        help="Path to the cchost binary. Requires --start-cchost.",
    )
    parser.addoption(
        "--platform",
        default="virtual",
        choices=["sgx", "virtual", "snp"],
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
    parser.addoption(
        "--enable-faketime",
        action="store_true",
    )


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "isolated_test: run this test with its own class-scoped cchost process.",
    )
    config.addinivalue_line(
        "markers",
        "disable_proxy: run this test without a proxy in front of the cchost process",
    )

    if config.getoption("--start-cchost"):
        enclave_package = config.getoption("--enclave-package")
        platform = config.getoption("--platform")
        binary = config.getoption("--cchost-binary") or get_default_cchost_path(
            platform
        )
        constitution = config.getoption("--constitution")
        enclave_file = get_enclave_path(platform, enclave_package)
        enable_faketime = config.getoption("--enable-faketime")
        config.pluginmanager.register(
            ManagedCCHostFixtures(
                binary, platform, enclave_file, constitution, enable_faketime
            )
        )
    else:
        config.pluginmanager.register(ExternalLedgerFixtures())


def pytest_collection_modifyitems(config, items):
    if not config.getoption("--start-cchost"):
        needs_cchost_skip = pytest.mark.skip(
            reason="Test requires a managed cchost process"
        )
        for item in items:
            if "isolated_test" in item.keywords:
                item.add_marker(needs_cchost_skip)


@pytest.fixture(scope="class")
def service_identifier(service_url: str) -> str:
    """
    Get the long term service identifier, under the form of a DID.

    The service is configured to include this identifier in receipts.
    """

    result = urlparse(service_url)
    assert result.hostname is not None
    return format_did_web(result.hostname, result.port)


@pytest.fixture(scope="class")
def base_client(service_url, member_auth):
    """
    Create a Client instance to connect to the test SCITT service.

    Most tests will want to use the `client` fixture instead, which resets the
    service to a known good state.
    """
    return Client(service_url, development=True, member_auth=member_auth)


@pytest.fixture(scope="class")
def configure_service(base_client: Client, service_identifier: str):
    """
    Change the service configuration.

    The fixture returns a function which may be called with the new
    configuration dictionary. It applies some good defaults for configuration
    entries that have not been specified.
    """

    def f(configuration):
        configuration = configuration.copy()
        configuration.setdefault("authentication", {"allow_unauthenticated": True})
        configuration.setdefault("service_identifier", service_identifier)

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
def trusted_ca(client) -> X5ChainCertificateAuthority:
    """
    Create a X5ChainCertificateAuthority and add its root to the SCITT service.

    The service will accept claims signed using certificates issued by the CA.
    """
    ca = X5ChainCertificateAuthority(kty="ec")
    proposal = governance.set_ca_bundle_proposal("x509_roots", ca.cert_bundle)
    client.governance.propose(proposal, must_pass=True)
    return ca


@pytest.fixture(scope="class")
def untrusted_ca(client) -> X5ChainCertificateAuthority:
    """
    Create a X5ChainCertificateAuthority but do not add its root to the SCITT service.

    The service will reject claims signed using certificates issued by the CA.
    """
    return X5ChainCertificateAuthority(kty="ec")


@pytest.fixture(scope="class")
def trust_store(client) -> StaticTrustStore:
    """
    Get the static trust store associated with the service.
    """
    params = client.get_parameters()
    return StaticTrustStore({params.service_id: params})
