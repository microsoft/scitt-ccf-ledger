# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
import shlex
from pathlib import Path

import pytest
from loguru import logger as LOG
from pycose.messages import CoseMessage

from pyscitt import crypto, did
from pyscitt.cli.governance import (
    SCITT_CONSTITUTION_MARKER_END,
    SCITT_CONSTITUTION_MARKER_START,
)
from pyscitt.cli.main import main
from pyscitt.governance import ProposalNotAccepted

from .infra.assertions import service_error
from .infra.did_web_server import DIDWebServer
from .infra.generate_cacert import generate_ca_cert_and_key


@pytest.fixture
def run(request):
    def f(*cmd, with_service_url=False, with_member_auth=False):
        args = [str(c) for c in cmd]

        # We necessary, we insert extra flags that depend on the service we are running against.
        # We request the fixtures dynamically by using `getfixturevalue` rather than as
        # dependencies of the `run` fixture, to avoid needlessly start a cchost process
        # if only running "offline" tests.
        if with_service_url:
            url = request.getfixturevalue("service_url")
            args.extend(["--url", url, "--development"])

        if with_member_auth:
            paths = request.getfixturevalue("member_auth_path")
            args.extend(["--member-cert", str(paths[0])])
            args.extend(["--member-key", str(paths[1])])

        LOG.info(shlex.join(["scitt"] + args))
        main(args)

    return f


def test_smoke_test(run, client, tmp_path: Path):
    trust_store_path = tmp_path / "store"
    trust_store_path.mkdir()
    (trust_store_path / "service.json").write_text(
        json.dumps(client.get_parameters().as_dict())
    )

    (tmp_path / "claims.json").write_text(json.dumps({"foo": "bar"}))

    (tmp_path / "config.json").write_text(
        json.dumps({"authentication": {"allow_unauthenticated": True}})
    )

    # We could use the did_web fixture for this, but that sets up certs for us
    # already, and we want to test the propose_ca_certs command.
    with DIDWebServer(tmp_path) as server:
        (tmp_path / "bundle.pem").write_text(server.cert_bundle)

        run(
            "governance",
            "propose_configuration",
            "--configuration",
            tmp_path / "config.json",
            with_service_url=True,
            with_member_auth=True,
        )

        run(
            "governance",
            "propose_ca_certs",
            "--name",
            "did_web_tls_roots",
            "--ca-certs",
            tmp_path / "bundle.pem",
            with_service_url=True,
            with_member_auth=True,
        )

        print(server.port)
        run(
            "create-did-web",
            "--url",
            f"https://localhost:{server.port}/me",
            "--kty",
            "ec",
            "--out-dir",
            tmp_path / "me",
        )

        run(
            "sign",
            "--key",
            tmp_path / "me" / "key.pem",
            "--did-doc",
            tmp_path / "me" / "did.json",
            "--claims",
            tmp_path / "claims.json",
            "--content-type",
            "application/json",
            "--out",
            tmp_path / "claims.cose",
        )

        run(
            "submit",
            "--skip-confirmation",
            tmp_path / "claims.cose",
            with_service_url=True,
        )

        run(
            "submit",
            tmp_path / "claims.cose",
            "--receipt",
            tmp_path / "receipt.cose",
            with_service_url=True,
        )

        run("pretty-receipt", tmp_path / "receipt.cose")

        run(
            "embed-receipt",
            tmp_path / "claims.cose",
            "--receipt",
            tmp_path / "receipt.cose",
            "--out",
            tmp_path / "claims.embedded.cose",
        )

        run(
            "validate",
            tmp_path / "claims.cose",
            "--receipt",
            tmp_path / "receipt.cose",
            "--service-trust-store",
            trust_store_path,
        )


def test_use_cacert_submit_verify_x509_signature(run, client, tmp_path: Path):
    # Add basic service config
    (tmp_path / "config.json").write_text(
        json.dumps({"authentication": {"allow_unauthenticated": True}})
    )
    run(
        "governance",
        "propose_configuration",
        "--configuration",
        tmp_path / "config.json",
        with_service_url=True,
        with_member_auth=True,
    )

    # Get the CA cert from the service params
    # Once in production this value can come from other trusted places
    service_params = client.get_parameters().as_dict()
    (tmp_path / "tlscacert.pem").write_text(
        f"-----BEGIN CERTIFICATE-----\n{service_params.get('serviceCertificate')}\n-----END CERTIFICATE-----\n"
    )

    # Setup signing keys imitating how third party might do it
    generate_ca_cert_and_key(
        f"{tmp_path}",
        "ES256",
        "ec",
        "P-256",
        key_filename="signerkey.pem",
        cacert_filename="signerca.pem",
    )

    # Configure SCITT policy to accept the message if it was signed
    # by the given key
    run(
        "governance",
        "propose_ca_certs",
        "--name",
        "x509_roots",
        "--ca-certs",
        tmp_path / "signerca.pem",
        with_service_url=True,
        with_member_auth=True,
    )

    # Prepare an x509 cose file to submit to the service
    (tmp_path / "claims.json").write_text(json.dumps({"foo": "bar"}))
    run(
        "sign",
        "--key",
        tmp_path / "signerkey.pem",
        "--claims",
        tmp_path / "claims.json",
        "--content-type",
        "application/json",
        "--x5c",
        tmp_path / "signerca.pem",
        "--out",
        tmp_path / "claims.cose",
    )

    # Submit cose and make sure TLS verification is enabled
    # this should exit without error
    run(
        "submit",
        "--cacert",
        tmp_path / "tlscacert.pem",
        tmp_path / "claims.cose",
        "--url",
        # TLS cert does not have 127.0.0.1 set in SAN but 0.0.0.0 and the verification fails
        # it does not happen in practice against a live running instance as SAN will contain
        # the public ip and the dns entries
        client.url.replace("127.0.0.1", "0.0.0.0"),
        "--receipt",
        tmp_path / "receipt.cbor",
    )

    run("pretty-receipt", tmp_path / "receipt.cbor")

    run(
        "embed-receipt",
        tmp_path / "claims.cose",
        "--receipt",
        tmp_path / "receipt.cbor",
        "--out",
        tmp_path / "claims.embedded.cose",
    )

    trust_store_path = tmp_path / "store"
    trust_store_path.mkdir()
    (trust_store_path / "service.json").write_text(
        json.dumps(service_params)
    )
    run(
        "validate",
        tmp_path / "claims.embedded.cose",
        "--service-trust-store",
        trust_store_path,
    )


def test_local_development(run, service_url, tmp_path: Path):
    # This is not particularly useful to run tests against, since it uses Mozilla CA roots, meaning
    # we can't issue any DID web that would validate, but at least we check that the command doesn't
    # fail.
    #
    # Note that unlike other commands, we don't need to set the --development flag, since that is
    # the default.
    run(
        "governance",
        "local_development",
        "--service-trust-store",
        tmp_path / "trust_store",
        "--url",
        service_url,
        with_member_auth=True,
    )


def test_create_ssh_did_web(run, tmp_path: Path):
    private_key, public_key = crypto.generate_rsa_keypair(2048)
    ssh_private_key = crypto.private_key_pem_to_ssh(private_key)
    ssh_public_key = crypto.pub_key_pem_to_ssh(public_key)

    (tmp_path / "id_rsa").write_text(ssh_private_key)
    (tmp_path / "id_rsa.pub").write_text(ssh_public_key)
    (tmp_path / "claims.json").write_text(json.dumps({"foo": "bar"}))

    run(
        "create-did-web",
        "--url",
        f"https://localhost:1234/me",
        "--ssh-key",
        tmp_path / "id_rsa.pub",
        "--out-dir",
        tmp_path / "me",
    )

    run(
        "create-did-web",
        "--url",
        f"https://localhost:1234/",
        "--ssh-key",
        tmp_path / "id_rsa.pub",
        "--out-dir",
        tmp_path / "me",
    )

    run(
        "create-did-web",
        "--url",
        f"https://localhost:1234",
        "--ssh-key",
        tmp_path / "id_rsa.pub",
        "--out-dir",
        tmp_path / "me",
    )

    run(
        "sign",
        "--key",
        tmp_path / "id_rsa",
        "--did-doc",
        tmp_path / "me" / "did.json",
        "--claims",
        tmp_path / "claims.json",
        "--content-type",
        "application/json",
        "--out",
        tmp_path / "claims.cose",
    )


def test_adhoc_signer(run, tmp_path: Path):
    private_key, public_key = crypto.generate_rsa_keypair(2048)
    (tmp_path / "key.pem").write_text(private_key)
    (tmp_path / "key_pub.pem").write_text(public_key)
    (tmp_path / "claims.json").write_text(json.dumps({"foo": "bar"}))

    # Sign without even an issuer.
    # Note that the ledger wouldn't accept such a claim, we'd need to embed an x509 chain for it to
    # work (which isn't supported by the CLI yet).
    run(
        "sign",
        "--key",
        tmp_path / "key.pem",
        "--claims",
        tmp_path / "claims.json",
        "--content-type",
        "application/json",
        "--out",
        tmp_path / "claims.cose",
    )

    # Sign with a DID issuer, but without creating an on-disk DID document first.
    # Also tests how to override the default algorithm.
    run(
        "sign",
        "--key",
        tmp_path / "key.pem",
        "--issuer",
        "did:web:example.com",
        "--claims",
        tmp_path / "claims.json",
        "--content-type",
        "application/json",
        "--alg",
        "PS384",
        "--out",
        tmp_path / "claims.cose",
    )


@pytest.mark.needs_prefix_tree
def test_prefix_tree(run, tmp_path: Path):
    (tmp_path / "claims.json").write_text(json.dumps({"foo": "bar"}))

    with DIDWebServer(tmp_path) as server:
        (tmp_path / "bundle.pem").write_text(server.cert_bundle)
        run(
            "governance",
            "local_development",
            "--service-trust-store",
            tmp_path / "trust_store",
            "--did-web-ca-certs",
            tmp_path / "bundle.pem",
            with_service_url=True,
            with_member_auth=True,
        )

        run(
            "create-did-web",
            "--url",
            f"https://localhost:{server.port}/me",
            "--kty",
            "ec",
            "--out-dir",
            tmp_path / "me",
        )

        run(
            "sign",
            "--key",
            tmp_path / "me" / "key.pem",
            "--did-doc",
            tmp_path / "me" / "did.json",
            "--claims",
            tmp_path / "claims.json",
            "--feed",
            "hello",
            "--content-type",
            "application/json",
            "--out",
            tmp_path / "claims.cose",
        )

        run(
            "submit",
            tmp_path / "claims.cose",
            with_service_url=True,
        )

        run("prefix-tree", "flush", with_service_url=True)

        # We can either fetch the read receipt by issuer and feed, ...
        run(
            "prefix-tree",
            "receipt",
            "--issuer",
            did.format_did_web("localhost", server.port, "me"),
            "--feed",
            "hello",
            "--output",
            tmp_path / "read_receipt.cbor",
            with_service_url=True,
        )

        # or we can fetch it based on our signed claim.
        run(
            "prefix-tree",
            "receipt",
            "--claim",
            tmp_path / "claims.cose",
            "--service-trust-store",
            tmp_path / "trust_store",
            "--output",
            tmp_path / "read_receipt.cbor",
            with_service_url=True,
        )


def test_registration_info(run, tmp_path: Path):
    private_key, public_key = crypto.generate_rsa_keypair(2048)
    (tmp_path / "key.pem").write_text(private_key)
    (tmp_path / "claims.json").write_text(json.dumps({"foo": "bar"}))

    binary_data = b"\xde\xad\xbe\xef"
    binary_path = tmp_path / "binary.txt"
    binary_path.write_bytes(binary_data)

    # This is a Grinning Face emoji
    unicode_data = "\U0001F600"
    unicode_path = tmp_path / "unicode.txt"
    unicode_path.write_text(unicode_data, encoding="utf-8")

    run(
        "sign",
        "--registration-info=int:foo=42",
        "--registration-info=int:negative=-42",
        "--registration-info=text:bar=hello",
        "--registration-info=with_default_type=world",
        f"--registration-info=bytes:binary_data=@{binary_path}",
        f"--registration-info=text:unicode_data=@{unicode_path}",
        "--key",
        tmp_path / "key.pem",
        "--content-type",
        "application/json",
        "--claims",
        tmp_path / "claims.json",
        "--out",
        tmp_path / "claims.cose",
    )

    data = (tmp_path / "claims.cose").read_bytes()
    msg = CoseMessage.decode(data)
    info = msg.phdr[crypto.COSE_HEADER_PARAM_REGISTRATION_INFO]
    assert info == {
        "foo": 42,
        "negative": -42,
        "bar": "hello",
        "with_default_type": "world",
        "binary_data": binary_data,
        "unicode_data": unicode_data,
    }


@pytest.mark.isolated_test
class TestUpdateScittConstitution:
    # These tests run in an isolated cchost process. This ensures that if
    # something goes wrong with the test and leaves the service with an invalid
    # constitution, the other tests can carry on unaffected.
    #
    # The isolated process is shared by the entire class though, so one broken
    # test could still affect other tests of this class.

    @pytest.fixture(autouse=True)
    def original_constitution(self, run, tmp_path_factory):
        """
        Save the original constitution and restore it after the test has run.
        The fixture provides the core constitution's contents, that is with the
        SCITT amendments stripped.

        It is marked as autouse, making the save/restore automatic for all tests
        in this class.
        """
        tmp = tmp_path_factory.mktemp("original_constitution")
        path = tmp / "constitution.js"
        run(
            "governance",
            "constitution",
            "--output",
            path,
            with_service_url=True,
        )

        try:
            parts = path.read_text().split(SCITT_CONSTITUTION_MARKER_START)
            core_constitution = parts[0]

            # Propose a new constitution, truncating anything after the marker.
            # This provides a consistent starting point for all the tests.
            core_path = tmp / "core_constitution.js"
            core_path.write_text(core_constitution)
            run(
                "governance",
                "propose_constitution",
                "--constitution-file",
                core_path,
                with_service_url=True,
                with_member_auth=True,
            )

            yield core_constitution

        finally:
            # Whatever happens in the test, do our best to restore it.
            run(
                "governance",
                "propose_constitution",
                "--constitution-file",
                path,
                with_service_url=True,
                with_member_auth=True,
            )

    @pytest.fixture
    def update_scitt_constitution(self, run, tmp_path):
        def f(script, include_markers=True, yes=True):
            path = tmp_path / "scitt.js"
            if include_markers:
                path.write_text(
                    SCITT_CONSTITUTION_MARKER_START
                    + script
                    + SCITT_CONSTITUTION_MARKER_END
                )
            else:
                path.write_text(script)

            run(
                "governance",
                "update_scitt_constitution",
                "--scitt-constitution-file",
                path,
                *(["--yes"] if yes else []),
                with_service_url=True,
                with_member_auth=True,
            )

        return f

    def test_update_scitt_constitution(self, run, tmp_path, update_scitt_constitution):
        proposal = tmp_path / "proposal.json"
        proposal.write_text(json.dumps({"actions": [{"name": "my_action"}]}))

        # The my_action action does not exist yet.
        with service_error("my_action: no such action"):
            run(
                "governance",
                "propose_generic",
                "--proposal-path",
                proposal,
                with_service_url=True,
                with_member_auth=True,
            )

        update_scitt_constitution(
            'actions.set("my_action", new Action(function(args) { }, function(args) { }))'
        )

        run(
            "governance",
            "propose_generic",
            "--proposal-path",
            proposal,
            with_service_url=True,
            with_member_auth=True,
        )

        update_scitt_constitution(
            'actions.set("another_action", new Action(function(args) { }, function(args) { }))'
        )

        # After updating the constitution again, the my_action action will
        # fail to run, showing that we actually modified the SCITT constitution,
        # and didn't just append to it.
        with service_error("my_action: no such action"):
            run(
                "governance",
                "propose_generic",
                "--proposal-path",
                proposal,
                with_service_url=True,
                with_member_auth=True,
            )

    def test_invalid_constitution(self, update_scitt_constitution):
        with pytest.raises(RuntimeError, match="does not start with marker"):
            update_scitt_constitution("", include_markers=False)

        with pytest.raises(RuntimeError, match="does not end with marker"):
            update_scitt_constitution(
                SCITT_CONSTITUTION_MARKER_START, include_markers=False
            )

        with pytest.raises(RuntimeError, match="does not end with marker"):
            update_scitt_constitution(
                SCITT_CONSTITUTION_MARKER_START
                + SCITT_CONSTITUTION_MARKER_END
                + "// Trailing",
                include_markers=False,
            )

    def test_trailing_text(
        self, run, original_constitution, update_scitt_constitution, tmp_path
    ):
        # Write a constitution with the right markers, but with some text after it.
        # We can't use update_scitt_constitution for this because of its safety rails so
        # we use the more low-level propose_constitution.
        tmp_path.joinpath("constitution.js").write_text(
            original_constitution
            + SCITT_CONSTITUTION_MARKER_START
            + SCITT_CONSTITUTION_MARKER_END
            + "// Trailing stuff"
        )

        run(
            "governance",
            "propose_constitution",
            "--constitution-file",
            tmp_path / "constitution.js",
            with_service_url=True,
            with_member_auth=True,
        )

        # Allowing this would be bad, as it would risk dropping the trailing text.
        with pytest.raises(
            RuntimeError,
            match="Existing constitution does not end with the right marker",
        ):
            update_scitt_constitution("")

    def test_race_condition(self, update_scitt_constitution, monkeypatch):
        # We want to make two concurrent modifications to the constitution, and
        # make sure update_scitt_constitution detects this.
        # The way we do this is by running update_scitt_constitution in interactive mode (yes=False),
        # but monkeypatch the input() function. The input will always return yes
        # to proceed, but before doing so it makes its own change to the constitution
        def confirm(*args):
            try:
                update_scitt_constitution("// Concurrent change")
            except ProposalNotAccepted:
                raise RuntimeError("concurrent change not accepted")
            return "yes"

        monkeypatch.setattr("builtins.input", confirm)
        with pytest.raises(ProposalNotAccepted):
            update_scitt_constitution("// Main change", yes=False)
