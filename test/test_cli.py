# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
import shlex
from pathlib import Path

import pytest
from loguru import logger as LOG
from pycose.messages import CoseMessage

from pyscitt import crypto
from pyscitt.cli.governance import (
    SCITT_CONSTITUTION_MARKER_END,
    SCITT_CONSTITUTION_MARKER_START,
)
from pyscitt.cli.main import main
from pyscitt.governance import ProposalNotAccepted

from .infra.assertions import service_error
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
        json.dumps({"authentication": {"allowUnauthenticated": True}})
    )


def test_local_development(run, service_url, tmp_path: Path):
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


def test_adhoc_signer(run, tmp_path: Path):
    private_key, public_key = crypto.generate_rsa_keypair()
    (tmp_path / "key.pem").write_text(private_key)
    (tmp_path / "key_pub.pem").write_text(public_key)
    (tmp_path / "statement.json").write_text(json.dumps({"foo": "bar"}))

    # Sign without even an issuer.
    # Note that the ledger wouldn't accept such a claim, we'd need to embed an x509 chain for it to
    # work (which isn't supported by the CLI yet).
    run(
        "sign",
        "--key",
        tmp_path / "key.pem",
        "--statement",
        tmp_path / "statement.json",
        "--content-type",
        "application/json",
        "--out",
        tmp_path / "signed_statement.cose",
    )

    # Sign with a custom issuer
    # Also tests how to override the default algorithm.
    run(
        "sign",
        "--key",
        tmp_path / "key.pem",
        "--issuer",
        "foo.bar.baz",
        "--statement",
        tmp_path / "statement.json",
        "--content-type",
        "application/json",
        "--alg",
        "PS384",
        "--out",
        tmp_path / "signed_statement.cose",
    )


def test_registration_info(run, tmp_path: Path):
    private_key, public_key = crypto.generate_rsa_keypair()
    (tmp_path / "key.pem").write_text(private_key)
    (tmp_path / "statement.json").write_text(json.dumps({"foo": "bar"}))

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
        "--statement",
        tmp_path / "statement.json",
        "--out",
        tmp_path / "signed_statement.cose",
    )

    data = (tmp_path / "signed_statement.cose").read_bytes()
    msg = CoseMessage.decode(data)
    info = msg.get_attr(crypto.SCITTRegistrationInfo)
    assert info == {
        "foo": 42,
        "negative": -42,
        "bar": "hello",
        "with_default_type": "world",
        "binary_data": binary_data,
        "unicode_data": unicode_data,
    }


def test_extract_payload_from_cose(run, tmp_path: Path):
    private_key, public_key = crypto.generate_rsa_keypair()
    (tmp_path / "key.pem").write_text(private_key)
    (tmp_path / "statement.json").write_text(json.dumps({"foo": "bar"}))

    run(
        "sign",
        "--key",
        tmp_path / "key.pem",
        "--content-type",
        "application/json",
        "--statement",
        tmp_path / "statement.json",
        "--out",
        tmp_path / "signed_statement.cose",
    )

    run(
        "split-payload",
        tmp_path / "signed_statement.cose",
        "--out",
        tmp_path / "payload.json",
    )

    data = (tmp_path / "payload.json").read_bytes()
    claims = json.loads(data)
    assert claims.get("foo") == "bar"


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
