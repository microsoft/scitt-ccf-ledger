# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
import os
import shlex
from pathlib import Path

import pytest
from cose.messages import CoseMessage
from loguru import logger as LOG

from infra.did_web_server import DIDWebServer
from pyscitt import crypto, did
from pyscitt.cli.main import main
from pyscitt.client import Client


def run(*cmd, **kwargs):
    args = [str(c) for c in cmd]
    for k, v in kwargs.items():
        flag = k.replace("_", "-")
        if v is True:
            args += [f"--{flag}"]
        elif isinstance(v, (str, Path)):
            args += [f"--{flag}={v}"]
        else:
            raise TypeError(f"Invalid value: {v}")

    LOG.info(shlex.join(["scitt"] + args))
    main(args)


def test_smoke_test(tmp_path: Path):
    url = os.environ.get("CCF_URL", "https://127.0.0.1:8000")
    server_args = {
        "url": url,
        "development": True,
    }

    trust_store = tmp_path / "store"
    trust_store.mkdir()
    (trust_store / "service.json").write_text(
        json.dumps(Client(**server_args).get_parameters())
    )

    (tmp_path / "claims.json").write_text(json.dumps({"foo": "bar"}))

    (tmp_path / "config.json").write_text(
        json.dumps({"authentication": {"allow_unauthenticated": True}})
    )

    with DIDWebServer(tmp_path) as server:
        (tmp_path / "bundle.pem").write_text(server.cert_bundle)

        run(
            "governance",
            "propose_configuration",
            configuration=tmp_path / "config.json",
            **server_args,
        )

        run(
            "governance",
            "propose_ca_certs",
            name="did_web_tls_roots",
            ca_certs=tmp_path / "bundle.pem",
            **server_args,
        )

        run(
            "create-did-web",
            url=f"https://localhost:{server.port}/me",
            kty="ec",
            out_dir=tmp_path / "me",
        )

        run(
            "sign",
            key=tmp_path / "me" / "key.pem",
            did_doc=tmp_path / "me" / "did.json",
            claims=tmp_path / "claims.json",
            content_type="application/json",
            out=tmp_path / "claims.cose",
        )

        run("submit", tmp_path / "claims.cose", skip_confirmation=True, **server_args)

        run(
            "submit",
            tmp_path / "claims.cose",
            receipt=tmp_path / "receipt.cose",
            **server_args,
        )

        run("pretty-receipt", tmp_path / "receipt.cose")

        run(
            "embed-receipt",
            tmp_path / "claims.cose",
            receipt=tmp_path / "receipt.cose",
            out=tmp_path / "claims.embedded.cose",
        )

        run(
            "validate",
            tmp_path / "claims.cose",
            receipt=tmp_path / "receipt.cose",
            service_trust_store=trust_store,
        )

        run(
            "validate",
            tmp_path / "claims.embedded.cose",
            service_trust_store=trust_store,
        )


def test_local_development(tmp_path: Path):
    url = os.environ.get("CCF_URL", "https://127.0.0.1:8000")

    # This is not particularly useful to run tests against, since it uses Mozilla CA roots, meaning
    # we can't issue any DID web that would validate, but at least we check that the command doesn't
    # fail.
    #
    # Note that unlike other commands, we don't need to set the --development flag, since that is
    # the default.
    run(
        "governance",
        "local_development",
        url=url,
        service_trust_store=tmp_path / "trust_store",
    )


def test_create_ssh_did_web(tmp_path: Path):
    private_key, public_key = crypto.generate_rsa_keypair(2048)
    ssh_private_key = crypto.private_key_pem_to_ssh(private_key)
    ssh_public_key = crypto.pub_key_pem_to_ssh(public_key)

    (tmp_path / "id_rsa").write_text(ssh_private_key)
    (tmp_path / "id_rsa.pub").write_text(ssh_public_key)
    (tmp_path / "claims.json").write_text(json.dumps({"foo": "bar"}))

    run(
        "create-did-web",
        url=f"https://localhost:1234/me",
        ssh_key=tmp_path / "id_rsa.pub",
        out_dir=tmp_path / "me",
    )

    run(
        "create-did-web",
        url=f"https://localhost:1234/",
        ssh_key=tmp_path / "id_rsa.pub",
        out_dir=tmp_path / "me",
    )

    run(
        "create-did-web",
        url=f"https://localhost:1234",
        ssh_key=tmp_path / "id_rsa.pub",
        out_dir=tmp_path / "me",
    )

    run(
        "sign",
        key=tmp_path / "id_rsa",
        did_doc=tmp_path / "me" / "did.json",
        claims=tmp_path / "claims.json",
        content_type="application/json",
        out=tmp_path / "claims.cose",
    )


def test_adhoc_signer(tmp_path: Path):
    private_key, public_key = crypto.generate_rsa_keypair(2048)
    (tmp_path / "key.pem").write_text(private_key)
    (tmp_path / "key_pub.pem").write_text(public_key)
    (tmp_path / "claims.json").write_text(json.dumps({"foo": "bar"}))

    # Sign without even an issuer.
    # Note that the ledger wouldn't accept such a claim, we'd need to embed an x509 chain for it to
    # work (which isn't supported by the CLI yet).
    run(
        "sign",
        key=tmp_path / "key.pem",
        claims=tmp_path / "claims.json",
        content_type="application/json",
        out=tmp_path / "claims.cose",
    )

    # Sign with a DID issuer, but without creating an on-disk DID document first.
    # Also tests how to override the default algorithm.
    run(
        "sign",
        key=tmp_path / "key.pem",
        issuer="did:web:example.com",
        claims=tmp_path / "claims.json",
        content_type="application/json",
        alg="PS384",
        out=tmp_path / "claims.cose",
    )


@pytest.mark.prefix_tree
def test_prefix_tree(tmp_path: Path):
    url = os.environ.get("CCF_URL", "https://127.0.0.1:8000")
    server_args = {
        "url": url,
        "development": True,
    }

    (tmp_path / "claims.json").write_text(json.dumps({"foo": "bar"}))

    with DIDWebServer(tmp_path) as server:
        (tmp_path / "bundle.pem").write_text(server.cert_bundle)
        run(
            "governance",
            "local_development",
            url=url,
            service_trust_store=tmp_path / "trust_store",
            did_web_ca_certs=tmp_path / "bundle.pem",
        )

        run(
            "create-did-web",
            url=f"https://localhost:{server.port}/me",
            kty="ec",
            out_dir=tmp_path / "me",
        )

        run(
            "sign",
            key=tmp_path / "me" / "key.pem",
            did_doc=tmp_path / "me" / "did.json",
            claims=tmp_path / "claims.json",
            feed="hello",
            content_type="application/json",
            out=tmp_path / "claims.cose",
        )

        run("submit", tmp_path / "claims.cose", **server_args)

        run("prefix-tree", "flush", **server_args)

        # We can either fetch the read receipt by issuer and feed, ...
        run(
            "prefix-tree",
            "receipt",
            issuer=did.format_did_web("localhost", server.port, "me"),
            feed="hello",
            output=tmp_path / "read_receipt.cbor",
            **server_args,
        )

        # or we can fetch it based on our signed claim.
        run(
            "prefix-tree",
            "receipt",
            claim=tmp_path / "claims.cose",
            service_trust_store=tmp_path / "trust_store",
            output=tmp_path / "read_receipt.cbor",
            **server_args,
        )


def test_registration_info(tmp_path: Path):
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
        key=tmp_path / "key.pem",
        content_type="application/json",
        claims=tmp_path / "claims.json",
        out=tmp_path / "claims.cose",
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
