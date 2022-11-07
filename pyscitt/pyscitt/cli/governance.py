# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import argparse
import json
from pathlib import Path
from typing import Optional, Union

import certifi

from .. import governance
from ..client import Client
from .client_arguments import add_client_arguments, create_client


def execute_governance(
    client: Client, proposal: Union[dict, bytes], dump_only: bool = False
):
    if isinstance(proposal, dict):
        proposal = json.dumps(proposal).encode("ascii")

    if dump_only:
        Path("proposal.json").write_bytes(proposal)
    else:
        result = client.governance.propose(proposal)
        if result.is_accepted:
            print(f"Proposal was accepted!")
        elif result.is_open:
            print(f"Proposal {result.id} is still open, more votes needed!")
        else:
            print(f"Proposal {result.id} is {result.state}")


def propose_root_ca_certs(
    client: Client, bundle_name: str, ca_cert_path: Path, dump_only: bool
):
    cert_bundle = ca_cert_path.read_text()
    proposal = governance.set_ca_bundle_proposal(bundle_name, cert_bundle)
    execute_governance(client, proposal, dump_only)


def propose_configuration(client: Client, configuration_path: Path, dump_only: bool):
    with open(configuration_path) as f:
        configuration = json.load(f)

    proposal = governance.set_scitt_configuration_proposal(configuration)
    execute_governance(client, proposal, dump_only)


def propose_open_service(
    client: Client, next_service_certificate_path: Path, dump_only: bool
):
    next_service_certificate = next_service_certificate_path.read_text()
    proposal = governance.transition_service_to_open_proposal(next_service_certificate)
    execute_governance(client, proposal, dump_only)


def propose_generic(client: Client, path: Path):
    proposal = path.read_bytes()
    execute_governance(client, proposal)


def activate_member(client: Client):
    r = client.post("/gov/ack/update_state_digest", sign_request=True)
    client.post("/gov/ack", content=r.content, sign_request=True)


def setup_local_development(
    client: Client, trust_store_dir: Optional[Path], did_web_ca_certs: Optional[Path]
):
    # Member activation and opening the service are not necessary when
    # using sandbox.sh, since that will already been taken care of.
    # They are idempotent operation anyway, so no harm in doing them again.

    print("Activating member credentials...")
    activate_member(client)

    print("Configuring DID Web root CA bundle...")
    if did_web_ca_certs:
        bundle = did_web_ca_certs.read_text()
    else:
        # This uses the Mozilla root program. certifi is the same package that
        # provides roots for eg. the requests and httpx modules.
        bundle = certifi.contents()
    proposal = governance.set_ca_bundle_proposal("did_web_tls_roots", bundle)
    client.governance.propose(proposal, must_pass=True)

    print("Disabling authentication...")
    config = {"authentication": {"allow_unauthenticated": True}}
    proposal = governance.set_scitt_configuration_proposal(config)
    client.governance.propose(proposal, must_pass=True)

    print("Opening service...")
    network = client.get("node/network").json()
    proposal = governance.transition_service_to_open_proposal(
        network["service_certificate"]
    )
    client.governance.propose(proposal, must_pass=True)

    if trust_store_dir:
        print(f"Adding service to {trust_store_dir} ...")
        trust_store_dir.mkdir(parents=True, exist_ok=True)
        parameters = client.get_parameters()
        service_id = parameters["serviceId"]
        path = trust_store_dir.joinpath(service_id + ".json")
        path.write_text(json.dumps(parameters))


def cli(fn):
    parser = fn(description="Execute governance actions")
    sub = parser.add_subparsers(help="Governance action to execute", required=True)

    p = sub.add_parser("propose_ca_certs")
    add_client_arguments(p, with_member_auth=True)
    p.add_argument(
        "--name",
        choices=["did_web_tls_roots", "x509_roots"],
        required=True,
        help="Name of the CA Cert bundle as referenced in CCF apps",
        dest="bundle_name",
    )
    p.add_argument(
        "--ca-certs",
        type=Path,
        help="Path to PEM-encoded CA Cert bundle",
        required=True,
    )
    p.add_argument(
        "--dump-only",
        action="store_true",
        help="Dumps the proposal to proposal.json and exits",
    )
    p.set_defaults(
        func=lambda args: propose_root_ca_certs(
            create_client(args), args.bundle_name, args.ca_certs, args.dump_only
        )
    )

    p = sub.add_parser("propose_configuration")
    add_client_arguments(p, with_member_auth=True)
    p.add_argument(
        "--configuration", type=Path, help="JSON configuration", required=True
    )
    p.add_argument(
        "--dump-only",
        action="store_true",
        help="Dumps the proposal to proposal.json and exits",
    )
    p.set_defaults(
        func=lambda args: propose_configuration(
            create_client(args), args.configuration, args.dump_only
        )
    )

    p = sub.add_parser("propose_generic")
    add_client_arguments(p, with_member_auth=True)
    p.add_argument("--proposal-path", type=Path, help="JSON proposal", required=True)
    p.set_defaults(
        func=lambda args: propose_generic(create_client(args), args.proposal_path)
    )

    p = sub.add_parser("propose_open_service")
    add_client_arguments(p, with_member_auth=True)
    p.add_argument(
        "--next-service-certificate",
        type=Path,
        help="Path to next service certificate",
        required=True,
    )
    p.add_argument(
        "--dump-only",
        action="store_true",
        help="Dumps the proposal to proposal.json and exits",
    )
    p.set_defaults(
        func=lambda args: propose_open_service(
            create_client(args), args.next_service_certificate, args.dump_only
        )
    )

    p = sub.add_parser("activate_member")
    add_client_arguments(p, with_member_auth=True)
    p.set_defaults(func=lambda args: activate_member(create_client(args)))

    p = sub.add_parser(
        "local_development", help="Configure a SCITT ledger for local development."
    )
    add_client_arguments(p, with_member_auth=True, development_only=True)
    p.add_argument(
        "--service-trust-store",
        type=Path,
        help="Folder containing a SCITT trust store, to which this service's identity will be added.",
    )
    p.add_argument(
        "--did-web-ca-certs",
        type=Path,
        help="Path to PEM-encoded CA Cert bundle, used by the service when resolving DID web issuers. By default, the Mozilla CA roots are used.",
    )
    p.set_defaults(
        func=lambda args: setup_local_development(
            create_client(args), args.service_trust_store, args.did_web_ca_certs
        )
    )

    return parser


if __name__ == "__main__":
    parser = cli(argparse.ArgumentParser)
    args = parser.parse_args()
    args.func(args)
