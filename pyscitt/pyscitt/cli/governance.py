# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Optional, Union
from urllib.parse import urlparse

import certifi

from pyscitt.did import format_did_web

from .. import governance
from ..client import Client
from .client_arguments import add_client_arguments, create_client


@dataclass
class GovernanceAction:
    proposal: Union[dict, bytes]
    ballot: Optional[str] = None


def add_proposal_arguments(p, *, enable_dump_only=True):
    if enable_dump_only:
        p.add_argument(
            "--dump-only",
            action="store_true",
            help="Dumps the proposal to proposal.json and exits",
        )
    else:
        p.set_defaults(dump_only=False)

    p.add_argument(
        "--allow-open",
        action="store_true",
        help="Do not fail if the proposal remains open",
    )


def execute_action(client: Client, action: GovernanceAction, args: argparse.Namespace):
    if isinstance(action.proposal, bytes):
        proposal = action.proposal
    else:
        proposal = json.dumps(action.proposal).encode("ascii")

    if args.dump_only:
        Path("proposal.json").write_bytes(proposal)
    else:
        result = client.governance.propose(proposal, vote=False)
        if not result.is_accepted:
            result = client.governance.vote(
                result.id, ballot=action.ballot, must_pass=not args.allow_open
            )

        if result.is_accepted:
            print(f"Proposal was accepted!")
        elif result.is_open:
            print(f"Proposal {result.id} is still open, more votes needed!")
        else:
            print(f"Proposal {result.id} is {result.state}")


def propose_root_ca_certs(bundle_name: str, ca_cert_path: Path):
    cert_bundle = ca_cert_path.read_text()
    proposal = governance.set_ca_bundle_proposal(bundle_name, cert_bundle)
    return GovernanceAction(proposal)


def propose_configuration(configuration_path: Path):
    with open(configuration_path) as f:
        configuration = json.load(f)

    proposal = governance.set_scitt_configuration_proposal(configuration)
    return GovernanceAction(proposal)


def propose_open_service(next_service_certificate_path: Path):
    next_service_certificate = next_service_certificate_path.read_text()
    proposal = governance.transition_service_to_open_proposal(next_service_certificate)
    return GovernanceAction(proposal)


def propose_generic(path: Path):
    return GovernanceAction(path.read_bytes())


def propose_constitution(path: Path):
    constitution = path.read_text()
    proposal = governance.set_constitution_proposal(constitution)
    return GovernanceAction(proposal)


SCITT_CONSTITUTION_MARKER_START = "// ----- SCITT Constitution starts here -----\n"
SCITT_CONSTITUTION_MARKER_END = "// ----- SCITT Constitution ends here -----"


def apply_scitt_constitution_update(
    original_constitution: str, new_scitt_constitution: str
) -> str:
    if not new_scitt_constitution.startswith(SCITT_CONSTITUTION_MARKER_START):
        raise RuntimeError(
            f"New SCITT constitution does not start with marker {repr(SCITT_CONSTITUTION_MARKER_START)}"
        )
    if not new_scitt_constitution.rstrip().endswith(SCITT_CONSTITUTION_MARKER_END):
        raise RuntimeError(
            f"New SCITT constitution does not end with marker {repr(SCITT_CONSTITUTION_MARKER_END)}"
        )
    if new_scitt_constitution.count(SCITT_CONSTITUTION_MARKER_START) > 1:
        raise RuntimeError(f"New SCITT constitution contains multiple start markers")
    if new_scitt_constitution.count(SCITT_CONSTITUTION_MARKER_END) > 1:
        raise RuntimeError(f"New SCITT constitution contains multiple end markers")

    parts = original_constitution.split(SCITT_CONSTITUTION_MARKER_START)
    if len(parts) == 1:
        print(
            "Did not find any marker in existing constitution. The SCITT constitution will be appended to it"
        )
    elif len(parts) == 2:
        if not parts[1].rstrip().endswith(SCITT_CONSTITUTION_MARKER_END):
            raise RuntimeError(
                "Existing constitution does not end with the right marker"
            )
    else:
        assert len(parts) > 2
        raise RuntimeError("Found multiple markers in constitution")

    core_constitution = parts[0]
    if not core_constitution.endswith("\n"):
        core_constitution += "\n"

    return core_constitution + new_scitt_constitution


def update_scitt_constitution(client: Client, scitt_constitution_path: Path, yes: bool):
    scitt_constitution = scitt_constitution_path.read_text()
    initial_constitution = client.get_constitution()
    final_constitution = apply_scitt_constitution_update(
        initial_constitution, scitt_constitution
    )

    if not yes:
        with TemporaryDirectory() as d:
            path = Path(d).joinpath("constitution.js")
            path.write_text(final_constitution)

            print(f"Updated constitution was written to {path}.")
            print("You may review and modify the file before proceeding.")
            answer = input("Do you wish to continue [y/N]: ").lower()

            if answer == "y" or answer == "yes":
                final_constitution = path.read_text()
                pass
            else:
                print("Aborting")
                sys.exit(1)

    proposal = governance.set_constitution_proposal(final_constitution)

    # The ballot we submit will only approve the proposal if the constitution
    # found in the KV still matches the original value we got before applying the
    # update. Otherwise a concurrent change has happened, and we shouldn't be making
    # any changes.
    # Note the use of `repr` to turn the constitution into a valid Javascript
    # string literal, in particular, escaping quotations marks and newlines.
    ballot = f"""
        export function vote (rawProposal, proposerId) {{
            const singletonKey = new ArrayBuffer(8);
            const constitution = ccf.bufToJsonCompatible(ccf.kv["public:ccf.gov.constitution"].get(singletonKey));
            return constitution == {repr(initial_constitution)};
        }}
    """
    return GovernanceAction(proposal, ballot)


def get_constitution(client: Client, path: Path):
    path.write_text(client.get_constitution())


def setup_local_development(
    client: Client, trust_store_dir: Optional[Path], did_web_ca_certs: Optional[Path]
):
    # Member activation and opening the service are not necessary when
    # using sandbox.sh, since that will already been taken care of.
    # They are idempotent operation anyway, so no harm in doing them again.

    print("Activating member credentials...")
    client.governance.activate_member()

    print("Configuring DID Web root CA bundle...")
    if did_web_ca_certs:
        bundle = did_web_ca_certs.read_text()
    else:
        # This uses the Mozilla root program. certifi is the same package that
        # provides roots for eg. the requests and httpx modules.
        bundle = certifi.contents()
    proposal = governance.set_ca_bundle_proposal("did_web_tls_roots", bundle)
    client.governance.propose(proposal, must_pass=True)

    print("Configuring service...")
    url = urlparse(client.url)
    assert url.hostname is not None

    config = {
        "authentication": {"allow_unauthenticated": True},
        "service_identifier": format_did_web(url.hostname, url.port),
    }
    proposal = governance.set_scitt_configuration_proposal(config)
    client.governance.propose(proposal, must_pass=True)

    print("Opening service...")
    network = client.get("node/network").json()
    proposal = governance.transition_service_to_open_proposal(
        network["service_certificate"]
    )
    client.governance.propose(proposal, must_pass=True)
    client.wait_for_network_open()

    if trust_store_dir:
        print(f"Adding service to {trust_store_dir} ...")
        trust_store_dir.mkdir(parents=True, exist_ok=True)
        parameters = client.get_parameters().as_dict()
        service_id = parameters["serviceId"]
        path = trust_store_dir.joinpath(service_id + ".json")
        path.write_text(json.dumps(parameters))


def cli(fn):
    parser = fn(description="Execute governance actions")
    sub = parser.add_subparsers(help="Governance action to execute", required=True)

    p = sub.add_parser("propose_ca_certs")
    add_client_arguments(p, with_member_auth=True)
    add_proposal_arguments(p)
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
    p.set_defaults(
        func=lambda args: execute_action(
            create_client(args),
            propose_root_ca_certs(args.bundle_name, args.ca_certs),
            args,
        )
    )

    p = sub.add_parser("propose_configuration")
    add_client_arguments(p, with_member_auth=True)
    add_proposal_arguments(p)
    p.add_argument(
        "--configuration", type=Path, help="JSON configuration", required=True
    )
    p.set_defaults(
        func=lambda args: execute_action(
            create_client(args),
            propose_configuration(args.configuration),
            args,
        )
    )

    p = sub.add_parser("propose_generic")
    add_client_arguments(p, with_member_auth=True)
    add_proposal_arguments(p, enable_dump_only=False)
    p.add_argument("--proposal-path", type=Path, help="JSON proposal", required=True)
    p.set_defaults(
        func=lambda args: execute_action(
            create_client(args),
            propose_generic(args.proposal_path),
            args,
        )
    )

    p = sub.add_parser("propose_open_service")
    add_client_arguments(p, with_member_auth=True)
    add_proposal_arguments(p)
    p.add_argument(
        "--next-service-certificate",
        type=Path,
        help="Path to next service certificate",
        required=True,
    )
    p.set_defaults(
        func=lambda args: execute_action(
            create_client(args),
            propose_open_service(args.next_service_certificate),
            args,
        )
    )

    p = sub.add_parser(
        "propose_constitution", help="Propose a new service constitution"
    )
    add_client_arguments(p, with_member_auth=True)
    add_proposal_arguments(p)
    p.add_argument(
        "--constitution-file",
        type=Path,
        required=True,
        help="Path to the new constitution",
    )
    p.set_defaults(
        func=lambda args: execute_action(
            create_client(args),
            propose_constitution(args.constitution_file),
            args,
        )
    )

    p = sub.add_parser(
        "update_scitt_constitution",
        help="Update the SCITT component of the service's constitution",
    )
    add_client_arguments(p, with_member_auth=True)
    add_proposal_arguments(p)
    p.add_argument(
        "--scitt-constitution-file",
        type=Path,
        required=True,
        help="Path to the scitt.js file which contains the new SCITT component of the constitution",
    )
    p.add_argument("--yes", action="store_true", help="Do not ask for confirmation")

    def func(args):
        client = create_client(args)
        action = update_scitt_constitution(
            client, args.scitt_constitution_file, args.yes
        )
        execute_action(client, action, args)

    p.set_defaults(func=func)

    p = sub.add_parser("activate_member")
    add_client_arguments(p, with_member_auth=True)
    p.set_defaults(func=lambda args: create_client(args).governance.activate_member())

    p = sub.add_parser(
        "constitution",
        help="Fetch the service's current constitution and write it to a file",
    )
    add_client_arguments(p)
    p.add_argument("--output", type=Path, help="Output file", required=True)
    p.set_defaults(func=lambda args: get_constitution(create_client(args), args.output))

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
