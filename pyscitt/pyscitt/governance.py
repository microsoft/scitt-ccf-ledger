# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .client import BaseClient

import json
from dataclasses import dataclass
from typing import Optional, Union


@dataclass
class SubmittedProposal:
    id: str
    state: str

    @property
    def is_open(self):
        return self.state == "Open"

    @property
    def is_accepted(self):
        return self.state == "Accepted"


class ProposalNotAccepted(Exception):
    ...


class GovernanceClient:
    client: "BaseClient"

    def __init__(self, client: "BaseClient"):
        self.client = client

    def propose(
        self,
        proposal: Union[dict, bytes],
        *,
        vote: bool = True,
        must_pass: bool = False,
    ) -> SubmittedProposal:
        """
        Submit a proposal to the SCITT CCF instance.

        Depending on the instance's constitution, proposals may not pass immediately and may need
        more members to cast a favourable ballot. The caller should either check this method's
        return value or use the `must_pass` argument before assuming the proposal is effective.

        vote:
            If True and the proposal isn't automatically accepted, an unconditional vote in its
            favour is cast.

        must_pass:
            If True and the proposal fails to pass even after a ballot in its favour is cast, an
            exception is raised.
        """
        assert vote or (not must_pass)

        if isinstance(proposal, dict):
            proposal = json.dumps(proposal).encode("ascii")

        response = self.client.post(
            "/gov/proposals", content=proposal, sign_request=True
        )
        out = response.json()
        result = SubmittedProposal(out["proposal_id"], out["state"])
        if vote and result.is_open:
            result = self.vote(result.id, must_pass=must_pass)

        return result

    def vote(
        self, proposal_id: str, ballot: Optional[str] = None, must_pass: bool = False
    ) -> SubmittedProposal:
        if ballot is None:
            ballot = """
                export function vote (rawProposal, proposerId) {
                    return true;
                }
            """
        response = self.client.post(
            f"/gov/proposals/{proposal_id}/ballots",
            sign_request=True,
            json={
                "ballot": ballot,
            },
        )

        out = response.json()
        result = SubmittedProposal(out["proposal_id"], out["state"])

        if must_pass and not result.is_accepted:
            raise ProposalNotAccepted(
                f"Proposal {result.id} was not accepted: {result.state}"
            )

        return result

    def activate_member(self):
        r = self.client.post("/gov/ack/update_state_digest", sign_request=True)
        self.client.post("/gov/ack", content=r.content, sign_request=True)


def set_scitt_configuration_proposal(configuration: dict) -> dict:
    return {
        "actions": [
            {
                "name": "set_scitt_configuration",
                "args": {
                    "configuration": configuration,
                },
            }
        ]
    }


def set_ca_bundle_proposal(name: str, bundle: str) -> dict:
    return {
        "actions": [
            {
                "name": "set_ca_cert_bundle",
                "args": {"name": name, "cert_bundle": bundle},
            }
        ]
    }


def transition_service_to_open_proposal(next_service_identity: str) -> dict:
    return {
        "actions": [
            {
                "name": "transition_service_to_open",
                "args": {"next_service_identity": next_service_identity},
            }
        ]
    }


def set_constitution_proposal(constitution: str):
    return {
        "actions": [
            {
                "name": "set_constitution",
                "args": {
                    "constitution": constitution,
                },
            }
        ]
    }
