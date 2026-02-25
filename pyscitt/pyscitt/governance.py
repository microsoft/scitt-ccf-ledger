# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .client import Client

import base64
import json
from dataclasses import dataclass
from typing import Optional, Union

from . import crypto

CCF_GOV_API_VERSION = "2024-07-01"


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


class ProposalNotAccepted(Exception): ...


class GovernanceClient:
    client: "Client"

    def __init__(self, client: "Client"):
        self.client = client

    @property
    def member_id(self) -> str:
        assert self.client.member_auth is not None
        return crypto.get_cert_fingerprint(self.client.member_auth.cert)

    def _gov_params(self) -> dict:
        return {"api-version": CCF_GOV_API_VERSION}

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
            "/gov/members/proposals:create",
            content=proposal,
            sign_request=True,
            params=self._gov_params(),
        )
        out = response.json()
        result = SubmittedProposal(out["proposalId"], out["proposalState"])
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
            f"/gov/members/proposals/{proposal_id}/ballots/{self.member_id}:submit",
            sign_request=True,
            params=self._gov_params(),
            json={
                "ballot": ballot,
            },
        )

        out = response.json()
        result = SubmittedProposal(out["proposalId"], out["proposalState"])

        if must_pass and not result.is_accepted:
            raise ProposalNotAccepted(
                f"Proposal {result.id} was not accepted: {result.state}"
            )

        return result

    def get_recovery_share(self, key: Optional[crypto.Pem] = None) -> bytes:
        encoded_share = self.client.get(
            f"/gov/recovery/encrypted-shares/{self.member_id}",
            params=self._gov_params(),
        ).json()["encryptedShare"]
        encrypted_share = base64.b64decode(encoded_share)

        if key is not None:
            return crypto.decrypt_recovery_share(key, encrypted_share)
        else:
            return encrypted_share

    def submit_recovery_share(self, share: bytes) -> None:
        self.client.post(
            f"/gov/recovery/members/{self.member_id}:recover",
            sign_request=True,
            params=self._gov_params(),
            json={"share": base64.b64encode(share).decode("ascii")},
        )

    def recover_service(self, encryption_private_key: crypto.Pem) -> None:
        """
        Perform a disaster recovery of the service. This assumes the service
        has a single member.

        https://microsoft.github.io/CCF/release/3.x/operations/recovery.html
        https://microsoft.github.io/CCF/release/3.x/governance/accept_recovery.html
        """
        recovery_share = self.get_recovery_share(encryption_private_key)
        previous_service_identity = self.client.get_previous_service_identity()
        next_service_identity = self.client.get_service_certificate()

        proposal = transition_service_to_open_proposal(
            next_service_identity,
            previous_service_identity,
        )
        self.propose(proposal, must_pass=True)
        self.submit_recovery_share(recovery_share)
        self.client.wait_for_network_open()

    def activate_member(self):
        r = self.client.post(
            f"/gov/members/state-digests/{self.member_id}:update",
            sign_request=True,
            params=self._gov_params(),
        )
        self.client.post(
            f"/gov/members/state-digests/{self.member_id}:ack",
            content=r.content,
            sign_request=True,
            params=self._gov_params(),
        )


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


def transition_service_to_open_proposal(
    next_service_identity: str, previous_service_identity: Optional[str] = None
) -> dict:
    args = {"next_service_identity": next_service_identity}

    if previous_service_identity:
        args["previous_service_identity"] = previous_service_identity

    return {
        "actions": [
            {
                "name": "transition_service_to_open",
                "args": args,
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
