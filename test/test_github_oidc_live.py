# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
import os
from pathlib import Path
from typing import Callable

import httpx
import pytest
from pycose.messages import Sign1Message

from demo.github_actions import policy, sign, smoke_test
from pyscitt.client import Client


def register_fulcio_statement(
    client: Client,
    configure_service: Callable[[dict], None],
    *,
    workflow: str,
    payload: bytes,
    output_dir: Path,
) -> dict[str, str]:
    configure_service(
        {
            "policy": policy.registration_policy(
                policy.FULCIO_ROOT.read_text(), workflow=workflow
            )
        }
    )
    with httpx.Client(timeout=30, follow_redirects=False) as session:
        statement = sign.sign_payload(payload, session, content_type="application/json")
    smoke_test.verify_statement(statement, payload)
    return sign.submit(client, statement, output_dir)


@pytest.mark.skipif(
    os.environ.get("SCITT_LIVE_GITHUB_OIDC") != "1",
    reason="Live GitHub OIDC/Fulcio probe is opt-in and requires a GitHub runner",
)
def test_real_fulcio_statement_to_managed_ledger(cchost, configure_service):
    workflow_ref = os.environ["GITHUB_WORKFLOW_REF"]
    repository = os.environ["GITHUB_REPOSITORY"]
    assert workflow_ref.startswith(
        f"{repository}/.github/workflows/build-test.yml@"
    ), "Live probe must authorize the expected build workflow, not certificate metadata"
    workflow = f"https://github.com/{workflow_ref}"
    payload = (
        Path(__file__).parents[1] / "demo/github_actions/payload.json"
    ).read_bytes()
    output_dir = Path(os.environ["SCITT_GITHUB_OIDC_OUTPUT_DIR"])
    client = Client(
        f"https://127.0.0.1:{cchost.rpc_port}",
        cacert=str(cchost.workspace / "service_cert.pem"),
    )
    try:
        outputs = register_fulcio_statement(
            client,
            configure_service,
            workflow=workflow,
            payload=payload,
            output_dir=output_dir,
        )
    finally:
        client.session.close()
    assert json.loads((output_dir / "submission.json").read_text()) == outputs
    assert (
        Sign1Message.decode(
            (output_dir / "transparent-statement.cose").read_bytes()
        ).payload
        == payload
    )
    print(
        f"Registered Fulcio-backed statement in transaction {outputs['transaction-id']}"
    )
