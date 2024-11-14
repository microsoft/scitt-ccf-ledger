# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import pytest

from pyscitt import crypto
from pyscitt.client import Client

from . import constants
from .infra.assertions import service_error
from .infra.cchost import CCHost
from .infra.x5chain_certificate_authority import X5ChainCertificateAuthority


@pytest.mark.isolated_test(enable_faketime=True)
def test_purge_old_operations(    
    client: Client,
    cchost: CCHost,
    trusted_ca: X5ChainCertificateAuthority,
    length: int,
    algorithm: str,
    params: dict,
):
    """
    Operations are purged from the service's memory after a while.
    """
    identity = trusted_ca.create_identity(length=length, alg=algorithm, **params)

    claim = crypto.sign_json_claimset(identity, "Payload")

    # Create two operations, such that one will be old enough to be purged but
    # not the other.
    tx1 = client.submit_claim_and_confirm(claim).operation_tx
    cchost.advance_time(seconds=constants.OPERATION_EXPIRY_SECONDS // 2)

    tx2 = client.submit_claim_and_confirm(claim).operation_tx
    cchost.advance_time(seconds=constants.OPERATION_EXPIRY_SECONDS // 2)

    # Just moving time forward doesn't actually do anything yet.
    # For now, both operations are still in memory.
    txs = [o["operationId"] for o in client.get_operations()]
    assert tx1 in txs
    assert tx2 in txs

    # Submit a claim again, just to get the indexing strategy
    # to run. This is what actually triggers a purge.
    client.submit_claim_and_confirm(claim)

    # Now the first operation has actually been purged, but not the second,
    # since that one is only half as old.
    txs = [o["operationId"] for o in client.get_operations()]
    assert tx1 not in txs
    assert tx2 in txs

    # Looking up an expired operation fails deterministically.
    with service_error("OperationExpired: Operation ID is too old"):
        client.wait_for_operation(tx1)

    # We can still look up the one that hasn't expired though.
    client.wait_for_operation(tx2)
