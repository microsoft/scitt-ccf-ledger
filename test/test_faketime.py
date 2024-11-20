# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import time

import pytest

from pyscitt import crypto
from pyscitt.client import Client
from pyscitt.verify import TrustStore, verify_receipt

from .infra.cchost import CCHost


@pytest.mark.isolated_test(enable_faketime=True)
def test_faketime(
    client: Client,
    cchost: CCHost,
):
    """
    Check that we are able to manipulate the service's clock.
    """
    before = client.get("/time").json()
    cchost.advance_time(seconds=3600)

    # cchost updates the time every 1ms, so don't go too fast or we might miss it
    time.sleep(0.010)
    after = client.get("/time").json()

    assert after - before >= 3600
    # Make sure we're in the right ball-park. This assumes the test takes less
    # than 60 seconds to execute, which seems reasonable.
    assert after - before < 3660
