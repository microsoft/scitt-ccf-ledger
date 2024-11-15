# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
import time

import pytest

from pyscitt import crypto

DEFAULT_ITERATIONS_NUM = 10
CLIENT_WAIT_TIME = 0.01


def measure_latency(fn, arg_fn=None, n=DEFAULT_ITERATIONS_NUM):
    if arg_fn is None:

        def arg_fn():
            return None

    times = []
    for _ in range(n):
        arg = arg_fn()
        t_start = time.perf_counter()
        fn(arg)
        t_end = time.perf_counter()
        times.append(t_end - t_start)
    return {
        "avg": sum(times) / len(times),
        "p99": sorted(times)[int(len(times) * 0.99)],
        "min": min(times),
        "max": max(times),
    }


@pytest.mark.perf
@pytest.mark.disable_proxy
class TestPerf:
    def test_latency(self, client, did_web, trusted_ca):
        payload = {"foo": "bar"}

        client = client.replace(wait_time=CLIENT_WAIT_TIME)

        # Test x5c performance.
        identity = trusted_ca.create_identity(
            length=1, alg="ES256", kty="ec", ec_curve="P-256"
        )
        claim = crypto.sign_json_claimset(identity, payload)

        latency_x5c_submit_s = measure_latency(lambda _: client.submit_claim(claim))
        latency_x5c_submit_and_receipt_s = measure_latency(
            lambda _: client.submit_claim_and_confirm(claim)
        )

        # Time-to-receipt depends on the configured signature interval of
        # the CCF network and is hence just a rough estimate.
        # Uncached did:web resolution uses a local server and is therefore
        # faster than in a real-world scenario.
        stats = {
            "latency_x5c_submit_s": latency_x5c_submit_s,
            "latency_x5c_submit_and_receipt_s": latency_x5c_submit_and_receipt_s,
        }

        # Write stats to file for further analysis.
        with open("perf.json", "w", encoding="utf-8") as fp:
            json.dump(stats, fp, indent=2)
