# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
import time

import pytest

from infra.x5chain_certificate_authority import X5ChainCertificateAuthority
from pyscitt import crypto, governance

X5C_PARAMS = dict(alg="ES256", kty="ec", ec_curve="P-256")


@pytest.fixture(scope="class")
def x5c_ca(client):
    ca = X5ChainCertificateAuthority(**X5C_PARAMS)

    client.governance.propose(
        governance.set_ca_bundle_proposal("x509_roots", ca.cert_bundle),
        must_pass=True,
    )

    return ca


def measure_latency(fn, arg_fn=None):
    if arg_fn is None:

        def arg_fn():
            return None

    times = []
    for _ in range(150):
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
class TestPerf:
    def test_latency(self, client, did_web, x5c_ca):
        payload = {"foo": "bar"}

        client = client.replace(wait_time=0.01, tcp_nodelay_patch=True)

        # Test did:web performance (uncached resolution).
        latency_did_web_uncached_submit_s = measure_latency(
            lambda claim: client.submit_claim(claim, skip_confirmation=True),
            lambda: crypto.sign_json_claimset(did_web.create_identity(), payload),
        )
        latency_did_web_uncached_submit_and_receipt_s = measure_latency(
            lambda claim: client.submit_claim(claim, skip_confirmation=False),
            lambda: crypto.sign_json_claimset(did_web.create_identity(), payload),
        )

        # Test did:web performance (cached resolution).
        identity = did_web.create_identity()
        claim = crypto.sign_json_claimset(identity, payload)

        # Make sure DID document is cached.
        client.submit_claim(claim)

        latency_did_web_cached_submit_s = measure_latency(
            lambda _: client.submit_claim(claim, skip_confirmation=True)
        )
        latency_did_web_cached_submit_and_receipt_s = measure_latency(
            lambda _: client.submit_claim(claim, skip_confirmation=False)
        )

        # Test x5c performance.
        identity = x5c_ca.create_identity(1, **X5C_PARAMS)
        claim = crypto.sign_json_claimset(identity, payload)

        latency_x5c_submit_s = measure_latency(
            lambda _: client.submit_claim(claim, skip_confirmation=True)
        )
        latency_x5c_submit_and_receipt_s = measure_latency(
            lambda _: client.submit_claim(claim, skip_confirmation=False)
        )

        # Time-to-receipt depends on the configured signature interval of
        # the CCF network and is hence just a rough estimate.
        # Uncached did:web resolution uses a local server and is therefore
        # faster than in a real-world scenario.
        stats = {
            "latency_did_web_uncached_submit_s": latency_did_web_uncached_submit_s,
            "latency_did_web_uncached_submit_and_receipt_s": latency_did_web_uncached_submit_and_receipt_s,
            "latency_did_web_cached_submit_s": latency_did_web_cached_submit_s,
            "latency_did_web_cached_submit_and_receipt_s": latency_did_web_cached_submit_and_receipt_s,
            "latency_x5c_submit_s": latency_x5c_submit_s,
            "latency_x5c_submit_and_receipt_s": latency_x5c_submit_and_receipt_s,
        }

        # Write stats to file for further analysis.
        with open("perf.json", "w", encoding="utf-8") as fp:
            json.dump(stats, fp, indent=2)
