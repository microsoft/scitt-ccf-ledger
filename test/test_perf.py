import json
import time

import pytest

from infra.x5chain_certificate_authority import X5ChainCertificateAuthority
from pyscitt import crypto, governance


@pytest.fixture(scope="class")
def x5c_ca(client):
    ca = X5ChainCertificateAuthority(alg="ES256", kty="ec", ec_curve="P-256")

    client.governance.propose(
        governance.set_ca_bundle_proposal("x509_roots", ca.cert_bundle),
        must_pass=True,
    )

    return ca


def measure_latency(f):
    times = []
    for _ in range(150):
        t_start = time.perf_counter()
        f()
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

        # Test did:web performance.
        identity = did_web.create_identity()
        claims = crypto.sign_json_claimset(identity, payload)

        # Make sure DID document is cached.
        client.submit_claim(claims)

        latency_did_web_submit_s = measure_latency(
            lambda: client.submit_claim(
                claims, skip_confirmation=True, decode=False, wait_time=0
            )
        )
        latency_did_web_submit_and_receipt_s = measure_latency(
            lambda: client.submit_claim(
                claims, skip_confirmation=False, decode=False, wait_time=0
            )
        )

        # Test x5c performance.
        identity = x5c_ca.create_identity(1, alg="ES256")
        claims = crypto.sign_json_claimset(identity, payload)

        latency_x5c_submit_s = measure_latency(
            lambda: client.submit_claim(
                claims, skip_confirmation=True, decode=False, wait_time=0
            )
        )
        latency_x5c_submit_and_receipt_s = measure_latency(
            lambda: client.submit_claim(
                claims, skip_confirmation=False, decode=False, wait_time=0
            )
        )

        # Note: Time-to-receipt depends on the configured signature interval of
        # the CCF network and is hence just a rough estimate.
        stats = {
            "latency_did_web_submit_s": latency_did_web_submit_s,
            "latency_did_web_submit_and_receipt_s": latency_did_web_submit_and_receipt_s,
            "latency_x5c_submit_s": latency_x5c_submit_s,
            "latency_x5c_submit_and_receipt_s": latency_x5c_submit_and_receipt_s,
        }

        # Write stats to file for further analysis.
        with open("perf.json", "w", encoding="utf-8") as fp:
            json.dump(stats, fp, indent=2)
