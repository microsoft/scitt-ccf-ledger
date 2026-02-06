# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import cast

import pycose
import pytest
from polars import DataFrame

from pyscitt import crypto
from pyscitt.client import Client

from .infra.assertions import service_error
from .infra.bencher import Bencher, Latency, Throughput
from .infra.x5chain_certificate_authority import X5ChainCertificateAuthority

X509_HASHV_POLICY_SCRIPT = f"""
export function apply(phdr) {{
// Check exact issuer 
if (phdr.cwt.iss !== "did:x509:0:sha256:HnwZ4lezuxq_GVcl_Sk7YWW170qAD0DZBLXilXet0jg::eku:1.3.6.1.4.1.311.10.3.13") {{ return "Invalid issuer"; }}
if (phdr.cwt.svn === undefined || phdr.cwt.svn < 0) {{ return "Invalid SVN"; }}
if (phdr.cwt.iat === undefined || phdr.cwt.iat < (Math.floor(Date.now() / 1000)) ) {{ return "Invalid iat"; }}

return true;
}}"""

ATTESTEDSVC_POLICY_SCRIPT = f"""
export function apply(phdr, uhdr, payload, details) {{
    // Check AMD TCB is valid
    if (details.product_name != "Milan") {{ return "Invalid AMD product name"; }}
    if (details.reported_tcb.hexstring !== "db18000000000004") {{ return "Invalid reported TCB"; }}

    // Check UVM/measurement endorsement is valid
    if (details.uvm_endorsements.did !== "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6.1.4.1.311.76.59.1.2") {{ return "Invalid uvm_endorsements did"; }}
    if (details.uvm_endorsements.feed !== "ContainerPlat-AMD-UVM") {{ return "Invalid uvm_endorsements feed"; }}
    if (details.uvm_endorsements.svn < "101") {{ return "Invalid uvm_endorsements svn"; }}

    // Check host_data is the expected digest of the CCE policy for the issuing service
    if (details.host_data !== "73973b78d70cc68353426de188db5dfc57e5b766e399935fb73a61127ea26d20") {{ return "Invalid host data"; }}

    // Check issuer is valid
    if (!phdr.cwt.iss.startsWith("did:attestedsvc:msft-css-dev:")) {{ return "Invalid issuer"; }}

    return true;
}}
"""

TEST_POLICY_SCRIPTS = {
    "x509_hashv": X509_HASHV_POLICY_SCRIPT,
    "attested_svc": ATTESTEDSVC_POLICY_SCRIPT,
}

TEST_VECTORS = [
    ("test/payloads/cts-hashv-cwtclaims-b64url.cose", "x509_hashv"),
    ("test/payloads/css-attested-cosesign1-20250925.cose", "attested_svc"),
]


def latency(df: DataFrame) -> Latency:
    return Latency(
        value=cast(float, df["latency (ns)"].mean()),
        high_value=cast(float, df["latency (ns)"].max()),
        low_value=cast(float, df["latency (ns)"].min()),
    )


@pytest.mark.parametrize("signed_statement_path, test_name", TEST_VECTORS)
@pytest.mark.bencher
def test_statement_latency(
    client: Client, configure_service, signed_statement_path: str, test_name: str
):
    client.wait_time = 0.1
    policy_script = TEST_POLICY_SCRIPTS[test_name]

    configure_service({"policy": {"policyScript": policy_script}})

    with open(signed_statement_path, "rb") as f:
        signed_statement = f.read()

    iterations = 10

    latency_ns = []
    for i in range(iterations):
        start = time.time()
        client.submit_signed_statement(signed_statement)
        latency_ns.append((time.time() - start) * 1_000_000_000)

    df = DataFrame({"latency (ns)": latency_ns})
    print(f"Statement Registration {test_name}")
    print(df.describe())

    bf = Bencher()
    bf.set(f"Register Signed Statement {test_name}", latency(df))

    latency_ns = []
    for i in range(iterations):
        start = time.time()
        client.submit_signed_statement_and_wait_for_receipt(signed_statement)
        latency_ns.append((time.time() - start) * 1_000_000_000)

    df = DataFrame({"latency (ns)": latency_ns})
    print(f"Statement Receipt Fetching {test_name}")
    print(df.describe())

    bf.set(f"Fetch Receipt {test_name}", latency(df))


@pytest.mark.parametrize("signed_statement_path, test_name", TEST_VECTORS)
@pytest.mark.bencher
def test_write_throughput(
    client: Client, configure_service, signed_statement_path: str, test_name: str
):
    """
    Measure how many submissions can be made per second using concurrent
    requests over a fixed time window.
    """
    client.wait_time = 0.001
    policy_script = TEST_POLICY_SCRIPTS[test_name]

    configure_service({"policy": {"policyScript": policy_script}})

    with open(signed_statement_path, "rb") as f:
        signed_statement = f.read()

    duration_s = 30
    max_workers = 16
    warmup_requests = max_workers
    lock = threading.Lock()
    completed_count = 0
    errors = 0
    last_error = None
    stop = False

    def _submit():
        nonlocal completed_count, errors, last_error
        while not stop:
            try:
                client.submit_signed_statement(signed_statement)
                with lock:
                    completed_count += 1
            except Exception as e:
                with lock:
                    errors += 1
                    last_error = e

    # Warmup: establish connections and warm caches before measuring
    for _ in range(warmup_requests):
        client.submit_signed_statement(signed_statement)

    start = time.monotonic()
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(_submit) for _ in range(max_workers)]
        time.sleep(duration_s)
        stop = True
        for fut in futures:
            fut.result()  # propagate any unexpected exceptions
    elapsed = time.monotonic() - start

    submissions_per_second = completed_count / elapsed
    error_rate = errors / max(completed_count + errors, 1)

    print(f"Throughput {test_name}: {completed_count} submissions in {elapsed:.2f}s")
    print(f"  Rate: {submissions_per_second:.2f} submissions/s")
    print(f"  Errors: {errors} ({error_rate:.1%})")
    if last_error:
        print(f"  Last error: {last_error}")

    assert error_rate < 0.01, (
        f"Error rate too high: {error_rate:.1%} ({errors}/{completed_count + errors}). "
        f"Last error: {last_error}"
    )
    assert submissions_per_second > 0, "No successful submissions"

    bf = Bencher()
    bf.set(
        f"Throughput {test_name}",
        Throughput(value=submissions_per_second),
    )
