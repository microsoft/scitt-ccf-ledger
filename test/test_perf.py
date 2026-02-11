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
    if (details.host_data !== "73973b78d70cc68353426de188db5dfc57e5b766e399935fb73a61127ea26d20") {{ return "Invalid host data "; }}

    // Check issuer is valid
    if (!phdr.cwt.iss.startsWith("did:attestedsvc:msft-css-dev:")) {{ return "Invalid issuer"; }}

    return true;
}}
"""

X509_HASHV_POLICY_REGO = f"""
package policy
default allow := false

issuer_allowed if {{
    input.phdr["CWT Claims"].iss == "did:x509:0:sha256:HnwZ4lezuxq_GVcl_Sk7YWW170qAD0DZBLXilXet0jg::eku:1.3.6.1.4.1.311.10.3.13"
}}
seconds_since_epoch := time.now_ns() / 1000000000
iat_in_the_past if {{
    input.phdr["CWT Claims"].iat < seconds_since_epoch
}}
svn_positive if {{
    input.phdr["CWT Claims"]._svn >= 0
}}
allow if {{
    issuer_allowed
    iat_in_the_past
    svn_positive
}}

errors contains "Invalid issuer" if {{ not issuer_allowed }}
errors contains "Invalid iat" if {{ not iat_in_the_past }}
errors contains "Invalid SVN" if {{ not svn_positive }}
"""

ATTESTEDSVC_POLICY_REGO = f"""
package policy
default allow := false

product_name_valid if {{
    input.attestation.product_name == "Milan"
}}
reported_tcb_valid if {{
    input.attestation.reported_tcb.hexstring == "db18000000000004"
}}
amd_tcb_valid if {{
    product_name_valid
    reported_tcb_valid
}}

uvm_did_valid if {{
    input.attestation.uvm_endorsements.did == "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6.1.4.1.311.76.59.1.2"
}}
uvm_feed_valid if {{
    input.attestation.uvm_endorsements.feed == "ContainerPlat-AMD-UVM"
}}
uvm_svn_valid if {{
    input.attestation.uvm_endorsements.svn == "101"
}}
uvm_valid if {{
    uvm_did_valid
    uvm_feed_valid
    uvm_svn_valid
}}

host_data_valid if {{
    input.attestation.host_data == "73973b78d70cc68353426de188db5dfc57e5b766e399935fb73a61127ea26d20"
}}

issuer_valid if {{
    startswith(input.phdr["CWT Claims"].iss, "did:attestedsvc:msft-css-dev:")
}}

allow if {{
    amd_tcb_valid
    uvm_valid
    host_data_valid
    issuer_valid
}}

errors contains "Invalid AMD product name" if {{ not product_name_valid }}
errors contains "Invalid reported TCB" if {{ not reported_tcb_valid }}
errors contains "Invalid uvm_endorsements did" if {{ not uvm_did_valid }}
errors contains "Invalid uvm_endorsements feed" if {{ not uvm_feed_valid }}
errors contains "Invalid uvm_endorsements svn" if {{ not uvm_svn_valid }}
errors contains "Invalid host data" if {{ not host_data_valid }}
errors contains "Invalid issuer" if {{ not issuer_valid }}
"""

TEST_POLICIES = {
    "x509_hashv": X509_HASHV_POLICY_SCRIPT,
    "attested_svc": ATTESTEDSVC_POLICY_SCRIPT,
    "x509_hashv_rego": X509_HASHV_POLICY_REGO,
    "attested_svc_rego": ATTESTEDSVC_POLICY_REGO,
}

TEST_VECTORS = [
    ("test/payloads/cts-hashv-cwtclaims-b64url.cose", "x509_hashv"),
    ("test/payloads/css-attested-cosesign1-20250925.cose", "attested_svc"),
    ("test/payloads/cts-hashv-cwtclaims-b64url.cose", "x509_hashv_rego"),
    ("test/payloads/css-attested-cosesign1-20250925.cose", "attested_svc_rego"),
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
    policy = TEST_POLICIES[test_name]
    policy_config = (
        {"policyRego": policy} if "rego" in test_name else {"policyScript": policy}
    )

    configure_service({"policy": policy_config})

    with open(signed_statement_path, "rb") as f:
        signed_statement = f.read()

    iterations = 50

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

    policy = TEST_POLICIES[test_name]
    policy_config = (
        {"policyRego": policy} if "rego" in test_name else {"policyScript": policy}
    )

    configure_service({"policy": policy_config})

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
