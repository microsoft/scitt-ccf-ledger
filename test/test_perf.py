# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import time
from typing import cast

import pycose
import pytest
from polars import DataFrame

from pyscitt import crypto
from pyscitt.client import Client

from .infra.assertions import service_error
from .infra.bencher import Bencher, Latency
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
    if (details.host_data !== "c71e9f286127f4327a7ddcfb4c6f6f1274a2858172549e10b9e506a19206fd57") {{ return "Invalid host data"; }}

    // Check issuer is valid
    if (!phdr.cwt.iss.startsWith("did:attestedsvc:msft-css-dev:")) {{ return "Invalid issuer"; }}

    return true;
}}
"""

X509_HASHV_POLICY_REGO = f"""
package policy
default allow := false
issuer_allowed if {{
    input.phdr.cwt.iss == "did:x509:0:sha256:HnwZ4lezuxq_GVcl_Sk7YWW170qAD0DZBLXilXet0jg::eku:1.3.6.1.4.1.311.10.3.13"
}}
seconds_since_epoch := time.now_ns() / 1000000000
iat_in_the_past if {{
    input.phdr.cwt.iat < seconds_since_epoch
}}
svn_undefined if {{
    not input.phdr.cwt.svn
}}
svn_positive if {{
    input.phdr.cwt.svn >= 0
}}
allow if {{
    issuer_allowed
    iat_in_the_past
    svn_undefined
}}
allow if {{
    issuer_allowed
    iat_in_the_past
    svn_positive
}}
"""

TEST_POLICY_SCRIPTS = {
    "x509_hashv": X509_HASHV_POLICY_SCRIPT,
    "attested_svc": ATTESTEDSVC_POLICY_SCRIPT,
}

TEST_VECTORS = [
    ("test/payloads/cts-hashv-cwtclaims-b64url.cose", "x509_hashv"),
    ("test/payloads/css-attested-cosesign1-20250812.cose", "attested_svc"),
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


@pytest.mark.bencher
def test_statement_latency_rego(client: Client, configure_service):
    client.wait_time = 0.1
    signed_statement_path = "test/payloads/cts-hashv-cwtclaims-b64url.cose"
    test_name = "x509_hashv"
    configure_service({"policy": {"policyRego": X509_HASHV_POLICY_REGO}})

    with open(signed_statement_path, "rb") as f:
        signed_statement = f.read()

    iterations = 10

    latency_ns = []
    for i in range(iterations):
        start = time.time()
        client.submit_signed_statement(signed_statement)
        latency_ns.append((time.time() - start) * 1_000_000_000)

    df = DataFrame({"latency (ns)": latency_ns})
    print(f"Statement Registration (Rego) {test_name}")
    print(df.describe())

    bf = Bencher()
    bf.set(f"Register Signed Statement (Rego) {test_name}", latency(df))

    latency_ns = []
    for i in range(iterations):
        start = time.time()
        client.submit_signed_statement_and_wait_for_receipt(signed_statement)
        latency_ns.append((time.time() - start) * 1_000_000_000)

    df = DataFrame({"latency (ns)": latency_ns})
    print(f"Statement Receipt Fetching (Rego) {test_name}")
    print(df.describe())

    bf.set(f"Fetch Receipt (Rego) {test_name}", latency(df))
