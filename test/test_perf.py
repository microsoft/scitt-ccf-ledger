# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import time
from pathlib import Path
from typing import cast

import pytest
from polars import DataFrame

from pyscitt.client import Client

from .infra.bencher import Bencher, Latency, Throughput
from .infra.locust_benchmark import parse_result, run_locust

LOCUST_SUBMIT_ROW = "POST /entries"
X509_HASHV_POLICY_SCRIPT = f"""
export function apply(phdr) {{
// Check exact issuer 
if (phdr.cwt.iss !== "did:x509:0:sha256:HnwZ4lezuxq_GVcl_Sk7YWW170qAD0DZBLXilXet0jg::eku:1.3.6.1.4.1.311.10.3.13") {{ return "Invalid issuer"; }}
if (phdr.cwt.svn === undefined || phdr.cwt.svn < 0) {{ return "Invalid SVN"; }}
if (phdr.cwt.iat === undefined || phdr.cwt.iat > (Math.floor(Date.now() / 1000)) ) {{ return "Invalid iat"; }}

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

PPE_CSS_POLICY_SCRIPT = f"""
export function apply(phdr, uhdr, payload, details) {{
    function check_tcb(ref_product, ref_tcb, reported_tcb) {{
        const ref = ccf.tcbHexToPolicy(ref_product, ref_tcb);
        const reported = ccf.tcbHexToPolicy(ref_product, reported_tcb);
        const fields = ["microcode", "snp", "tee", "boot_loader", "fmc"];
        for (const f of fields) {{
            if (f in ref && reported[f] < ref[f]) {{
                return false;
            }}
        }}
        return true;
    }}

    // Check AMD TCB is valid
    if (details.product_name === "Milan") {{
        if (!check_tcb("00a00f11", "db18000000000004", details.reported_tcb.hexstring)) {{ return "Invalid reported TCB"; }}
    }} else if (details.product_name === "Genoa") {{
        if (!check_tcb("00a10f11", "541700000000000a", details.reported_tcb.hexstring)) {{ return "Invalid reported TCB"; }}
    }} else {{
        return "Unsupported product name";
    }}

    // Check UVM/measurement endorsement is valid
    if (details.uvm_endorsements.did !== "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6.1.4.1.311.76.59.1.2") {{ return "Invalid uvm_endorsements did"; }}
    if (details.uvm_endorsements.feed !== "ContainerPlat-AMD-UVM") {{ return "Invalid uvm_endorsements feed"; }}
    if (details.uvm_endorsements.svn < "103") {{ return "Invalid uvm_endorsements svn"; }}

    // Check host_data is the expected digest of the CCE policy for the issuing service
    if (details.host_data !== "0ee2054606c2af7292607efd12f0745a4a97ca52c92005488ca1de54c4be349e") {{ return "Invalid host data"; }}

    // Check issuer is valid
    if (!phdr.cwt.iss.startsWith("did:attestedsvc:css-cts-ppe:")) {{ return "Invalid issuer"; }}

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

PPE_CSS_POLICY_REGO = f"""
package policy
default allow := false

product_name_valid if {{
    input.attestation.product_name == "Genoa"
}}
reported_tcb_valid if {{
    input.attestation.reported_tcb.hexstring == "541700000000000a"
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
    input.attestation.uvm_endorsements.svn == "104"
}}
uvm_valid if {{
    uvm_did_valid
    uvm_feed_valid
    uvm_svn_valid
}}

host_data_valid if {{
    input.attestation.host_data == "0ee2054606c2af7292607efd12f0745a4a97ca52c92005488ca1de54c4be349e"
}}

issuer_valid if {{
    startswith(input.phdr["CWT Claims"].iss, "did:attestedsvc:css-cts-ppe:")
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
    "ppe_css": PPE_CSS_POLICY_SCRIPT,
    "x509_hashv_rego": X509_HASHV_POLICY_REGO,
    "attested_svc_rego": ATTESTEDSVC_POLICY_REGO,
    "ppe_css_rego": PPE_CSS_POLICY_REGO,
}

TEST_VECTORS = [
    ("test/payloads/cts-hashv-cwtclaims-b64url.cose", "x509_hashv"),
    ("test/payloads/css-attested-cosesign1-20250925.cose", "attested_svc"),
    ("test/payloads/css-attested-cosesign1-20260302.cose", "ppe_css"),
    ("test/payloads/cts-hashv-cwtclaims-b64url.cose", "x509_hashv_rego"),
    ("test/payloads/css-attested-cosesign1-20250925.cose", "attested_svc_rego"),
    ("test/payloads/css-attested-cosesign1-20260302.cose", "ppe_css_rego"),
]


def latency(df: DataFrame) -> Latency:
    return Latency(
        value=cast(float, df["latency (ns)"].mean()),
        high_value=cast(float, df["latency (ns)"].max()),
        low_value=cast(float, df["latency (ns)"].min()),
    )


def run_locust_registration(
    client: Client, signed_statement: bytes, tmp_path: Path
) -> tuple[Throughput, Latency]:
    """
    Drive concurrent Locust users, each repeatedly submitting with
    POST /entries?waitForCommit=true, and return committed registrations per
    second and the per-request latency (p50, with p99 high and min low, in ns).
    """
    statements_dir = tmp_path / "statements"
    statements_dir.mkdir()
    (statements_dir / "signed_statement.cose").write_bytes(signed_statement)

    stats = run_locust(
        client.url,
        tmp_path,
        ["--scitt-statements", str(statements_dir), "--skip-confirmation"],
        LOCUST_SUBMIT_ROW,
    )
    print(f"Locust {LOCUST_SUBMIT_ROW} statistics: {stats}")
    return parse_result(stats)


@pytest.mark.parametrize("signed_statement_path, test_name", TEST_VECTORS)
@pytest.mark.bencher
def test_statement_latency(
    client: Client, configure_service, signed_statement_path: str, test_name: str
):
    """Measure registration latency through global commit and receipt delivery."""
    policy = TEST_POLICIES[test_name]
    policy_config = (
        {"policyRego": policy} if "rego" in test_name else {"policyScript": policy}
    )

    configure_service({"policy": policy_config})

    with open(signed_statement_path, "rb") as f:
        signed_statement = f.read()

    iterations = 50

    latency_ns = []
    for _ in range(iterations):
        start = time.perf_counter_ns()
        client.submit_signed_statement_wait_for_commit(signed_statement)
        latency_ns.append(time.perf_counter_ns() - start)

    df = DataFrame({"latency (ns)": latency_ns})
    print(f"Statement Registration and Receipt {test_name}")
    print(df.describe())

    bf = Bencher()
    bf.set(f"Register Signed Statement and Receive Receipt {test_name}", latency(df))


@pytest.mark.parametrize("signed_statement_path, test_name", TEST_VECTORS)
@pytest.mark.bencher
def test_write_throughput(
    client: Client,
    configure_service,
    tmp_path: Path,
    signed_statement_path: str,
    test_name: str,
):
    """
    Measure committed registrations per second, and their latency, with Locust
    driving concurrent blocking submissions from distributed workers.
    """
    policy = TEST_POLICIES[test_name]
    policy_config = (
        {"policyRego": policy} if "rego" in test_name else {"policyScript": policy}
    )

    configure_service({"policy": policy_config})

    with open(signed_statement_path, "rb") as f:
        signed_statement = f.read()

    throughput, registration_latency = run_locust_registration(
        client, signed_statement, tmp_path
    )

    bf = Bencher()
    label = f"Concurrent Registration {test_name}"
    bf.set(label, throughput)
    bf.set(label, registration_latency)
