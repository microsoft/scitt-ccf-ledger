# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# This script is used to run a perf test on the SCITT CCF Ledger app.
# See ./run_logging_control.sh to obtain a reference point against a simple CCF sample app.
# Note that this script only measures a single REST API endpoint and may
# not reflect a full enduser workflow which may involve receipt fetching as well.

# NOTE: Before running this script, you must start a CCF sandbox.
#       Run this from the repository root: ./start.sh
import os
import subprocess
from pathlib import Path

from infra.fixtures import SCITTFixture
from pyscitt import crypto

CONNECTIONS = 100
THREADS = 2
DURATION = 10


def test_perf(tmp_path: Path):
    wrk = os.environ.get("WRK")
    if wrk is None:
        raise Exception(
            "'wrk' not found, set WRK env variable.\n"
            "Install from https://github.com/wg/wrk"
        )

    with SCITTFixture(tmp_path) as fixture:
        identity = fixture.did_web_server.create_identity()
        claims = crypto.sign_json_claims(identity, {"foo": "bar"})

        # send dummy claims to issuer manually to avoid waiting for DID resolution in benchmark
        receipt = fixture.client.submit_claim(claims, decode=False).receipt

        claims_file = tmp_path / "claims.cose"
        claims_file.write_bytes(claims)

        # create wrk script
        wrk_script = tmp_path / "wrk_cws.lua"
        wrk_script.write_text(
            f'wrk.method = "POST"\n'
            f'wrk.headers["Content-Type"] = "application/cose"\n'
            f'local f = io.open("{claims_file}", "rb")\n'
            f'wrk.body = f:read("*all")'
        )

        endpoint = f"{fixture.service_url}/app/entries"

        # run benchmark with wrk
        wrk_cmd = [
            wrk,
            "-c",
            f"{CONNECTIONS}",
            "-t",
            f"{THREADS}",
            "-d",
            f"{DURATION}",
            "-s",
            wrk_script,
            "--latency",
            endpoint,
        ]
        subprocess.run(wrk_cmd)
