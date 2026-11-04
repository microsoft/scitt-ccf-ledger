# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import venv
from pathlib import Path
from urllib.parse import urlsplit


def write_outputs(outputs: dict[str, str]) -> None:
    if any("\n" in value or "\r" in value for value in outputs.values()):
        raise ValueError("Action outputs must not contain newlines")
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
        for name, value in outputs.items():
            stream.write(f"{name}={value}\n")


def venv_executables(directory: Path) -> tuple[Path, Path]:
    if sys.platform == "win32":
        return directory / "Scripts/python.exe", directory / "Scripts/scitt.exe"
    return directory / "bin/python", directory / "bin/scitt"


def setup() -> None:
    output_root = os.environ["SCITT_OUTPUT_DIR"]
    if "\n" in output_root or "\r" in output_root:
        raise ValueError("Action output paths must not contain newlines")
    parent = Path(output_root).resolve()
    parent.mkdir(parents=True, exist_ok=True)
    directory = Path(
        tempfile.mkdtemp(prefix="scitt-sign-", dir=os.environ["RUNNER_TEMP"])
    )
    venv.create(directory, with_pip=True)
    python, scitt = venv_executables(directory)
    subprocess.run(
        [
            str(python),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--quiet",
            str(Path(__file__).resolve().parents[3] / "pyscitt"),
        ],
        check=True,
    )
    output_directory = Path(tempfile.mkdtemp(prefix="statement-", dir=parent))
    write_outputs(
        {
            "python": str(python),
            "scitt": str(scitt),
            "output-dir": str(output_directory),
        }
    )


def sign() -> None:
    url = urlsplit(os.environ["SCITT_LEDGER_URL"])
    if (
        url.scheme != "https"
        or not url.hostname
        or url.username is not None
        or url.password is not None
        or url.fragment
    ):
        raise ValueError("Ledger URL must use HTTPS without credentials or fragment")
    subprocess.run(
        [
            os.environ["SCITT_CLI"],
            "sign-gha-fulcio",
            f"--statement={os.environ['SCITT_FILE']}",
            f"--content-type={os.environ['SCITT_CONTENT_TYPE']}",
            f"--out={Path(os.environ['SCITT_OUTPUT_DIR']) / 'signed-statement.cose'}",
        ],
        check=True,
    )


def submit() -> None:
    directory = Path(os.environ["SCITT_OUTPUT_DIR"])
    arguments = ["--url", os.environ["SCITT_LEDGER_URL"]]
    if os.environ["SCITT_SERVICE_CA"]:
        arguments.append(f"--cacert={os.environ['SCITT_SERVICE_CA']}")
    subprocess.run(
        [
            os.environ["SCITT_CLI"],
            "submit",
            *arguments,
            f"--transparent-statement={directory / 'transparent-statement.cose'}",
            "--",
            str(directory / "signed-statement.cose"),
        ],
        check=True,
    )


def verify() -> None:
    import cbor2

    from pyscitt.client import Client

    directory = Path(os.environ["SCITT_OUTPUT_DIR"])
    with tempfile.TemporaryDirectory(
        prefix="scitt-trust-", dir=os.environ["RUNNER_TEMP"]
    ) as trust_directory:
        client = Client(
            os.environ["SCITT_LEDGER_URL"],
            cacert=os.environ["SCITT_SERVICE_CA"] or None,
        )
        try:
            keys = client.get_scitt_keys()
        finally:
            client.session.close()
        (Path(trust_directory) / "scitt-keys.cbor").write_bytes(cbor2.dumps(keys))
        verification = subprocess.run(
            [
                os.environ["SCITT_CLI"],
                "validate",
                f"--service-trust-store={trust_directory}",
                f"--expected-payload={os.environ['SCITT_FILE']}",
                "--offline",
                "--output=json",
                "--",
                str(directory / "transparent-statement.cose"),
            ],
            stdout=subprocess.PIPE,
            text=True,
        )
        print(verification.stdout, end="", flush=True)
        verification.check_returncode()

    result = json.loads(verification.stdout)
    if not isinstance(result, dict) or result.get("transparent") is not True:
        raise ValueError("The statement was not verified as transparent")
    receipts = result.get("receipts")
    if (
        not isinstance(receipts, list)
        or len(receipts) != 1
        or not isinstance(receipts[0], dict)
    ):
        raise ValueError("Expected one verified ledger receipt")
    transaction_id = receipts[0].get("registration_txid")
    if not isinstance(transaction_id, str) or not re.fullmatch(
        r"[0-9]+\.[0-9]+", transaction_id
    ):
        raise ValueError(
            "Verification output has an invalid registration transaction ID"
        )
    write_outputs(
        {
            "transaction-id": transaction_id,
            "signed-statement": str((directory / "signed-statement.cose").resolve()),
            "transparent-statement": str(
                (directory / "transparent-statement.cose").resolve()
            ),
        }
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["setup", "sign", "submit", "verify"])
    command = parser.parse_args().command
    try:
        {"setup": setup, "sign": sign, "submit": submit, "verify": verify}[command]()
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.returncode) from None


if __name__ == "__main__":
    main()
