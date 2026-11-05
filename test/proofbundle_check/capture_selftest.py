# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Self-test of the key set handling in capture.py, without a ledger.

Usage, from the repository root in the functional test environment:

    python -m test.proofbundle_check.capture_selftest

Not collected by pytest. A fake service serves key sets that hold only kids;
the receipts hold only a kid in their protected header. That is all
capture.py reads to choose and reload key sets.
"""

import json
import sys
import tempfile
from pathlib import Path
from test.proofbundle_check.capture import KEYS_PATH, Recorder
from typing import Callable, Dict, List, Optional

import cbor2


class FakeResponse:
    def __init__(self, content: bytes) -> None:
        self.content = content

    def raise_for_status(self) -> None:
        pass


class FakeService:
    """Serves /.well-known/scitt-keys with the kids it currently holds."""

    def __init__(self, url: str, kids: List[bytes]) -> None:
        self.url = url
        self.kids = kids
        self.key_requests = 0

    def get(self, path: str) -> FakeResponse:
        assert path == KEYS_PATH
        self.key_requests += 1
        keys = [{1: 2, 2: kid, -1: 2} for kid in self.kids]
        return FakeResponse(cbor2.dumps(keys))


def receipt(kid: bytes) -> bytes:
    protected = cbor2.dumps({1: -35, 4: kid})
    return cbor2.dumps(cbor2.CBORTag(18, [protected, {}, None, b"signature"]))


def keyset_kids(directory: Path, digest: Optional[str]) -> List[bytes]:
    if digest is None:
        return []
    keys = cbor2.loads((directory / "keys" / f"{digest}.cbor").read_bytes())
    return [k[2] for k in keys]


def captures(directory: Path) -> List[Dict]:
    lines = (directory / "captures.jsonl").read_text().splitlines()
    return [json.loads(line) for line in lines]


def reloads(directory: Path) -> List[Dict]:
    path = directory / "reloads.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


def record(recorder: Recorder, service: FakeService, kid: bytes) -> None:
    recorder.write(service, "get_receipt", None, None, receipt(kid))  # type: ignore[arg-type]


def recovery(directory: Path) -> None:
    """The kid is known before a recovery and new after it."""
    service = FakeService("https://service-a", [b"old"])
    recorder = Recorder(directory)
    record(recorder, service, b"old")
    service.kids = [b"new"]
    record(recorder, service, b"new")
    rows = captures(directory)
    assert b"new" in keyset_kids(
        directory, rows[1]["keyset_sha256"]
    ), "new kid not recorded"
    log = reloads(directory)
    assert (
        len(log) == 1 and log[0]["kid_found"]
    ), f"expected one reload that finds the kid: {log}"
    assert service.key_requests == 2, service.key_requests


def still_unknown(directory: Path) -> None:
    """The kid is missing even after the reload: one reload, the kid stays absent."""
    service = FakeService("https://service-b", [b"old"])
    recorder = Recorder(directory)
    record(recorder, service, b"old")
    record(recorder, service, b"other")
    record(recorder, service, b"other")
    rows = captures(directory)
    for row in rows[1:]:
        assert b"other" not in keyset_kids(directory, row["keyset_sha256"])
    log = reloads(directory)
    assert (
        len(log) == 1 and not log[0]["kid_found"]
    ), f"expected one reload without the kid: {log}"
    assert service.key_requests == 2, service.key_requests


def old_receipt_after_recovery(directory: Path) -> None:
    """A receipt signed before the recovery needs no further reload."""
    service = FakeService("https://service-c", [b"old"])
    recorder = Recorder(directory)
    record(recorder, service, b"old")
    service.kids = [b"new"]
    record(recorder, service, b"new")
    record(recorder, service, b"old")
    rows = captures(directory)
    assert b"old" in keyset_kids(directory, rows[2]["keyset_sha256"])
    assert len(reloads(directory)) == 1
    assert service.key_requests == 2, service.key_requests


CASES: List[Callable[[Path], None]] = [
    recovery,
    still_unknown,
    old_receipt_after_recovery,
]


def main() -> int:
    failed = 0
    for case in CASES:
        with tempfile.TemporaryDirectory() as tmp:
            try:
                case(Path(tmp))
            except AssertionError as exc:
                failed += 1
                print(f"FAIL {case.__name__}: {exc}")
            else:
                print(f"PASS {case.__name__}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
