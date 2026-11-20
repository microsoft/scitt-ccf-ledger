# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Record the receipts and transparent statements the functional tests produce.

This pytest plugin is only loaded when the optional proofbundle check is
enabled (PROOFBUNDLE_CHECK=1 in run_functional_tests.sh), as

    pytest -p test.proofbundle_check.capture ./test

It wraps the pyscitt Client methods that return a receipt or a transparent
statement, appends what they returned to SCITT_PROOFBUNDLE_CAPTURE_DIR and
hands the value back unchanged. The first time it sees a service, it reads the
service's /.well-known/scitt-keys, so that the receipts can later be checked
offline by check.py. A receipt whose kid is in none of the key sets read so far
for its service, for example after the service was recovered with a new
identity, makes it read the key set once more, at most once per kid and
service; every such reload is logged in reloads.jsonl. Only key sets that the
service serves are recorded.
"""

import functools
import hashlib
import json
import os
import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import cbor2
import pytest

from pyscitt.client import Client

CAPTURE_DIR_ENV = "SCITT_PROOFBUNDLE_CAPTURE_DIR"
KEYS_PATH = "/.well-known/scitt-keys"
COSE_KID = 4
COSE_KEY_KID = 2
RECEIPTS_LABEL = 394

# Methods whose return value is, or holds, a receipt or a transparent statement.
# The kind says which of the two the returned bytes are.
WRAPPED = {
    "submit_signed_statement_and_wait": "transparent_statement",
    "submit_signed_statement_and_wait_for_receipt": "receipt",
    "submit_signed_statement_wait_for_commit": "receipt",
    "wait_for_entry": "receipt",
    "get_receipt": "receipt",
    "get_transparent_statement": "transparent_statement",
}


def receipt_kids(kind: str, output: bytes) -> List[bytes]:
    """The kid of each receipt in output; empty if it cannot be read."""
    try:
        if kind == "receipt":
            receipts = [output]
        else:
            receipts = cbor2.loads(output).value[1].get(RECEIPTS_LABEL) or []
        kids = []
        for receipt in receipts:
            protected = cbor2.loads(cbor2.loads(receipt).value[0])
            kid = protected.get(COSE_KID)
            if isinstance(kid, bytes):
                kids.append(kid)
        return kids
    except Exception:
        return []


def keyset_kids(data: bytes) -> Set[bytes]:
    """The kids of a COSE_KeySet as served by /.well-known/scitt-keys."""
    try:
        keys = cbor2.loads(data)
    except Exception:
        return set()
    if not isinstance(keys, list):
        return set()
    return {
        k[COSE_KEY_KID]
        for k in keys
        if isinstance(k, dict) and isinstance(k.get(COSE_KEY_KID), bytes)
    }


class Recorder:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        (directory / "keys").mkdir(parents=True, exist_ok=True)
        self.captures = directory / "captures.jsonl"
        self.lock = threading.Lock()
        self.local = threading.local()
        self.test = ""
        self.count = 0
        self.statements: Dict[Tuple[str, str], bytes] = {}
        # Per service URL, the sha256 of each key set read, oldest first.
        self.keysets: Dict[str, List[str]] = {}
        self.kids: Dict[str, Set[bytes]] = {}
        self.reloaded: Set[Tuple[str, bytes]] = set()
        self.originals: Dict[str, Callable[..., Any]] = {}

    def fetch(self, client: Client) -> Optional[str]:
        """Read the service key set, store it, -> its sha256 (None on error)."""
        try:
            response = client.get(KEYS_PATH)
            response.raise_for_status()
            data = response.content
        except Exception:  # the check reports a missing key set
            return None
        digest = hashlib.sha256(data).hexdigest()
        (self.directory / "keys" / f"{digest}.cbor").write_bytes(data)
        with self.lock:
            self.kids[digest] = keyset_kids(data)
            digests = self.keysets.setdefault(client.url, [])
            if digest in digests:
                digests.remove(digest)
            digests.append(digest)
        return digest

    def keyset(self, client: Client, kids: List[bytes]) -> Optional[str]:
        """sha256 of the key set to check these receipts with.

        The newest key set read for the service that holds the first kid. If
        no such key set has been read, the key set is read again, at most once
        per kid and service; a kid that it still lacks stays unknown, and the
        check reports the receipt as needing relying-party trust.
        """
        url = client.url
        with self.lock:
            first_time = url not in self.keysets
            if first_time:
                self.keysets[url] = []
        if first_time:
            self.fetch(client)
        if not kids:
            return self.latest(url)
        kid = kids[0]
        found = self.holding(url, kid)
        if found is not None:
            return found
        with self.lock:
            already = (url, kid) in self.reloaded
            self.reloaded.add((url, kid))
        if already:
            return self.latest(url)
        before = self.latest(url)
        after = self.fetch(client)
        found = self.holding(url, kid)
        self.log_reload(client, kid, before, after, found is not None)
        return found if found is not None else self.latest(url)

    def holding(self, url: str, kid: bytes) -> Optional[str]:
        with self.lock:
            for digest in reversed(self.keysets.get(url, [])):
                if kid in self.kids.get(digest, set()):
                    return digest
        return None

    def latest(self, url: str) -> Optional[str]:
        with self.lock:
            digests = self.keysets.get(url, [])
            return digests[-1] if digests else None

    def log_reload(
        self,
        client: Client,
        kid: bytes,
        before: Optional[str],
        after: Optional[str],
        found: bool,
    ) -> None:
        line = {
            "test": self.test,
            "service_url": client.url,
            "kid_hex": kid.hex(),
            "keyset_before": before,
            "keyset_after": after,
            "kid_found": found,
        }
        with self.lock:
            with (self.directory / "reloads.jsonl").open("a", encoding="utf-8") as f:
                f.write(json.dumps(line, sort_keys=True) + "\n")

    def remember(self, client: Client, tx: str, statement: bytes) -> None:
        with self.lock:
            self.statements[(client.url, tx)] = statement

    def write(
        self,
        client: Client,
        method: str,
        tx: Optional[str],
        statement: Optional[bytes],
        output: bytes,
    ) -> None:
        if statement is None and tx is not None:
            with self.lock:
                statement = self.statements.get((client.url, tx))
        keyset = self.keyset(client, receipt_kids(WRAPPED[method], output))
        with self.lock:
            self.count += 1
            line = {
                "n": self.count,
                "test": self.test,
                "method": method,
                "kind": WRAPPED[method],
                "service_url": client.url,
                "tx": tx,
                "keyset_sha256": keyset,
                "signed_statement_hex": statement.hex() if statement else None,
                "output_hex": output.hex(),
            }
            with self.captures.open("a", encoding="utf-8") as f:
                f.write(json.dumps(line, sort_keys=True) + "\n")

    def wrap(self, name: str) -> None:
        original = getattr(Client, name)
        self.originals[name] = original
        recorder = self

        @functools.wraps(original)
        def wrapper(client: Client, *args: Any, **kwargs: Any) -> Any:
            depth = getattr(recorder.local, "depth", 0)
            recorder.local.depth = depth + 1
            try:
                result = original(client, *args, **kwargs)
            finally:
                recorder.local.depth = depth
            if depth == 0:
                # Only the outermost call is recorded: the submit methods
                # call wait_for_entry and get_transparent_statement themselves.
                try:
                    recorder.record(client, name, args, kwargs, result)
                except Exception as exc:  # never change the test's outcome
                    recorder.error(name, exc)
            return result

        setattr(Client, name, wrapper)

    def record(
        self, client: Client, name: str, args: tuple, kwargs: dict, result: Any
    ) -> None:
        if name.startswith("submit_"):
            statement = args[0] if args else kwargs["signed_statement"]
            self.remember(client, result.tx, statement)
            self.write(client, name, result.tx, statement, result.response_bytes)
        else:
            tx = args[0] if args else kwargs["tx"]
            self.write(client, name, tx, None, result)

    def error(self, name: str, exc: Exception) -> None:
        with self.lock:
            with (self.directory / "capture-errors.txt").open("a") as f:
                f.write(f"{self.test} {name}: {type(exc).__name__}: {exc}\n")

    def wrap_submit_async(self) -> None:
        # submit_signed_statement returns only a transaction ID; remember the
        # statement so that a later get_receipt for that ID can be paired.
        original = Client.submit_signed_statement
        self.originals["submit_signed_statement"] = original
        recorder = self

        @functools.wraps(original)
        def wrapper(client: Client, signed_statement: bytes) -> Any:
            pending = original(client, signed_statement)
            recorder.remember(client, pending.operation_tx, signed_statement)
            return pending

        setattr(Client, "submit_signed_statement", wrapper)

    def unwrap(self) -> None:
        for name, original in self.originals.items():
            setattr(Client, name, original)


_RECORDER: Optional[Recorder] = None


def pytest_configure(config: pytest.Config) -> None:
    global _RECORDER
    directory = os.environ.get(CAPTURE_DIR_ENV)
    if not directory:
        raise pytest.UsageError(
            f"{CAPTURE_DIR_ENV} must be set when the capture plugin is loaded"
        )
    _RECORDER = Recorder(Path(directory))
    for name in WRAPPED:
        _RECORDER.wrap(name)
    _RECORDER.wrap_submit_async()


def pytest_unconfigure(config: pytest.Config) -> None:
    if _RECORDER is not None:
        _RECORDER.unwrap()


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item: pytest.Item) -> None:
    if _RECORDER is not None:
        _RECORDER.test = item.nodeid
