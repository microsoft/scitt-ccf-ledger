# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Check CCF receipts offline with proofbundle.scitt_ccf (draft -06 profile).

Usage:
    python check.py [--captures DIR] [--require-captures] [--per-capture]

Runs in its own virtual environment with the pinned proofbundle of
requirements.txt (see scripts/proofbundle-check.sh), never in the environment
of the functional tests. It checks, in this order:

1. vectors/*.json: two receipts this ledger issued, unchanged, from
   microsoft/scitt-ccf-ledger#500; each must give the overall status and the
   receipt status it expects.
2. vectors/counter-check/*.json: fixtures with a deliberately wrong
   expectation; each must be reported as a mismatch.
3. With --captures: every receipt and transparent statement recorded by
   capture.py during the functional tests. Only the receipts are judged: each
   must be confirmed. The status of the statement itself (for example a
   statement that is not a hash envelope) is reported as a NOTE, counted per
   kind, and does not change the exit status. The number of key set reloads
   that capture.py logged (reloads.jsonl) is reported as a NOTE as well.
   A receipt recorded without its signed statement, and any error capture.py
   logged in capture-errors.txt, is an ERROR.

stdout: one line per vector, one line per distinct capture result with the
number of captures (--per-capture: one line per capture), and one NOTE line
per kind of statement status; the other lines start with PASS, SKIP, FAIL or
ERROR.
Exit status: 0 if no case is FAIL or ERROR, 1 if any is FAIL, 2 if any is
ERROR or --require-captures finds no confirmed receipt.

Trust shortcuts, for a self-check of the ledger under test only: the statement
signer key is taken from the statement's protected x5chain, the service keys
from the key set the service under test served during the run, the issuer
from the receipt, and the expected payload digest from the statement itself.
None of these is a source of trust outside this check.
"""

import argparse
import importlib.metadata
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from proofbundle.scitt_ccf import (  # type: ignore[import-not-found]
    CONFIRMED,
    ScittFormatError,
    decode_cose_sign1,
    load_cose_keyset,
    verify_transparent_statement,
)

HERE = Path(__file__).resolve().parent
FORMAT = "ccf06-runner-fixture/1"
RECEIPTS_LABEL = 394  # RFC 9943
X5CHAIN_LABEL = 33  # RFC 9360
CWT_LABEL = 15  # RFC 9597


class InputError(Exception):
    pass


# ---------------------------------------------------------------------------
# CBOR heads, enough to place receipts in a statement's unprotected header
# ---------------------------------------------------------------------------


def _head(major: int, argument: int) -> bytes:
    if argument < 24:
        return bytes([major << 5 | argument])
    for additional, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if argument < 1 << (8 * width):
            return bytes([major << 5 | additional]) + argument.to_bytes(width, "big")
    raise InputError("CBOR argument too large")


def _read_head(data: bytes, pos: int) -> Tuple[int, int, int]:
    if pos >= len(data):
        raise InputError("truncated CBOR")
    major, additional = data[pos] >> 5, data[pos] & 31
    if additional < 24:
        return major, additional, pos + 1
    if additional > 27:
        raise InputError("indefinite length or reserved CBOR head")
    width = 1 << (additional - 24)
    if pos + 1 + width > len(data):
        raise InputError("truncated CBOR")
    return (
        major,
        int.from_bytes(data[pos + 1 : pos + 1 + width], "big"),
        pos + 1 + width,
    )


def _item_end(data: bytes, pos: int) -> int:
    """End of the definite-length CBOR item at pos, without decoding it."""
    pending = 1
    while pending:
        major, argument, pos = _read_head(data, pos)
        pending -= 1
        if major in (2, 3):
            pos += argument
        elif major == 4:
            pending += argument
        elif major == 5:
            pending += 2 * argument
        elif major == 6:
            pending += 1
        if pos > len(data):
            raise InputError("truncated CBOR")
    return pos


def assemble(statement: bytes, receipts: List[bytes]) -> bytes:
    """Place receipts as byte strings under label 394 of a Signed Statement.

    The statement's unprotected header is replaced; every other byte is kept.
    """
    major, argument, pos = _read_head(statement, 0)
    if (major, argument) != (6, 18):
        raise InputError("signed statement is not CBOR tag 18 (COSE_Sign1)")
    major, argument, pos = _read_head(statement, pos)
    if (major, argument) != (4, 4):
        raise InputError("signed statement is not an array of four elements")
    major, argument, pos = _read_head(statement, pos)
    if major != 2:
        raise InputError("protected header is not a byte string")
    start = pos + argument
    end = _item_end(statement, start)
    if statement[start] >> 5 != 5:
        raise InputError("unprotected header is not a map")
    header = (
        _head(5, 1)
        + _head(0, RECEIPTS_LABEL)
        + _head(4, len(receipts))
        + b"".join(_head(2, len(r)) + r for r in receipts)
    )
    return statement[:start] + header + statement[end:]


# ---------------------------------------------------------------------------
# Fixtures: vectors/ and vectors/counter-check/
# ---------------------------------------------------------------------------


def _hex(value: Any, name: str) -> bytes:
    if not isinstance(value, str):
        raise InputError(f"{name} must be a hex string")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise InputError(f"{name} is not hex") from exc


def _key(entry: Any, name: str) -> Any:
    if not isinstance(entry, dict) or "spki_hex" not in entry:
        raise InputError(f"{name} entries need spki_hex")
    spki = _hex(entry["spki_hex"], f"{name}.spki_hex")
    if "kid_hex" in entry:
        return {"spki": spki, "kid": _hex(entry["kid_hex"], f"{name}.kid_hex")}
    return spki


def load_fixture(path: Path) -> Dict[str, Any]:
    try:
        fixture = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InputError(f"cannot read: {exc}") from exc
    if not isinstance(fixture, dict) or fixture.get("format") != FORMAT:
        raise InputError(f"format must be {FORMAT}")
    if "transparent_statement_hex" in fixture:
        statement = _hex(
            fixture["transparent_statement_hex"], "transparent_statement_hex"
        )
    else:
        receipts = fixture.get("receipts_hex")
        if not isinstance(receipts, list) or not receipts:
            raise InputError(
                "give transparent_statement_hex, or signed_statement_hex and receipts_hex"
            )
        statement = assemble(
            _hex(fixture.get("signed_statement_hex"), "signed_statement_hex"),
            [_hex(r, "receipts_hex[]") for r in receipts],
        )
    services = fixture.get("trusted_service_keys")
    statement_keys = fixture.get("trusted_statement_keys")
    if not isinstance(statement_keys, list) or not isinstance(services, dict):
        raise InputError(
            "trusted_statement_keys must be a list, trusted_service_keys a map"
        )
    expected = fixture.get("expected")
    if not isinstance(expected, dict) or not isinstance(expected.get("receipts"), list):
        raise InputError("expected needs status and receipts")
    return {
        "id": fixture.get("id", path.stem),
        "statement": statement,
        "digest": _hex(
            fixture.get("expected_payload_digest_hex"), "expected_payload_digest_hex"
        ),
        "rp_trust": {
            "scitt_statement_keys": [
                _key(k, "trusted_statement_keys") for k in statement_keys
            ],
            "scitt_ccf_services": {
                issuer: [_key(k, f"trusted_service_keys[{issuer}]") for k in keys]
                for issuer, keys in services.items()
            },
        },
        "expected_status": expected.get("status"),
        "expected_receipts": expected["receipts"],
    }


def verify(
    statement: bytes, digest: bytes, rp_trust: dict
) -> Tuple[str, List[str], str]:
    result = verify_transparent_statement(
        statement, canonical_root=digest, rp_trust=rp_trust
    )
    detail = result.detail.splitlines()[0] if result.detail else ""
    return result.status, [c.status for c in result.receipts], detail


def shown(status: str, receipts: List[str]) -> str:
    return f"status={status} receipts={','.join(receipts) or '-'}"


def check_vectors(directory: Path, counter: bool) -> List[Tuple[str, str]]:
    lines = []
    for path in sorted(directory.glob("*.json")):
        try:
            fx = load_fixture(path)
            status, receipts, detail = verify(
                fx["statement"], fx["digest"], fx["rp_trust"]
            )
        except InputError as exc:
            lines.append(("ERROR", f"vector {path.name} {exc}"))
            continue
        matches = (
            status == fx["expected_status"] and receipts == fx["expected_receipts"]
        )
        want = shown(fx["expected_status"], fx["expected_receipts"])
        if counter:
            verdict = "FAIL" if matches else "PASS"
            lines.append(
                (
                    verdict,
                    f"counter-check {fx['id']} expected {want} got {shown(status, receipts)}",
                )
            )
        else:
            verdict = "PASS" if matches else "FAIL"
            text = (
                shown(status, receipts)
                if matches
                else f"expected {want} got {shown(status, receipts)} detail={detail!r}"
            )
            lines.append((verdict, f"vector {fx['id']} {text}"))
    return lines


# ---------------------------------------------------------------------------
# Captures from the functional tests
# ---------------------------------------------------------------------------


def _signer_keys(statement: bytes) -> List[bytes]:
    """SPKI of the end-entity certificate in the protected x5chain, if any."""
    try:
        chain = decode_cose_sign1(statement).protected.get(X5CHAIN_LABEL)
    except ScittFormatError:
        return []
    leaf = chain[0] if isinstance(chain, list) and chain else chain
    if not isinstance(leaf, bytes):
        return []
    try:
        cert = x509.load_der_x509_certificate(leaf)
    except ValueError:
        return []
    return [
        cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    ]


def _payload_digest(statement: bytes) -> bytes:
    """The statement's payload if it is a 32-byte digest, else 32 zero bytes."""
    try:
        payload = decode_cose_sign1(statement).payload
    except ScittFormatError:
        return bytes(32)
    return payload if isinstance(payload, bytes) and len(payload) == 32 else bytes(32)


def _services(statement: bytes, keyset: Optional[bytes]) -> Dict[str, list]:
    """The served key set under every issuer named by a receipt of the statement."""
    if keyset is None:
        return {}
    keys = load_cose_keyset(keyset)
    issuers = set()
    try:
        receipts = decode_cose_sign1(statement).unprotected.get(RECEIPTS_LABEL) or []
    except ScittFormatError:
        receipts = []
    for raw in receipts if isinstance(receipts, list) else []:
        try:
            cwt = decode_cose_sign1(raw, role="receipt").protected.get(CWT_LABEL)
        except (ScittFormatError, TypeError):
            continue
        if isinstance(cwt, dict) and isinstance(cwt.get(1), str):
            issuers.add(cwt[1])
    return {issuer: keys for issuer in issuers}


class Notes:
    """Statement statuses other than confirmed, counted per kind.

    A kind is the statement status with its detail, numbers replaced by N
    (not those in names such as "RFC 9995" or "scitt-ccf/v1"); the distinct
    numbers are listed with the kind.
    """

    NUMBER = re.compile(r"(?<![A-Za-z0-9/-])(?<!RFC )-?[0-9]+")

    def __init__(self) -> None:
        self.kinds: Dict[str, List[Any]] = {}

    def add(self, status: str, detail: str) -> None:
        kind = f"{status}: {self.NUMBER.sub('N', detail)}"
        numbers = ",".join(self.NUMBER.findall(detail))
        entry = self.kinds.setdefault(kind, [0, []])
        entry[0] += 1
        if numbers and numbers not in entry[1]:
            entry[1].append(numbers)

    def lines(self) -> List[Tuple[str, str]]:
        out = []
        for kind, (count, values) in self.kinds.items():
            shown_values = (
                " [" + "; ".join(values) + "]"
                if 0 < len(values) <= 3
                else f" [{len(values)} distinct]" if values else ""
            )
            plural = "s" if count > 1 else ""
            out.append(("NOTE", f"{count} statement{plural} {kind}{shown_values}"))
        return out

    def total(self) -> int:
        return sum(count for count, _values in self.kinds.values())


def check_captures(directory: Path, notes: Notes) -> List[Tuple[str, int, str]]:
    """-> (verdict, capture number, text) for every recorded capture.

    Only the receipts are judged. The statement's own status goes to notes.
    """
    results: List[Tuple[str, int, str]] = []
    path = directory / "captures.jsonl"
    if not path.exists():
        return results
    for raw in path.read_text(encoding="utf-8").splitlines():
        capture = json.loads(raw)
        n = capture["n"]
        label = f"{capture['test'] or '-'} {capture['method']}"
        output = bytes.fromhex(capture["output_hex"])
        signed = capture.get("signed_statement_hex")
        try:
            if capture["kind"] == "transparent_statement":
                statement = output
            elif signed:
                statement = assemble(bytes.fromhex(signed), [output])
            else:
                results.append(
                    ("ERROR", n, f"{label} receipt without a recorded signed statement")
                )
                continue
            keyset = None
            if capture.get("keyset_sha256"):
                keyset = (
                    directory / "keys" / f"{capture['keyset_sha256']}.cbor"
                ).read_bytes()
            rp_trust = {
                "scitt_statement_keys": _signer_keys(statement),
                "scitt_ccf_services": _services(statement, keyset),
            }
            result = verify_transparent_statement(
                statement, canonical_root=_payload_digest(statement), rp_trust=rp_trust
            )
        except (InputError, ScittFormatError, OSError, ValueError) as exc:
            results.append(("ERROR", n, f"{label} {type(exc).__name__}: {exc}"))
            continue
        statement_detail = result.detail.splitlines()[0] if result.detail else ""
        if result.statement_status != CONFIRMED:
            notes.add(result.statement_status, statement_detail)
        receipts = [c.status for c in result.receipts]
        if not receipts:
            if result.statement_status == CONFIRMED:
                results.append(("FAIL", n, f"{label} no receipt in the statement"))
            # Otherwise the statement could not be read and its notes entry
            # says so; no receipt was judged.
            continue
        text = f"{label} receipts={','.join(receipts)}"
        if all(r == CONFIRMED for r in receipts):
            results.append(("PASS", n, text))
        else:
            failed = next(c for c in result.receipts if c.status != CONFIRMED)
            results.append(("FAIL", n, f"{text} detail={failed.detail!r}"))
    return results


def read_reloads(directory: Path) -> List[dict]:
    """The key set reloads capture.py logged, see reloads.jsonl."""
    path = directory / "reloads.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def grouped(results: List[Tuple[str, int, str]]) -> List[Tuple[str, str]]:
    """One line per distinct verdict and text, with the number of captures."""
    counts: Dict[Tuple[str, str], int] = {}
    for verdict, _n, text in results:
        counts[(verdict, text)] = counts.get((verdict, text), 0) + 1
    return [
        (verdict, f"{count} capture{'s' if count > 1 else ''} {text}")
        for (verdict, text), count in counts.items()
    ]


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--captures", type=Path, help="directory written by capture.py")
    parser.add_argument("--require-captures", action="store_true")
    parser.add_argument("--vectors", type=Path, default=HERE / "vectors")
    parser.add_argument(
        "--per-capture",
        action="store_true",
        help="one line per capture instead of one per distinct result",
    )
    args = parser.parse_args(argv)

    print(
        f"proofbundle {importlib.metadata.version('proofbundle')}, python {sys.version.split()[0]}",
        file=sys.stderr,
    )
    lines = check_vectors(args.vectors, counter=False)
    lines += check_vectors(args.vectors / "counter-check", counter=True)
    verdicts = [verdict for verdict, _ in lines]
    notes = Notes()
    reloads: List[dict] = []
    if args.captures is not None:
        captured = check_captures(args.captures, notes)
        capture_errors = args.captures / "capture-errors.txt"
        if capture_errors.exists():
            try:
                errors = [
                    line
                    for line in capture_errors.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]
            except (OSError, UnicodeDecodeError) as exc:
                captured.append(("ERROR", 0, f"cannot read capture errors: {exc}"))
            else:
                if errors:
                    captured.append(
                        (
                            "ERROR",
                            0,
                            f"{len(errors)} capture error(s) recorded in {capture_errors}",
                        )
                    )
        if args.require_captures and not any(v == "PASS" for v, _n, _text in captured):
            captured.append(("ERROR", 0, f"no confirmed receipt in {args.captures}"))
        verdicts += [verdict for verdict, _n, _text in captured]
        if args.per_capture:
            lines += [(v, f"capture {n} {text}") for v, n, text in captured]
        else:
            lines += grouped(captured)
        lines += notes.lines()
        reloads = read_reloads(args.captures)
        if reloads:
            found = sum(1 for r in reloads if r.get("kid_found"))
            plural = "s" if len(reloads) != 1 else ""
            lines.append(
                (
                    "NOTE",
                    f"{len(reloads)} key set reload{plural} for a kid not in the"
                    f" key sets read before; kid found afterwards: {found}",
                )
            )
    for verdict, text in lines:
        print(f"{verdict} {text}")
    counts = {v: verdicts.count(v) for v in ("PASS", "SKIP", "FAIL", "ERROR")}
    summary = ", ".join(f"{n} {v}" for v, n in counts.items())
    print(
        f"{summary}; notes, not judged: {notes.total()} statements"
        f" in {len(notes.kinds)} kind{'s' if len(notes.kinds) != 1 else ''};"
        f" key set reloads: {len(reloads)}",
        file=sys.stderr,
    )
    if counts["ERROR"]:
        return 2
    return 1 if counts["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
