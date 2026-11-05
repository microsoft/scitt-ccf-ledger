# Optional receipt check with proofbundle

An offline second reader for the receipts this ledger issues. It checks them
with [`proofbundle.scitt_ccf`](https://pypi.org/project/proofbundle/) 6.4.0,
which reads CCF receipts under the CCF receipt profile, draft -06
(draft-ietf-scitt-receipts-ccf-profile-06). It does not change the functional
tests and is not needed to run them.

## What it checks

1. `vectors/*.json`: twelve receipt cases from #500, plus one additional
   `MIX` fixture assembled from an unchanged and a modified receipt. The
   twelve cases are two unchanged receipts (`K23`, `K24`) and five changed
   receipts from each of two days (`F23-1`..`F23-5`, `F24-1`..`F24-5`).
   `MIX` places the unchanged and modified receipts in one statement. Each
   fixture holds its expected overall status and receipt statuses.
2. `vectors/counter-check/*.json`: one fixture with a deliberately wrong
   expectation; the check passes only if it reports the mismatch.
3. With a capture directory: every receipt and transparent statement that the
   functional tests obtained through `pyscitt.client.Client`, recorded by
   `capture.py`. Only the receipts are judged: each must be `confirmed`.
   The status of the statement itself, for example a statement that is not an
   RFC 9995 hash envelope, is printed as a `NOTE` with the number of
   statements per kind and does not change the exit status. A receipt
   recorded without its signed statement and an error that `capture.py`
   logged in `capture-errors.txt` are errors, and so is a capture directory
   without a single confirmed receipt under `--require-captures`, which
   `scripts/proofbundle-check.sh` passes.

`capture.py` reads each service's key set the first time it sees the service.
A receipt whose kid is in none of the key sets read so far for its service,
for example after a recovery gave the service a new identity, makes it read
the key set once more, at most once per kid and service. A kid that the
service still does not serve stays unknown and its receipt fails with
`needs_rp_trust`. Reloads are logged in `reloads.jsonl` and counted in a
`NOTE`.

## How to run

    # vectors only
    scripts/proofbundle-check.sh

    # record receipts during the functional tests, then check them
    PROOFBUNDLE_CHECK=1 SCITT_PROOFBUNDLE_CAPTURE_DIR=/tmp/proofbundle-capture ./run_functional_tests.sh
    scripts/proofbundle-check.sh /tmp/proofbundle-capture

    # self-test of the key set handling in capture.py, in the functional test environment
    python -m test.proofbundle_check.capture_selftest

With `PROOFBUNDLE_CHECK=1`, `run_functional_tests.sh` refuses a capture path
that already exists, so use a new one for each run; it creates the directory
itself (mode 700), and its parent must exist.

`scripts/proofbundle-check.sh` installs `requirements.txt` into a virtual
environment of its own (`venv-proofbundle`): the `scitt` extra pins
`cbor2==6.1.4`, and the functional test environment keeps its own cbor2.

In CI the capture and the check are off by default. Set the repository
variable `PROOFBUNDLE_CHECK` to `1` to run them after the functional tests,
without blocking the job; set `PROOFBUNDLE_CHECK_BLOCKING` to `1` as well to
make the check blocking.

## Trust shortcuts

This is a self-check of the ledger under test. The statement signer key comes
from the statement's protected x5chain, the service keys from the key set the
service under test served during the run (`/.well-known/scitt-keys`, read once
per service and again for an unknown kid), the issuer from the receipt and the expected payload digest from
the statement. None of these is a source of trust outside this check. A
statement that proofbundle cannot read at all leaves its receipt unjudged; it
appears only as a `NOTE`.

## License

`capture.py`, `capture_selftest.py`, `check.py`, `__init__.py` and
`scripts/proofbundle-check.sh` carry the notice this repository requires.
The vectors, the counter-check fixture and this README are MIT licensed,
Copyright (c) 2026 Konrad Gruszka, the same license as proofbundle.
