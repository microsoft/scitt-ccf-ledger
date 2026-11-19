# Request logging

SCITT retains its existing `::START::` / `::END::` messages and space-separated
`Stage`, `Verb`, `Path`, `Query`, `URL`, `Status`, optional `Code`/`TxId`,
`TimeMs`, and request-ID fields. Matched SCITT handlers retain their route
template in `Path`; `URL` retains the requested URL. A wrapped request emits
one `START Stage=MAIN` and one final `END Stage=MAIN`, even if CCF retries it.
If CCF invokes its local-commit hook, the existing `END Stage=POSTCOMMIT`
record with `TxId` is retained. Both END stages are emitted at final completion,
in MAIN/POSTCOMMIT order, and report the same final response status and duration
from the initial request attempt, rather than a provisional handler status.
No TPAL-specific identity, denial, or transaction-size fields are added.

The implementation follows [TPAL PR 551](https://github.com/microsoft/TPAL/pull/551)
(`f816bee`), adapted to SCITT's format:

| Case | SCITT completion |
| --- | --- |
| Wrapped success or application error | START and final MAIN END; POSTCOMMIT END if locally committed |
| Missing, invalid, untrusted, or claim-rejected JWT | MAIN END with 401 and the existing `Code=InvalidAuthenticationInfo`; correlated reason at DEBUG, no duplicate INFO denial |
| Unknown route, unsupported verb, OPTIONS | MAIN END only, with 404, 405, or 204 |
| Unwrapped CCF endpoint in the application registry | MAIN END without START; POSTCOMMIT if its hook runs |
| Handler/framework exception or framework status override | END uses CCF's final status; request-ID headers are restored if CCF cleared them |
| Transaction conflicts or exhausted retries | One ID and START across attempts, then final END(s); attempt-local error/commit state is reset |
| Redirect to primary | Follower MAIN END with 307; followed primary execution logs separately |
| Internal forwarding | No false successful follower END; primary logs local execution |
| Direct/redirected `waitForCommit` | END(s) wait for the consensus callback's final status |
| Internally forwarded `waitForCommit` | Synchronous END(s); CCF does not invoke that callback on forwarded responses |
| Endpoint/allowed-verb lookup exception | MAIN END with 500, clear the synchronous scope, then rethrow |
| Unscoped readiness/backpressure rejection | Existing INFO `DispatchFailedEvent: <path> <status>`, escaped and capped, no invented END |
| Unscoped completion | INFO `RequestCompletedEvent: status=<status>, scope=unavailable`, no invented IDs |
| Missing/mismatched scope or occupied RPC user data | Error diagnostic; handlers, authentication and consensus callbacks still execute; foreign data is not overwritten |
| Consensus callback throws `std::exception` | Error diagnostic and final 500 CBOR `InternalError`, rather than closing the session without a response |

The last row intentionally adopts TPAL's response-behavior change, not merely
its logging. SCITT retains its existing CBOR error format. Timing failures are
diagnosed without replacing the application's response; unavailable durations
use `TimeMs=-1`.

Request state belongs to the RPC, not the worker thread. A weak thread-local
bridge associates CCF's synchronous registry events with that RPC; asynchronous
consensus callbacks capture the owned state and restore any intervening log
correlation when finished. Response headers echo the original client ID.
Logged path/query values are capped at 1,024 bytes each, URL at 2,048 bytes and
client ID at 128 bytes, including `...[truncated]`. Whitespace, control and
non-ASCII bytes are percent-escaped so values cannot inject SCITT fields or
lines. Existing URL escapes and ordinary colons are preserved. Limits apply
after escaping and do not split generated escapes or change the request.

HTTP parsing, transport and request-size rejections before application lookup
remain CCF diagnostics. Asynchronous internal-forwarding timeouts still cannot
produce an application END/504 or restored response IDs. Lookup exceptions
produce an END, but CCF's outer error response cannot preserve these headers.
The node and governance registries are outside SCITT's application registry.
TPAL's certificate/role/hook authorization, impersonation, private-ledger query
redaction and decoded `contentsBytes` have no SCITT equivalent and are not added.

Regression coverage is in `app/unit-tests/tracing_test.cpp` and
`test/test_tracing.py`; both are included in the existing native/functional test
suites.
