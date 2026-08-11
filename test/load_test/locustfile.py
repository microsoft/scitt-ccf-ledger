# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import random
import time
from http import HTTPStatus
from pathlib import Path

import cbor2
from locust import FastHttpUser, events, task

CT_COSE = "application/cose"

# The api-version has to be sent for the service to answer a waitForCommit
# submission with the COSE receipt, rather than with the legacy operation body.
SCITT_API_VERSION = "2026-03-26"

# Submitting with waitForCommit makes POST /entries return once the transaction
# is committed, so the operation does not have to be polled afterwards.
SUBMIT_PATH = f"/entries?waitForCommit=true&api-version={SCITT_API_VERSION}"
SUBMIT_NAME = "POST /entries"

# COSE_Sign1 unprotected header label carrying the CCF inclusion proofs, and
# the label of the proof list within it.
COSE_INCLUSION_PROOFS_LABEL = 396
COSE_INCLUSION_PROOF_KEY = -1

# Keys of the CCF inclusion proof: the leaf components, of which the second one
# is the internal evidence holding the registration transaction ID.
INCLUSION_PROOF_LEAF_KEY = 1


@events.init_command_line_parser.add_listener
def init_parser(parser):
    parser.add_argument("--scitt-statements", help="Path to statements directory")
    parser.add_argument(
        "--skip-confirmation",
        action="store_true",
        default=False,
    )


class Submitter(FastHttpUser):
    def on_start(self):
        # Allow 503 responses to flow through to catch_response handlers
        # instead of being raised as exceptions by geventhttpclient, which
        # fails when trying to decode the binary CBOR response body as UTF-8.
        self.client.client.valid_response_codes = frozenset(
            self.client.client.valid_response_codes | {503}
        )
        claims_dir = self.environment.parsed_options.scitt_statements
        self.skip_confirmation = self.environment.parsed_options.skip_confirmation
        self._signed_statements = []
        for path in Path(claims_dir).glob("*.cose"):
            self._signed_statements.append(path.read_bytes())

    def _reconnect(self):
        """
        Drop the pooled connection so the next request opens a new one.

        When the service is a cluster behind an L4 load balancer, balancing
        happens per connection: every request sent over a kept-alive connection
        is served by the same node. Historical state is fetched and cached per
        node, so a retry is only worth making against a different node. Closing
        the connection lets the load balancer route the next attempt elsewhere,
        which is what a client would do in production.
        """
        try:
            self.client.client.close()
        except Exception:
            pass

    @staticmethod
    def _extract_tx_id(receipt):
        """
        Get the registration transaction ID out of a COSE receipt.

        The receipt is a COSE_Sign1 whose unprotected header holds the CCF
        inclusion proof. The second component of the proof leaf is the internal
        evidence, which is a colon separated string whose second field is the
        registration transaction ID. This mirrors how pyscitt's
        verify_transparent_statement extracts regtxid.
        """
        msg = cbor2.loads(receipt)
        if isinstance(msg, cbor2.CBORTag):
            msg = msg.value

        uhdr = msg[1]
        inclusion_proofs = uhdr[COSE_INCLUSION_PROOFS_LABEL][COSE_INCLUSION_PROOF_KEY]
        proof = cbor2.loads(inclusion_proofs[0])
        leaf = proof[INCLUSION_PROOF_LEAF_KEY]
        internal_evidence = leaf[1]

        return internal_evidence.split(":")[1]

    @task
    def submit_signed_statement(self):
        start = time.perf_counter()
        exception = None
        signed_statement = random.choice(self._signed_statements)

        try:
            # The submission is synchronous: the response is only sent once the
            # transaction commits, and carries the receipt. A backup answers
            # with a 307 pointing at the primary, which is followed
            # transparently, in the same way pyscitt follows it.
            with self.client.post(
                SUBMIT_PATH,
                data=signed_statement,
                headers={"Content-Type": CT_COSE},
                name=SUBMIT_NAME,
                catch_response=True,
            ) as resp:
                if resp.status_code != HTTPStatus.CREATED:
                    resp.failure(f"Unexpected status {resp.status_code}")
                    return

                try:
                    if not self.skip_confirmation:
                        entry_id = self._extract_tx_id(resp.content)
                    else:
                        entry_id = None
                except Exception as e:
                    resp.failure(f"No transaction ID in the receipt: {e}")
                    return

            if not self.skip_confirmation:
                self._wait_for_statement(entry_id)
        except Exception as e:
            exception = e
        finally:
            elapsed = time.perf_counter() - start
            self.environment.events.request.fire(
                request_type="TASK",
                name="submit_signed_statement",
                response_time=elapsed * 1000,
                response_length=len(signed_statement),
                response=None,
                exception=exception,
                context={},
            )

    def _wait_for_statement(self, entry_id, max_retries=20):
        import gevent

        for _ in range(max_retries):
            with self.client.get(
                f"/entries/{entry_id}/statement?api-version={SCITT_API_VERSION}",
                name="GET /entries/[id]/statement",
                catch_response=True,
            ) as resp:
                if resp.status_code == 200:
                    return
                elif resp.status_code == 503:
                    # if it is the last retry, report failure instead of success to capture in stats
                    if _ == max_retries - 1:
                        resp.failure("Statement not available after max retries")
                    else:
                        resp.success()
                else:
                    resp.failure(f"Statement poll failed: {resp.status_code}")
                    return
            # The first couple of attempts stay on the same connection, since a
            # transaction is normally cached within a second of being asked for.
            # Beyond that the node is unlikely to resolve it, so move to another.
            if _ >= 1:
                self._reconnect()
            gevent.sleep(0.3 * (_ + 1))
