# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import random
import time
from pathlib import Path

import cbor2
from locust import FastHttpUser, events, task

CT_COSE = "application/cose"


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

    @task
    def submit_signed_statement(self):
        start = time.perf_counter()
        exception = None
        signed_statement = random.choice(self._signed_statements)

        try:
            with self.client.post(
                "/entries",
                data=signed_statement,
                headers={"Content-Type": CT_COSE},
                name="POST /entries",
                catch_response=True,
            ) as resp:
                if resp.status_code not in (200, 202):
                    resp.failure(f"Unexpected status {resp.status_code}")
                    return
                if self.skip_confirmation:
                    return

                # Poll for operation completion
                operation = cbor2.loads(resp.content)
                operation_id = operation["OperationId"]

            entry_id = self._wait_for_operation(operation_id)
            if entry_id is not None:
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

    def _wait_for_operation(self, operation_id, max_retries=20):
        import gevent

        for _ in range(max_retries):
            with self.client.get(
                f"/operations/{operation_id}",
                name="GET /operations/[id]",
                catch_response=True,
            ) as resp:
                if resp.status_code == 200:
                    operation = cbor2.loads(resp.content)
                    status = operation.get("Status")
                    if status == "succeeded":
                        return operation.get("EntryId", operation_id)
                    else:
                        resp.failure(f"Operation failed with status: {status}")
                        return None
                elif resp.status_code == 202:
                    # if it is the last retry, report failure instead of success to capture in stats
                    if _ == max_retries - 1:
                        resp.failure("Operation not completed after max retries")
                    else:
                        resp.success()
                else:
                    resp.failure(f"Operation poll failed: {resp.status_code}")
                    return None
            gevent.sleep(0.3 * (_ + 1))
        return None

    def _wait_for_statement(self, entry_id, max_retries=20):
        import gevent

        for _ in range(max_retries):
            with self.client.get(
                f"/entries/{entry_id}/statement",
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
            gevent.sleep(0.3 * (_ + 1))
