# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import random
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
        claims_dir = self.environment.parsed_options.scitt_statements
        self.skip_confirmation = self.environment.parsed_options.skip_confirmation
        self._signed_statements = []
        for path in Path(claims_dir).glob("*.cose"):
            self._signed_statements.append(path.read_bytes())

    @task
    def submit_signed_statement(self):
        signed_statement = random.choice(self._signed_statements)

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

        self._wait_for_operation(operation_id)

    def _wait_for_operation(self, operation_id):
        with self.client.get(
            f"/operations/{operation_id}",
            name="GET /operations/[id]",
            catch_response=True,
        ) as resp:
            if resp.status_code == 200:
                return
            elif resp.status_code == 202:
                resp.success()  # count as success, will retry
                import gevent

                gevent.sleep(0.01)
                self._wait_for_operation(operation_id)
            else:
                resp.failure(f"Operation poll failed: {resp.status_code}")
