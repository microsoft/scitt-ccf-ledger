# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import random
from pathlib import Path

from locust import FastHttpUser, events, task

from pyscitt.client import Client

CLIENT_WAIT_TIME = 0.01


@events.init_command_line_parser.add_listener
def init_parser(parser):
    parser.add_argument("--scitt-statements", help="Path to statements directory")
    parser.add_argument(
        "--skip-confirmation",
        help="Whether to skip statements submission confirmation or not",
        action="store_true",
        default=False,
    )


class ScittUser(FastHttpUser):
    abstract = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client = Client(self.host, development=True, wait_time=CLIENT_WAIT_TIME)
        self.request_event = self.environment.events.request

    def trace(self, name, fn):
        common_tags = dict(
            request_type=name,
            name=name,
            response_time=0,
            response_length=0,
            context={**self.context()},
        )
        try:
            fn()
        except Exception as e:
            self.request_event.fire(**common_tags, exception=e)
        else:
            self.request_event.fire(**common_tags, exception=None)


class Submitter(ScittUser):
    def on_start(self):
        claims_dir = self.environment.parsed_options.scitt_statements
        self.skip_confirmation = self.environment.parsed_options.skip_confirmation
        self._signed_statements = []
        for path in Path(claims_dir).glob("*.cose"):
            self._signed_statements.append(path.read_bytes())

    @task
    def submit_signed_statement(self):
        signed_statement = self._signed_statements[
            random.randrange(len(self._signed_statements))
        ]
        self.trace(
            "submit_signed_statement",
            lambda: (
                self.client.submit_signed_statement(signed_statement)
                if self.skip_confirmation
                else self.client.submit_signed_statement_and_wait(signed_statement)
            ),
        )
