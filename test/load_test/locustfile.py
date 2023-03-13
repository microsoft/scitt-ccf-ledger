# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import random
from pathlib import Path

from locust import User, events, task

from pyscitt.client import Client


@events.init_command_line_parser.add_listener
def init_parser(parser):
    parser.add_argument("--scitt-claims", help="Path to claims directory")


class ScittUser(User):
    abstract = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client = Client(self.host, development=True)
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
        claims_dir = self.environment.parsed_options.scitt_claims
        self._claims = []
        for path in Path(claims_dir).glob("*.cose"):
            self._claims.append(path.read_bytes())

    @task
    def submit_claim(self):
        claim = self._claims[random.randrange(len(self._claims))]
        self.trace("submit_claim", lambda: self.client.submit_claim(claim))
