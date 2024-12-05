# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import boofuzz
import ssl
from .infra.fixtures import ManagedCCHostFixtures
from .infra.cchost import get_default_cchost_path, get_enclave_path
from pathlib import Path
from loguru import logger as LOG


do_not_verify_tls = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
do_not_verify_tls.check_hostname = False
do_not_verify_tls.verify_mode = ssl.CERT_NONE

def response_must_be_400(target, fuzz_data_logger, session, *args, **kwargs):
    try:
        response = target.recv(10000)
    except:
        fuzz_data_logger.log_fail("Unable to connect. Target is down.")
        return False
    
    # check response contains a substring foobar
    if b"HTTP/1.1 400 BAD_REQUEST" not in response:
        fuzz_data_logger.log_fail("Response does not contain 'HTTP/1.1 400 BAD_REQUEST'")
        fuzz_data_logger.log_fail("Response: {}".format(response))
        return False
    
    return True


def test_fuzz_api_submissions_random_payload():
    # Create a session and a target to fuzz
    session = boofuzz.Session(
        target=boofuzz.Target(
            connection=boofuzz.SSLSocketConnection(host="127.0.0.1", port=8000, sslcontext=do_not_verify_tls)
        ),
        post_test_case_callbacks=[response_must_be_400],
        receive_data_after_each_request = False,
        check_data_received_each_request = False,
        receive_data_after_fuzz = False,
        ignore_connection_issues_when_sending_fuzz_data = False,
        ignore_connection_ssl_errors= True,
        reuse_target_connection= False,
        sleep_time = 0.01,
    )

    # Create a request variable with fuzzable fields
    boofuzz.s_initialize(name="SubmitAny")
    with boofuzz.s_block("Request-Line"):
        boofuzz.s_static("POST /entries HTTP/1.1\r\n")
        boofuzz.s_static("User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:65.0) Gecko/20100101 Firefox/65.0\r\n")
        boofuzz.s_static("Accept: text/html,application/json;q=0.9,image/webp,*/*;q=0.8\r\n")
        boofuzz.s_static("Accept-Language: en-US,en;q=0.5\r\n")
        boofuzz.s_static("Accept-Encoding: gzip, deflate\r\n")
        boofuzz.s_static("Content-Type: application/cose\r\n")

        # Add claculated content length
        boofuzz.s_static("Content-Length: ", name="Content-Length-Header")
        boofuzz.s_size("Body-Content", output_format="ascii", name="Content-Length-Value", fuzzable=False)
        boofuzz.s_static("\r\n", "Content-Length-CRLF")
    
    boofuzz.s_static("\r\n", "Request-CRLF")

    # Add a fuzzable payload
    with boofuzz.s_block("Body-Content"):
        boofuzz.s_delim(b'\xD2', name="COSE tag")
        boofuzz.s_delim(b'\x84', name="CBOR array tag")
        boofuzz.s_string("Body content ...", name="Body-Content-Value", max_len=(1<<20 - 2)) # 1MB

    # Add a defined request to the session
    session.connect(boofuzz.s_get("SubmitAny"))
    
    # Execute the fuzzing session with all of the session request tests
    session.fuzz(max_depth=1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--start-cchost",
        action="store_true",
        help="Start a cchost process managed by the test framework",
    )
    parser.add_argument(
        "--enclave-package",
        default="/tmp/scitt/lib/libscitt",
        help="The enclave package to load.",
    )
    parser.add_argument(
        "--constitution",
        type=Path,
        default="/tmp/scitt/share/scitt/constitution",
        help="Path to the directory containing the constitution.",
    )
    args = parser.parse_args()

    if args.start_cchost:
        platform = 'virtual'
        enclave_package = args.enclave_package
        binary = get_default_cchost_path(platform)
        constitution = args.constitution
        enclave_file = get_enclave_path(platform, enclave_package)
        mccf = ManagedCCHostFixtures(
            binary,
            platform,
            enclave_file,
            constitution,
            False,
            None,
        )
        cchost = mccf.start_cchost(None)
    
    test_fuzz_api_submissions_random_payload()

    