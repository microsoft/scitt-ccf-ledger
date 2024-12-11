# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import os
import ssl

import boofuzz  # type: ignore

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
        fuzz_data_logger.log_fail(
            "Response does not contain 'HTTP/1.1 400 BAD_REQUEST'"
        )
        fuzz_data_logger.log_fail("Response: {}".format(response))
        return False

    return True


def test_fuzz_api_submissions_random_payload():
    """
    Generate random payloads and try to register them, each call should return 400 error
    """
    session = boofuzz.Session(
        target=boofuzz.Target(
            connection=boofuzz.SSLSocketConnection(
                host="127.0.0.1", port=8000, sslcontext=do_not_verify_tls
            )
        ),
        post_test_case_callbacks=[response_must_be_400],
        receive_data_after_each_request=False,
        check_data_received_each_request=False,
        receive_data_after_fuzz=False,
        ignore_connection_issues_when_sending_fuzz_data=False,
        ignore_connection_ssl_errors=True,
        reuse_target_connection=False,
        sleep_time=0.002,
        web_port=None,
    )

    # Create a request variable with fuzzable fields
    boofuzz.s_initialize(name="SubmitAny")
    with boofuzz.s_block("Request-Line"):
        boofuzz.s_static("POST /entries HTTP/1.1\r\n")
        boofuzz.s_static(
            "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:65.0) Gecko/20100101 Firefox/65.0\r\n"
        )
        boofuzz.s_static(
            "Accept: text/html,application/json;q=0.9,image/webp,*/*;q=0.8\r\n"
        )
        boofuzz.s_static("Accept-Language: en-US,en;q=0.5\r\n")
        boofuzz.s_static("Accept-Encoding: gzip, deflate\r\n")
        boofuzz.s_static("Content-Type: application/cose\r\n")

        # Add claculated content length
        boofuzz.s_static("Content-Length: ", name="Content-Length-Header")
        boofuzz.s_size(
            "Body-Content",
            output_format="ascii",
            name="Content-Length-Value",
            fuzzable=False,
        )
        boofuzz.s_static("\r\n", "Content-Length-CRLF")

    boofuzz.s_static("\r\n", "Request-CRLF")

    # Add a fuzzable payload
    with boofuzz.s_block("Body-Content"):
        boofuzz.s_delim(b"\xD2", name="COSE tag")
        boofuzz.s_delim(b"\x84", name="CBOR array tag")
        boofuzz.s_string(
            "Body content ...", name="Body-Content-Value", max_len=(1 << 20 - 2)
        )  # 1MB

    test_request = boofuzz.s_get("SubmitAny")
    print("Number of mutations", test_request.num_mutations())
    session.connect(test_request)
    session.fuzz(max_depth=2)


def test_fuzz_api_submissions_cose_payload():
    """
    Randomise parts of the cose envelope and do a successfull submission
    """
    current_dir = os.path.dirname(__file__)

    session = boofuzz.Session(
        target=boofuzz.Target(
            connection=boofuzz.SSLSocketConnection(
                host="127.0.0.1", port=8000, sslcontext=do_not_verify_tls
            )
        ),
        post_test_case_callbacks=[response_must_be_400],
        receive_data_after_each_request=False,
        check_data_received_each_request=False,
        receive_data_after_fuzz=False,
        ignore_connection_issues_when_sending_fuzz_data=False,
        ignore_connection_ssl_errors=True,
        reuse_target_connection=False,
        sleep_time=0.002,
        web_port=None,
    )

    # Create a request variable with fuzzable fields
    boofuzz.s_initialize(name="SubmitCose")
    with boofuzz.s_block("Request-Line"):
        boofuzz.s_static("POST /entries HTTP/1.1\r\n")
        boofuzz.s_static(
            "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:65.0) Gecko/20100101 Firefox/65.0\r\n"
        )
        boofuzz.s_static(
            "Accept: text/html,application/json;q=0.9,image/webp,*/*;q=0.8\r\n"
        )
        boofuzz.s_static("Accept-Language: en-US,en;q=0.5\r\n")
        boofuzz.s_static("Accept-Encoding: gzip, deflate\r\n")
        boofuzz.s_static("Content-Type: application/cose\r\n")
        # Add claculated content length
        boofuzz.s_static("Content-Length: ", name="Content-Length-Header")
        boofuzz.s_size(
            "Body-Content",
            output_format="ascii",
            name="Content-Length-Value",
            fuzzable=False,
        )
        boofuzz.s_static("\r\n", "Content-Length-CRLF")
    boofuzz.s_static("\r\n", "Request-CRLF")

    filepath = os.path.join(current_dir, "payloads/cts-hashv-cwtclaims-b64url.cose")
    print("seeding test cose file for fuzzing", filepath)
    # Add a fuzzable payload
    with boofuzz.s_block("Body-Content"):
        boofuzz.s_from_file(
            filename=filepath, name="Body-Content-Value", fuzzable=True, max_len=1 << 20
        )

    test_request = boofuzz.s_get("SubmitCose")
    print("Number of mutations", test_request.num_mutations())
    session.connect(test_request)
    session.fuzz(max_depth=2)


if __name__ == "__main__":
    test_fuzz_api_submissions_random_payload()
    test_fuzz_api_submissions_cose_payload()
