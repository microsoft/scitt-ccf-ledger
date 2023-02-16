# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import argparse
import base64
import http
import json
import logging
import ssl
import subprocess
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

CONNECT_TIMEOUT = 5
HTTP_RETRIES = 5
HTTP_DEFAULT_RETRY_AFTER = 1

AFETCH_DIR = "/tmp/scitt"


def fetch_unattested(url, nonce):
    response = request(url)

    result = json.dumps(
        {
            "url": url,
            "nonce": nonce,
            "status_code": response["status_code"],
            "body": base64.b64encode(response["body"]).decode("utf-8"),
        }
    ).encode("utf-8")

    return result


def fetch_attested(url, nonce):
    retries = HTTP_RETRIES
    with tempfile.NamedTemporaryFile() as out_path:
        args = [
            f"{AFETCH_DIR}/afetch",
            f"{AFETCH_DIR}/libafetch.enclave.so.signed",
            out_path.name,
            url,
            nonce,
        ]
        logging.info(f"Starting {' '.join(args)}")
        while True:
            retries -= 1
            try:
                subprocess.run(
                    args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True
                )
                break
            except subprocess.CalledProcessError as e:
                logging.error(f"afetch failed with code {e.returncode}: {e.stdout}")
            except Exception as e:
                logging.error(f"Unknown error: {e}")
            if retries >= 0:
                logging.info(f"Retrying in {HTTP_DEFAULT_RETRY_AFTER} seconds")
                time.sleep(HTTP_DEFAULT_RETRY_AFTER)
            else:
                raise e
        with open(out_path.name, "rb") as f:
            result = f.read()
        logging.info(f"afetch succeeded, output size is {len(result)} bytes")

    return result


def request(url, data=None, headers=None):
    logging.info(f"Requesting {url}")
    if headers is None:
        headers = {}
    req = Request(url, data, headers)
    # Transport-level security is not required here as the content
    # sent back to CCF is signed by the attested-fetch enclave through
    # hardware attestation. Because of that, we can safely disable
    # certificate validation and don't have to deal with CCF's self-signed certs.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    retries = HTTP_RETRIES
    success = False
    status_code = 0
    body = b""
    while not success and retries >= 0:
        retries -= 1
        try:
            response = urlopen(req, context=ctx, timeout=CONNECT_TIMEOUT)
            status_code = response.getcode()
            body = response.read()
            success = True
            logging.info(f"HTTP status {status_code}")
            break
        except HTTPError as e:
            status_code = e.getcode()
            body = e.read()
            retry_after = int(e.headers.get("Retry-After", HTTP_DEFAULT_RETRY_AFTER))
            logging.error(f"HTTP status {status_code}: {body}")
            if status_code not in [
                http.HTTPStatus.TOO_MANY_REQUESTS,
                http.HTTPStatus.SERVICE_UNAVAILABLE,
            ]:
                break
        except URLError as e:
            retry_after = HTTP_DEFAULT_RETRY_AFTER
            logging.error(f"Network error: {e.reason}")
        except Exception as e:
            retry_after = HTTP_DEFAULT_RETRY_AFTER
            logging.error(f"Unknown error: {e}")
        if retries >= 0:
            logging.info(f"Retrying in {retry_after} seconds")
            time.sleep(retry_after)
    return {
        "success": success,
        "status_code": status_code,
        "body": body,
    }


def run(url, nonce, callback_url: str, unattested: bool):
    if unattested:
        result = fetch_unattested(url, nonce)
    else:
        result = fetch_attested(url, nonce)

    headers = {"Content-Type": "application/json"}
    request(callback_url, result, headers)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s.%(msecs)03d %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    parser = argparse.ArgumentParser()
    parser.add_argument("url")
    parser.add_argument("nonce")
    parser.add_argument("callback_url")
    parser.add_argument("--unattested", action="store_true")
    args = parser.parse_args()

    run(args.url, args.nonce, args.callback_url, args.unattested)
