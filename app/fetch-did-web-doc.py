#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import argparse
import base64
import errno
import hashlib
import http
import json
import logging
import os
import ssl
import subprocess
import sys
import tempfile
import time
import uuid
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

CONNECT_TIMEOUT = 5
HTTP_RETRIES = 5
FETCH_RETRIES = 5
HTTP_DEFAULT_RETRY_AFTER = 1

RETRIABLE_STATUS_CODES = {
    http.HTTPStatus.TOO_MANY_REQUESTS,
    http.HTTPStatus.SERVICE_UNAVAILABLE,
}

AFETCH_DIR = "/tmp/scitt"


def refetchable(result):
    """Parse result to decide if it should be refetched."""
    fetch_data = json.loads(result)["data"]
    decoded_data = base64.b64decode(fetch_data)
    data = json.loads(decoded_data)

    if "error" in data:
        logging.error(f"afetch failed: {data['error']['message']}")
        return True
    if "result" in data:
        status = data["result"]["status"]
        logging.info(f"afetch got http response: {status}")
        if status in RETRIABLE_STATUS_CODES:
            return True
    return False


def fetch_attested(url, nonce):
    retries = HTTP_RETRIES
    while retries > 0:
        retries -= 1
        with tempfile.NamedTemporaryFile() as out_path:
            args = [
                f"{AFETCH_DIR}/afetch",
                f"{AFETCH_DIR}/libafetch.enclave.so.signed",
                out_path.name,
                url,
                nonce,
            ]
            logging.info(f"Starting {' '.join(args)}")
            try:
                subprocess.run(
                    args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True
                )
            except subprocess.CalledProcessError as e:
                logging.error(f"afetch failed with code {e.returncode}: {e.stdout}")
                raise e
            except Exception as e:
                logging.error(f"Unknown error: {e}")
                raise e
            with open(out_path.name, "rb") as f:
                result = f.read()
            if not refetchable(result):
                break
        if retries != 0:
            logging.info(f"Retrying afetch in {HTTP_DEFAULT_RETRY_AFTER} seconds")
            time.sleep(HTTP_DEFAULT_RETRY_AFTER)
    logging.info(f"afetch finished, output size is {len(result)} bytes")

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
    while retries >= 0:
        retries -= 1
        try:
            response = urlopen(req, context=ctx, timeout=CONNECT_TIMEOUT)
            status_code = response.getcode()
            logging.info(f"HTTP status {status_code}")
            break
        except HTTPError as e:
            status_code = e.getcode()
            body = e.read()
            retry_after = int(e.headers.get("Retry-After", HTTP_DEFAULT_RETRY_AFTER))
            logging.error(f"HTTP status {status_code}: {body}")
            if status_code not in RETRIABLE_STATUS_CODES:
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


def get_queue_dir(url):
    queue_id = hashlib.sha256(url.encode("utf-8")).hexdigest()
    queue_dir = os.path.join(tempfile.gettempdir(), f"scitt-fetch-queue-{queue_id}")
    return queue_dir


def queue_request(url: str, nonce: str, callback_url: str, callback_context: bytes):
    logging.info(
        f"Queuing request for {url} (nonce: {nonce}, callback: {callback_url})"
    )

    queue_dir = get_queue_dir(url)

    request_metadata = {
        "nonce": nonce,
        "callback_url": callback_url,
        "callback_context": base64.b64encode(callback_context).decode("ascii"),
    }
    request_id = uuid.uuid4().hex
    request_path = os.path.join(queue_dir, f"{request_id}.json")

    # Write the request metadata to a temporary file.
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        json.dump(request_metadata, f)

    try:
        while True:
            # Create the queue folder if it doesn't exist yet.
            try:
                os.mkdir(queue_dir)
            except OSError as e:
                if e.errno == errno.EEXIST:
                    is_new_queue = False
                else:
                    raise e
            else:
                logging.info(f"Created queue folder {queue_dir}")
                is_new_queue = True

            # Move the request file to the queue folder.
            try:
                os.rename(f.name, request_path)
            except OSError as e:
                # If the queue folder was deleted in the meantime, try again.
                if e.errno == errno.ENOENT:
                    continue
                else:
                    raise e
            else:
                logging.info(f"Queued request {request_path}")
            break
    except Exception as e:
        logging.error(f"Error while queuing request", exc_info=e)
        os.remove(f.name)
        raise e

    return is_new_queue


def process_requests(url):
    queue_dir = get_queue_dir(url)

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_queue_dir = os.path.join(tmp_dir, "queue")

        try:
            # Process the first request by doing an actual fetch.
            # The queue folder is not moved yet, so that more requests
            # for the same URL can be queued while the fetch is in progress.
            request_path = os.path.join(queue_dir, os.listdir(queue_dir)[0])
            logging.info(f"Processing first request {request_path}")
            with open(request_path) as f:
                request_metadata = json.load(f)

            # Add nonce as query parameter for cache busting.
            # This reduces the time to observe DID document updates
            # for some servers like GitHub Pages.
            url = url + f"?{request_metadata['nonce']}"

            result = fetch_attested(url, request_metadata["nonce"])

            # Send back the result to the callback URL.
            callback_data = {
                "result": json.loads(result),
                "context": request_metadata["callback_context"],
            }
            body = json.dumps(callback_data).encode("utf-8")
            headers = {"Content-Type": "application/json"}
            request(request_metadata["callback_url"], body, headers)

            # Remove the request file to prevent it from being processed again below.
            os.remove(request_path)

        except Exception as e:
            logging.error(
                f"Error while processing first request in {queue_dir}", exc_info=e
            )
            logging.info(f"Removing queue {queue_dir} and aborting")
            raise
        finally:
            # Move the queue folder to a temporary location that will be deleted and
            # process any remaining requests that were added in the meantime.
            os.rename(queue_dir, tmp_queue_dir)

        for fname in os.listdir(tmp_queue_dir):
            # Process remaining requests by relying on the resolution
            # cache maintained in the ledger KV.
            request_path = os.path.join(tmp_queue_dir, fname)
            logging.info(f"Processing remaining request {request_path}")
            with open(request_path) as f:
                request_metadata = json.load(f)

            callback_data = {
                "context": request_metadata["callback_context"],
            }
            body = json.dumps(callback_data).encode("utf-8")
            headers = {"Content-Type": "application/json"}
            request(request_metadata["callback_url"], body, headers)


def run(url, nonce, callback_url: str, callback_context: bytes):
    is_new_queue = queue_request(url, nonce, callback_url, callback_context)
    if is_new_queue:
        process_requests(url)


if __name__ == "__main__":
    # The logs we print get captured by CCF and included in its own logs.
    # We omit a timestamp since CCF puts its own anyway.
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(levelname)s: %(message)s",
    )

    parser = argparse.ArgumentParser()
    parser.add_argument("url")
    parser.add_argument("nonce")
    parser.add_argument("callback_url")
    args = parser.parse_args()

    callback_context = sys.stdin.buffer.read()
    run(args.url, args.nonce, args.callback_url, callback_context)
