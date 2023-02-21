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
import hashlib
import os
import errno
import uuid
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


def get_queue_dir(url):
    queue_id = hashlib.sha256(url.encode("utf-8")).hexdigest()
    queue_dir = os.path.join(tempfile.gettempdir(), f"scitt-fetch-queue-{queue_id}")
    return queue_dir


def queue_request(url: str, nonce: str, callback_url: str, unattested: bool):
    logging.info(f"Queuing request for {url} (nonce: {nonce}, callback: {callback_url}, unattested: {unattested})")

    queue_dir = get_queue_dir(url)
    request_metadata = {
        "url": url,
        "nonce": nonce,
        "callback_url": callback_url,
        "unattested": unattested,
    }
    request_id = uuid.uuid4().hex
    request_path = os.path.join(queue_dir, f"{request_id}.json")

    # Write the request metadata to a temporary file.
    with tempfile.NamedTemporaryFile(delete=False) as f:
        json.dump(request_metadata, f)

    try:
        while True:
            # Create the queue folder if it doesn't exist yet.
            try:
                os.mkdir(queue_dir)
            except OSError as e:
                if e.errno == errno.EEXIST:
                    is_first = False
                else:
                    raise e
            else:
                logging.info(f"Created queue folder {queue_dir}")
                is_first = True

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
        logging.error(f"Error while queuing request: {e}")
        os.remove(f.name)
        raise e
    
    return is_first


def process_requests(url):
    queue_dir = get_queue_dir(url)

    # TODO: what if this fails? more entries will be queued but never processed

    is_first = True
    while True:
        for fname in os.listdir(queue_dir):
            request_path = os.path.join(queue_dir, fname)
            logging.info(f"Processing request {request_path}")
            with open(request_path) as f:
                request_metadata = json.load(f)
            
            if is_first:
                # Add nonce as query parameter for cache busting.
                # This reduces the time to observe DID document updates
                # for some servers like GitHub Pages.
                url = url + f"?{request_metadata['nonce']}"

                if request_metadata["unattested"]:
                    result = fetch_unattested(url, request_metadata["nonce"])
                else:
                    result = fetch_attested(url, request_metadata["nonce"])
                
                callback_data = {
                    "result": json.loads(result)
                }
            else:
                callback_data = {}
            
            body = json.dumps(callback_data).encode("utf-8")
            headers = {"Content-Type": "application/json"}
            request(request_metadata["callback_url"], body, headers)

            logging.info(f"Removing request {request_path}")
            os.remove(request_path)
            
            is_first = False
        
        try:
            os.rmdir(queue_dir)
        except OSError as e:
            if e.errno == errno.ENOTEMPTY:
                continue
            raise e
        logging.info(f"Removed queue {queue_dir}")
        break


def run(url, nonce, callback_url: str, unattested: bool):
    is_new_url = queue_request(url, nonce, callback_url, unattested)

    # If this is the first request for this URL, process it
    # and all other requests that were queued in the meantime.
    # Processing finishes when the queue is empty and removed.
    if is_new_url:
        process_requests(url)


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
