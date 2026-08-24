#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Launches a multi-node SCITT CCF cluster for local development and load
# testing. Normally invoked as `NODE_COUNT=3 ./docker/run-dev.sh`.
#
# Like run-dev.sh, this configures the network in a way that is NOT suitable
# for production: it generates an ad-hoc governance member key pair, disables
# API authentication and sets a permissive policy.
#
# All nodes share the host network namespace, as run-dev.sh does, and are
# addressed on consecutive ports. This keeps a single address (localhost:PORT)
# valid for clients on the host and for peer nodes alike, which matters because
# CCF uses the same published address for client redirects and for peer
# snapshot fetches.
#
# Clients are expected to talk to the nginx round robin load balancer which
# listens on CCF_PORT, mirroring the production deployment. The nodes
# themselves are on the ports above it.

set -e
set -o pipefail

echo "Starting a $NODE_COUNT node CCF network for development and functional testing."

if ! command -v python &> /dev/null && ! command -v python3.12 &> /dev/null; then
    echo "Neither python nor python3.12 could be found."
    echo "On Azure Linux, run: tdnf install python3.12"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo "jq could not be found. On Azure Linux, run: tdnf install jq"
    exit 1
fi

NODE_COUNT=${NODE_COUNT:-3}
if [ "$NODE_COUNT" -lt 2 ]; then
    echo "NODE_COUNT must be at least 2, use docker/run-dev.sh for a single node."
    exit 1
fi

CCF_HOST=${CCF_HOST:-"localhost"}
# Port the load balancer listens on, and therefore the address clients use.
# Node 0 takes the port above it and subsequent nodes use consecutive ports.
CCF_PORT=${CCF_PORT:-8000}
# Node-to-node port of the first node. Subsequent nodes use consecutive ports.
CCF_NODE_PORT=${CCF_NODE_PORT:-8100}

# Round robin load balancer in front of the nodes. Set to 0 to expose the nodes
# only. Passive health checks take a node out of rotation after
# LB_MAX_FAILS failed connections and put it back after LB_FAIL_TIMEOUT.
LOAD_BALANCER=${LOAD_BALANCER:-1}
LB_IMAGE=${LB_IMAGE:-"nginx:stable-alpine"}
LB_MAX_FAILS=${LB_MAX_FAILS:-1}
LB_FAIL_TIMEOUT=${LB_FAIL_TIMEOUT:-"5s"}
LB_CONNECT_TIMEOUT=${LB_CONNECT_TIMEOUT:-"2s"}
# A waitForCommit submission holds its connection open for the whole commit
# latency, so the proxy must not time the session out sooner than the client.
LB_PROXY_TIMEOUT=${LB_PROXY_TIMEOUT:-"300s"}

DOCKER_TAG=${DOCKER_TAG:-"scitt"}
CLUSTER_NAME=${CLUSTER_NAME:-"scitt-dev-$(date +%s)"}

WORKSPACE=${WORKSPACE:-"workspace/"}

VOLUME_NAME="${CLUSTER_NAME}-vol"

# Resources per node. The single node dev setup uses 1 CPU, which is far too
# little to drive a meaningful load test.
CPUS_PER_NODE=${CPUS_PER_NODE:-2}
MEMORY_PER_NODE=${MEMORY_PER_NODE:-2g}
WORKER_THREADS=${WORKER_THREADS:-1}

# Latency and throughput tuning. The defaults target a sustained write load
# with an end to end commit latency (waitForCommit=true) below 100ms.
#
# A transaction is only committed once a subsequent signature transaction has
# been replicated and acknowledged by a majority, so SIG_DELAY and SIG_TX_COUNT
# bound the commit latency directly.
#
# SIG_TX_COUNT is the more important of the two under load. Only requests that
# are in flight can be uncommitted, so a value above the client concurrency can
# never be reached and latency falls back to the SIG_DELAY timer. Keeping it
# small also keeps a signature's batch inside the 20,000 byte append_entries
# limit (hardcoded in CCF), so the batch replicates in a single message.
SIG_DELAY=${SIG_DELAY:-"100ms"}
SIG_TX_COUNT=${SIG_TX_COUNT:-10}

# Whether joining nodes bootstrap from a snapshot of the primary. Left off,
# because a node which joins from a snapshot has no ledger below the snapshot
# seqno and cannot serve historical queries such as GET /entries/{txid}: the
# receipt lookup needs the ledger secrets, which are derived by reading back to
# seqno 1. Replaying the whole ledger instead is cheap for a development
# cluster and means every node can serve every read.
JOIN_FROM_SNAPSHOT=${JOIN_FROM_SNAPSHOT:-false}

# SNP attestation config
SNP_ATTESTATION_CONFIG=${SNP_ATTESTATION_CONFIG:-}

node_name() {
    echo "${CLUSTER_NAME}-node$1"
}

node_rpc_port() {
    echo $((CCF_PORT + 1 + $1))
}

lb_name() {
    echo "${CLUSTER_NAME}-lb"
}

lb_url() {
    echo "https://${CCF_HOST}:${CCF_PORT}"
}

node_to_node_port() {
    echo $((CCF_NODE_PORT + $1))
}

node_url() {
    echo "https://${CCF_HOST}:$(node_rpc_port "$1")"
}

function cleanup() {
    if [ "${KEEP_CLUSTER:-0}" = "1" ]; then
        echo "KEEP_CLUSTER=1, leaving containers and volume in place."
        echo "Tear down with: docker rm -f \$(docker ps -aq --filter name=${CLUSTER_NAME}) && docker volume rm $VOLUME_NAME"
        return
    fi
    docker stop "$(lb_name)" > /dev/null 2>&1 || true
    docker rm "$(lb_name)" > /dev/null 2>&1 || true
    for ((i = 0; i < NODE_COUNT; i++)); do
        docker stop "$(node_name "$i")" > /dev/null 2>&1 || true
        docker rm "$(node_name "$i")" > /dev/null 2>&1 || true
    done
    docker volume rm "$VOLUME_NAME" > /dev/null 2>&1 || true
}

trap cleanup EXIT

rm -rf "$WORKSPACE"
mkdir -p "$WORKSPACE"

cp -r ./app/constitution "$WORKSPACE"

echo "Generate keys"
KEYGEN=$(pwd)/docker/keygenerator.sh
pushd "$WORKSPACE" > /dev/null
$KEYGEN --name member0 --gen-enc-key
popd > /dev/null

echo "Generate node configurations"
for ((i = 0; i < NODE_COUNT; i++)); do
    NAME=$(node_name "$i")
    RPC_PORT=$(node_rpc_port "$i")
    N2N_PORT=$(node_to_node_port "$i")
    mkdir -p "$WORKSPACE/$NAME"

    if [ "$i" -eq 0 ]; then
        COMMAND=$(cat <<EOF
{
    "type": "Start",
    "service_certificate_file": "/host/service_cert.pem",
    "start": {
      "constitution_files": [
        "/host/constitution/validate.js",
        "/host/constitution/apply.js",
        "/host/constitution/resolve.js",
        "/host/constitution/actions.js",
        "/host/constitution/scitt.js"
      ],
      "members": [
        {
          "certificate_file": "/host/member0_cert.pem",
          "encryption_public_key_file": "/host/member0_enc_pubk.pem"
        }
      ],
      "cose_signatures": {
        "issuer": "${CCF_HOST}:${CCF_PORT}",
        "subject": "scitt.ccf.signature.v1"
      }
    }
  }
EOF
        )
    else
        COMMAND=$(cat <<EOF
{
    "type": "Join",
    "service_certificate_file": "/host/service_cert.pem",
    "join": {
      "retry_timeout": "1s",
      "target_rpc_address": "${CCF_HOST}:$(node_rpc_port 0)",
      "fetch_recent_snapshot": ${JOIN_FROM_SNAPSHOT}
    }
  }
EOF
        )
    fi

    cat > "$WORKSPACE/$NAME/config.json" <<EOF
{
  "network": {
    "node_to_node_interface": {
      "bind_address": "0.0.0.0:${N2N_PORT}",
      "published_address": "${CCF_HOST}:${N2N_PORT}"
    },
    "rpc_interfaces": {
      "interface_name": {
        "bind_address": "0.0.0.0:${RPC_PORT}",
        "published_address": "${CCF_HOST}:${RPC_PORT}",
        "http_configuration": {"max_body_size": "2MB"},
        "redirections": {
          "to_primary": {"kind": "NodeByRole", "target": {"role": "primary"}}
        }
      }
    }
  },
  "node_certificate": {
    "subject_alt_names": [
      "iPAddress:0.0.0.0",
      "iPAddress:127.0.0.1",
      "dNSName:localhost",
      "dNSName:${CCF_HOST}"
    ]
  },
  "ledger": {
    "directory": "/host/${NAME}/ledger"
  },
  "snapshots": {
    "directory": "/host/${NAME}/snapshots"
  },
  "output_files": {
    "node_certificate_file": "/host/${NAME}/node.pem",
    "pid_file": "/host/${NAME}/node.pid",
    "node_to_node_address_file": "/host/${NAME}/node.node_address",
    "rpc_addresses_file": "/host/${NAME}/node.rpc_addresses"
  },
  "ledger_signatures": {
    "tx_count": ${SIG_TX_COUNT},
    "delay": "${SIG_DELAY}"
  },
  "worker_threads": ${WORKER_THREADS},
  "command": ${COMMAND}
}
EOF

    if [ -n "$SNP_ATTESTATION_CONFIG" ]; then
        if [ ! -f "$SNP_ATTESTATION_CONFIG" ]; then
            echo "Error: SNP_ATTESTATION_CONFIG is set to '$SNP_ATTESTATION_CONFIG' but the file does not exist."
            exit 1
        fi
        SNP_ATTESTATION_CONTENT=$(jq '.' "$SNP_ATTESTATION_CONFIG")
        jq --argjson content "$SNP_ATTESTATION_CONTENT" '.attestation = $content' \
            "$WORKSPACE/$NAME/config.json" > "$WORKSPACE/$NAME/config.json.tmp"
        mv "$WORKSPACE/$NAME/config.json.tmp" "$WORKSPACE/$NAME/config.json"
    fi
done

if [ "$LOAD_BALANCER" = "1" ]; then
    echo "Generate load balancer configuration"
    # Layer 4 (TCP) proxying, so the TLS session is established end to end with
    # a node and clients keep validating the CCF service certificate. It also
    # leaves member client certificate authentication untouched, which
    # terminating TLS at the proxy would break.
    #
    # nginx balances new *connections* round robin. Requests are only spread
    # evenly if clients open several connections, which they do under load
    # since each in-flight waitForCommit submission occupies one.
    #
    # Health checking is passive, as active checks are not in nginx OSS: a node
    # which refuses a connection is taken out of rotation for LB_FAIL_TIMEOUT
    # and the connection is retried against the next node.
    {
        cat <<EOF
worker_processes auto;
error_log /dev/stderr notice;
pid /tmp/nginx.pid;

events {
    worker_connections 2500;
}

stream {
    upstream ccf_nodes {
        # Shared state, so the rotation is even across worker processes rather
        # than each worker balancing independently.
        zone ccf_nodes 64k;
EOF
        for ((i = 0; i < NODE_COUNT; i++)); do
            echo "        server ${CCF_HOST}:$(node_rpc_port "$i") max_fails=${LB_MAX_FAILS} fail_timeout=${LB_FAIL_TIMEOUT};"
        done
        cat <<EOF
    }

    server {
        listen ${CCF_PORT};
        proxy_pass ccf_nodes;
        proxy_connect_timeout ${LB_CONNECT_TIMEOUT};
        proxy_timeout ${LB_PROXY_TIMEOUT};
        proxy_next_upstream on;
        proxy_next_upstream_tries ${NODE_COUNT};
    }
}
EOF
    } > "$WORKSPACE/nginx.conf"
fi

echo "Create a volume to store the workspace"
docker volume create "$VOLUME_NAME" > /dev/null

echo "Copy the workspace to the volume"
# Note that this requires a temporary container to mount the volume.
# `docker cp` is used rather than piping a tar into the container, because the
# image contains neither `tar` nor a usable package manager to install it with.
# The container is only created, never started, which is enough for `docker cp`
# to write through to the mounted volume.
COPY_HELPER=$(docker create -v "$VOLUME_NAME":/host --entrypoint "" "$DOCKER_TAG" true)
docker cp "$WORKSPACE"/. "$COPY_HELPER":/host
docker rm "$COPY_HELPER" > /dev/null

# Determine networking flags. All nodes share one network namespace so that
# every node is reachable on the same address from the host and from its peers.
DOCKER_FLAGS=()
if [ "$DOCKER_IN_DOCKER" = "1" ]; then
    # This assumes that the container we're running in
    # wasn't started with a custom hostname.
    DOCKER_FLAGS+=("--network=container:$(hostname)")
else
    DOCKER_FLAGS+=("--network=host")
fi

# Expose the SEV-SNP guest device when running on SNP hardware, so that the
# node can request an attestation report from the firmware. Only the nodes need
# it, not the load balancer.
NODE_DOCKER_FLAGS=()
if [ -e /dev/sev-guest ]; then
    NODE_DOCKER_FLAGS+=("--device=/dev/sev-guest")
fi

start_node() {
    local i=$1
    local name
    name=$(node_name "$i")

    echo "Starting $name on $(node_url "$i") (cpus=$CPUS_PER_NODE, memory=$MEMORY_PER_NODE)"
    docker run --name "$name" \
        -d \
        "${DOCKER_FLAGS[@]}" \
        "${NODE_DOCKER_FLAGS[@]+"${NODE_DOCKER_FLAGS[@]}"}" \
        --cpus="$CPUS_PER_NODE" \
        --memory="$MEMORY_PER_NODE" \
        -v "$VOLUME_NAME":/host \
        --entrypoint "cchost" \
        "$DOCKER_TAG" --config "/host/${name}/config.json" > /dev/null
}

start_lb() {
    local name
    name=$(lb_name)

    echo "Starting load balancer $name on $(lb_url), forwarding to $NODE_COUNT nodes"
    docker run --name "$name" \
        -d \
        "${DOCKER_FLAGS[@]}" \
        -v "$VOLUME_NAME":/host \
        --entrypoint "nginx" \
        "$LB_IMAGE" -c /host/nginx.conf -g "daemon off;" > /dev/null
}

wait_for_node() {
    local url=$1
    local name=$2
    local timeout=30
    while ! curl -s -f -k "$url"/node/network > /dev/null; do
        echo "Waiting for $name to start..."
        sleep 1
        timeout=$((timeout - 1))
        if [ $timeout -eq 0 ]; then
            echo "$name failed to start, exiting"
            echo "Docker logs:"
            docker logs "$name"
            exit 1
        fi
    done
}

CCF_URL=$(node_url 0)

start_node 0

echo "Setting up python virtual environment."
if [ ! -f "venv/bin/activate" ]; then
    if command -v python &> /dev/null; then
        PYTHON=python
    elif command -v python3.12 &> /dev/null; then
        PYTHON=python3.12
    else
        echo "Neither python nor python3.12 is available. Please install one of them."
        exit 1
    fi
    $PYTHON -m venv "venv"
fi

# shellcheck disable=SC1091
source venv/bin/activate
echo "Using pip index URL: ${PIP_INDEX_URL:-default}"
pip install --disable-pip-version-check -q -e ./pyscitt

wait_for_node "$CCF_URL" "$(node_name 0)"

scitt governance local_development \
    --url "$CCF_URL" \
    --member-key "$WORKSPACE"/member0_privk.pem \
    --member-cert "$WORKSPACE"/member0_cert.pem

for ((i = 1; i < NODE_COUNT; i++)); do
    start_node "$i"
done

scitt governance trust_local_nodes \
    --url "$CCF_URL" \
    --member-key "$WORKSPACE"/member0_privk.pem \
    --member-cert "$WORKSPACE"/member0_cert.pem \
    --node-count "$NODE_COUNT"

echo
echo "SCITT is running with $NODE_COUNT nodes:"
for ((i = 0; i < NODE_COUNT; i++)); do
    wait_for_node "$(node_url "$i")" "$(node_name "$i")"
    echo "  $(node_name "$i"): $(node_url "$i")"
done

if [ "$LOAD_BALANCER" = "1" ]; then
    # Started once every node is serving, so that no client request is balanced
    # onto a node which would still refuse the connection.
    start_lb
    wait_for_node "$(lb_url)" "$(lb_name)"
    echo
    echo "Load balancer (round robin over all nodes): $(lb_url)"
    echo "Use this address as --url for clients; writes are redirected to the primary."
fi

echo
echo "Signature interval: every ${SIG_TX_COUNT} transactions or ${SIG_DELAY}"
echo "Consensus message timeout: ${MESSAGE_TIMEOUT}"
echo
echo "Following logs of $(node_name 0). Press Ctrl-C to tear the cluster down."
docker logs -f "$(node_name 0)"
