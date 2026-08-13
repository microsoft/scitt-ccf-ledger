# Build and push SCITT Docker images

This folder contains scripts and utilities to build and run docker images for the SCITT application.

## Build and run docker images

To build a docker image, run the following command from the root of the repository:

```bash
./docker/build.sh
```

### Run a single-node development container

To run a docker container using a built image, run the following command from the root of the repository:

```bash
./docker/run-dev.sh
```

Both scripts accept different variables for customization. Please refer to the corresponding scripts for the full list of available variables to use.

### Multi-node development cluster

`run-dev.sh` starts a single node by default. Set `NODE_COUNT` to a value greater
than 1 and it delegates to `run-dev-cluster.sh`, which starts a CCF network of
that many nodes, opens the service, and transitions the joining nodes to
`Trusted` via a governance proposal:

```bash
NODE_COUNT=3 ./docker/run-dev.sh
```

Node `i` listens for client requests on `https://localhost:$((CCF_PORT + 1 + i))`,
so the default 3-node cluster is served by nodes on ports 8001, 8002 and 8003.
Every node is configured to redirect write requests to the primary, so clients
may submit to any of them. All containers use `--network=host`, matching the
single-node script.

#### Load balancer

Clients are not expected to address the nodes directly. An nginx container
listens on `CCF_PORT` (8000 by default) and distributes connections over the
nodes in round robin order, which is how the service is fronted in production:

```
client --> localhost:8000 (nginx)  --> localhost:8001  node0
                                   --> localhost:8002  node1
                                   --> localhost:8003  node2
```

Points worth knowing:

- **Layer 4 passthrough.** nginx proxies the raw TCP stream with its `stream`
  module and does not terminate TLS.
- **Per connection balancing.** Round robin applies to new connections, not
  individual requests, so a client which reuses one connection stays pinned to
  one node.
- **Writes are redirected, not proxied.** A node which is not the primary
  answers a write with a 307 to the primary's own address
  (`redirections.to_primary` is `NodeByRole`), so the client's second attempt
  goes directly to the primary rather than back through the load balancer.
- **Passive health checks.** Active health checks are not available in nginx
  OSS, so a node which refuses a connection is taken out of rotation for
  `LB_FAIL_TIMEOUT` and the connection is retried against the next node.

The generated configuration is written to `workspace/nginx.conf`, so it can be
inspected or edited before a rerun.

#### Running the functional tests against the cluster

The functional tests talk to whatever `CCF_URL` points at, so they can be run
against the cluster by setting `NODE_COUNT`:

```bash
DOCKER=1 NODE_COUNT=3 ./run_functional_tests.sh
```

`CCF_URL` then resolves to the load balancer, so the suite exercises requests
being spread over the nodes and writes being redirected to the primary, rather
than a single node serving everything.

Containers and the shared volume are removed when the script exits. Set
`KEEP_CLUSTER=1` to leave the cluster running instead; the script then prints the
`docker rm`/`docker volume rm` command needed to tear it down later.

> **Note:** joining nodes are configured with `join.fetch_recent_snapshot` set
> to `false` (override with `JOIN_FROM_SNAPSHOT=true`), so they replay the whole
> ledger from the first transaction instead of bootstrapping from a snapshot of
> the primary. A node which joins from a snapshot holds no ledger below the
> snapshot seqno, and cannot serve historical queries such as
> `GET /entries/{txid}`, because the receipt lookup needs ledger secrets derived
> by reading back to seqno 1; requests to that node would poll with 302 forever.
> Replaying the ledger is cheap on a development cluster, keeps every node able
> to serve every read, and removes the need for the `SnapshotRead` and
> `LedgerChunkRead` operator features on the client interface.
