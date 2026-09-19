---
title: "Warm Agent Pool"
linkTitle: "Warm Agent Pool"
weight: 10
---

Spread a batch of work across a pool of identical, already-running worker
agents. The pool is built from ordinary mesh MCP services, with no gossip and
no changes to the node.

<video autoplay loop muted playsinline controls style="width: 100%; border-radius: 8px;">
  <source src="../../../demo-warm-agent-pool.mp4" type="video/mp4">
</video>

Source: [`development/examples/code-reviewer-pool/`](https://github.com/google/sam/tree/main/development/examples/code-reviewer-pool).

## The idea

Some agent tools are expensive to start but cheap to reuse: a reviewer that
calls an LLM, a sandbox that boots a runtime, a service that holds a warm
model in memory. You do not want to start one per request, and you do not
want a single instance that handles all your work one job at a time. What
you want is a pool of identical, already-running workers, and something that
hands them out one job at a time.

This use case builds that on the mesh, using only ordinary MCP services. The
worked example is a code reviewer: several identical reviewer workers, a
manager that leases them, and an orchestrator that spreads a batch of files
across the pool in parallel.

## The pieces

- **Workers**: plain `code-reviewer` MCP services. Each exposes a single
  `review_code` tool that sends the snippet to an LLM and returns comments
  grouped by severity. They are stateless and interchangeable. The pool's job
  is to keep them busy.
- **Manager**: a normal MCP service that exposes `acquire_worker`,
  `release_worker` and `list_workers`. It is also an MCP client of its own
  node. Every few seconds it calls `find_remote_tools` to learn which worker
  peers exist (through the DHT), and it tracks which of them are free or busy
  with leases.
- **Orchestrator**: any mesh MCP client (an agent harness or a custom
  program). The loop per file is `acquire_worker`, then
  `call_remote_tool(peer, review_code)`, then `release_worker`. Run those
  chains concurrently and each acquire returns a different free worker, so
  parallel dispatch never collides.

## Why there is no readiness broadcast

A classic worker pool needs to know two things: who exists and who is busy.
The manager gets the first from DHT discovery and the second from its own
leases. These are exactly the two facts that a readiness broadcast would
otherwise provide. So the whole pool runs on discovery and leasing, without
pub/sub. The trade-off is that leasing is authoritative only while the
manager is the only dispatcher. That fits a single-manager pool. If you
needed several managers, that is the point where you would need real
coordination.

## What makes it correct under concurrency

"Hand out a warm worker, one job at a time" stays true even when acquires
race and workers come and go:

- **No double lease.** The manager is single-threaded and `leaseFree()` is
  fully synchronous (there is no `await` between picking a worker and marking
  it busy), so two concurrent `acquire_worker` calls can never receive the
  same peer.
- **Grace eviction.** Discovery never drops a leased worker on a transient
  miss, and it drops a free one only after `SAM_GRACE_MISSES` consecutive
  misses. A slow, busy worker is not evicted and handed out again in the
  middle of a review.
- **Fencing tokens.** `acquire_worker` returns a `lease_id`. `release_worker`
  clears the lease only if that id still matches, so a late release from an
  expired lease cannot free a worker that belongs to a newer holder.
- **Single-flight guard.** Even if a lease race got through, the worker
  itself returns `POOL_BUSY` for a second concurrent `review_code`, so the
  one-at-a-time rule holds at the source.

## Lease enforcement

Workers trust the manager and not the caller. On `acquire_worker` the
manager creates a short-lived HMAC token bound to that worker and to the
lease expiry. The orchestrator forwards the token in the `review_code`
arguments, and the worker verifies it offline (shared secret, no call back to
the manager). Any `review_code` without a valid, unexpired token gets
`NO_LEASE`. Both sides default to a hardcoded development secret
(`sam-dev-pool-secret`), so enforcement works out of the box. Set a matching
`SAM_POOL_SECRET` on the manager and on every worker to override it.
Mismatched or one-sided secrets fail closed, and every call returns
`NO_LEASE`.

## What you can do with it

- **Parallel batch work.** Spread a directory of files (or tasks) across N
  warm workers and collect results as they arrive. The limit is the pool
  size, and the work is not serialised.
- **Elastic capacity.** Scale a worker deployment up or down in the middle of
  a job. The manager picks up a new worker on its next discovery pass and
  starts leasing it, and it drains a worker that disappears without
  corrupting in-flight leases.
- **A reusable pattern.** Swap `code-reviewer` for any tool that is expensive
  to warm up (test runner, sandbox, embedder, browser). The manager is
  generic. It pools whatever `SAM_POOL_SERVICE` names.

## Try it on kind

The repository ships a [kind](https://kind.sigs.k8s.io/)-based local mesh that
brings up the whole pool with one command.

### 1. Set an LLM key for the reviewer image

The reviewer workers call an LLM. Supply `GEMINI_API_KEY` at runtime through
`service.env`, preferably using a Kubernetes Secret. Do not put the key in
the Dockerfile or image.

### 2. Bring the mesh up and deploy the pool

```bash
make build            # builds ./bin/sam-node (once)
make kind-up          # control plane + router (no sam-nodes yet)
```

Then build the two images and deploy the pool as `charts/sam-node` releases:
three reviewer replicas and one manager. Each replica enrolls as its own
mesh node, so the pool is three `code-reviewer` services with the same name.

```bash
docker build -t reviewer:local -f development/examples/code-reviewer-pool/reviewer/Dockerfile development/examples/code-reviewer-pool
docker build -t pool-manager:local -f development/examples/code-reviewer-pool/manager/Dockerfile development/examples/code-reviewer-pool
kind load docker-image --name sam-kind reviewer:local pool-manager:local

helm --kube-context kind-sam-kind -n sam-kind install reviewers charts/sam-node \
  -f development/kind/sam-node.values.yaml \
  -f development/examples/code-reviewer-pool/reviewer/values.yaml --set replicaCount=3
helm --kube-context kind-sam-kind -n sam-kind install manager charts/sam-node \
  -f development/kind/sam-node.values.yaml \
  -f development/examples/code-reviewer-pool/manager/values.yaml
```

### 3. Start a local orchestrator node

```bash
make kind-local-node  # a local sam-node enrolled in the mesh; leave it running
```

`kind-local-node` runs in the foreground in its own shell and exposes the
mesh MCP tools at `http://127.0.0.1:9099/mcp` (token `devtoken`). No
`kubectl port-forward` is needed. This local node is the entry point into
the mesh for your orchestrator.

### 4. Point your harness at the local node

Add the local node as an MCP server in the harness you use to drive the
mesh. The details differ per harness (some use a JSON or TOML config file,
others a UI), but the settings are always the same:

- **Transport:** HTTP (Streamable HTTP / `http`)
- **URL:** `http://127.0.0.1:9099/mcp`
- **Header:** `X-Sam-Authentication: Bearer devtoken`

For example, harnesses that use the common `mcpServers` JSON config (Claude Code,
Cursor, and others) would add:

```json
{
  "mcpServers": {
    "sam-mesh": {
      "type": "http",
      "url": "http://127.0.0.1:9099/mcp",
      "headers": { "X-Sam-Authentication": "Bearer devtoken" }
    }
  }
}
```

Check the MCP documentation of your harness for its exact config format.
Once connected, the mesh exposes `acquire_worker`, `release_worker`,
`list_workers`, `find_remote_tools` and `call_remote_tool` as tools that your
agent (or program) can call.

### 5. Drive the pool

Have your orchestrator run these steps per file, in parallel:

1. `acquire_worker` returns `{peer_id, tool, lease_id, token}`.
2. `call_remote_tool(peer_id, review_code, {code, token})`. Forward the
   `token` in the tool arguments, because the pool requires it.
3. `release_worker(peer_id, lease_id)`. Pass the `lease_id` back, so that a
   stale release cannot free a worker that belongs to a newer holder.

A natural prompt for an agent harness:

> Using the `sam-mesh` tools: for each file in
> `development/examples/code-reviewer-pool/samples/`, acquire a worker, call its
> `review_code` with the file contents (forwarding the token), and release it
> (pass the `lease_id` back). Run them in parallel.

The reviews come back concurrently, limited by the number of workers in the
pool.

### 6. Elasticity (add a worker in the middle of a job)

Scale the reviewer pool down, start a larger job, then scale it back up. The
manager picks up the new worker on its next discovery pass and starts
leasing it:

```bash
kubectl --context kind-sam-kind -n sam-kind scale deploy/reviewers-sam-node --replicas=2
# start a big job, then:
kubectl --context kind-sam-kind -n sam-kind scale deploy/reviewers-sam-node --replicas=3
```

## Configuration

| var | default | used by |
|-----|---------|---------|
| `SAM_NODE_URL` | `http://127.0.0.1:8080/mcp` | manager |
| `SAM_API_TOKEN` | `devtoken` | manager |
| `SAM_POOL_SERVICE` | `code-reviewer` | manager |
| `SAM_DISCOVERY_MS` | `3000` | manager |
| `SAM_LEASE_MS` | `60000` | manager |
| `SAM_GRACE_MISSES` | `2` | manager |
| `SAM_POOL_SECRET` | `sam-dev-pool-secret` (enforcement always on) | manager + reviewer |

## Optional shared review workspace

The example can also share review reports through Hypercore, Autobase and
Hyperdrive, with Hyperswarm providing the separate replication network.
The pool retains one manager and its existing acquire/review/release flow.
Sharing is disabled unless `SAM_WORKSPACE_DIR` is set.

See the [example workspace README](https://github.com/local-xyz/sam/tree/feat/reviewer-shared-workspace/development/examples/code-reviewer-pool#readme)
for the local demo, explicit writer admission and persistent storage setup.
Workspace tools are exposed to the calling harness; the Gemini subprocess
receives prior findings through its wrapper, not through newly configured MCP tools.
