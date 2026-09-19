# Reviewer pool with an optional shared workspace

This extends the existing SAM example. One manager still leases reviewers;
reviewers still expose `review_code` and invoke Gemini CLI. When enabled,
reviewers also publish reports and receive earlier reviews as attributed context.

- SAM discovers services and transports MCP calls.
- Autobase combines admitted writers' finding records.
- Each reviewer stores reports in its own Hyperdrive, referenced by key,
  version, path and SHA-256 in the shared records.
- Hypercore/Corestore provide storage and replication. Hyperswarm connects
  workspace peers separately from SAM.

The calling harness can use `workspace_info`, `list_findings` and `read_finding`.
These are tools **exported by the reviewer**. They are not configured as tools
inside Gemini CLI. The wrapper retrieves up to three reports for the exact code
hash, supplies at most 16 KiB of attributed context, and publishes the new review.

## Run the basics locally

From this directory, with Node 26:

```sh
npm ci --prefix shared
npm ci --prefix reviewer
npm ci --prefix manager
npm test --prefix shared
npm run demo --prefix shared
```

The demo uses three real, isolated storage directories and real Hypercore
replication streams. Reviewer A publishes a report; reviewer B receives it as
context; the manager sees both reports. It uses a deterministic fake reviewer
and in-memory connections, so it needs no API key, running SAM mesh, Docker or
public Hyperswarm discovery. Temporary demo storage is removed afterward.

Tests cover real file retrieval, writer admission, disconnected publication and
reconnection, reopening persisted storage, invalid hashes, unavailable files,
UTF-8 context limits, failure fallback, and MCP worker capacity across clients.

## Enable sharing in the existing SAM deployment

Sharing is disabled by default. Install `shared` alongside the two services.
Each process needs its own writable persistent directory; never share or clone
a live workspace directory between processes.

| Environment variable | Meaning |
|---|---|
| `SAM_WORKSPACE_DIR` | Enables sharing and selects this process's persistent directory. |
| `SAM_WORKSPACE_KEY` | Manager's public Autobase bootstrap key. Set on **every reviewer**. Omit only when creating the founder/manager workspace. |
| `SAM_WORKSPACE_WRITERS` | Comma-separated reviewer writer keys to admit on manager startup. Set only on the founder. |
| `SAM_NODE_URL` | Existing manager's local SAM MCP URL. |
| `SAM_API_TOKEN_PATH` | Optional file containing that node's local API token; takes precedence over `SAM_API_TOKEN`. |

Initialize and inspect directories while their owning processes are stopped:

```sh
node shared/cli.mjs workspace-data/manager
# Copy baseKey from the output into SAM_WORKSPACE_KEY for the reviewers.
node shared/cli.mjs workspace-data/reviewer-a "$SAM_WORKSPACE_KEY"
node shared/cli.mjs workspace-data/reviewer-b "$SAM_WORKSPACE_KEY"
```

Copy the two reviewer `writerKey` values into the manager's
`SAM_WORKSPACE_WRITERS`. Start the manager with `SAM_WORKSPACE_DIR` pointing to
its initialized directory, then start the reviewers with their respective
directories and the shared `SAM_WORKSPACE_KEY`. All instances join the workspace
swarm automatically. Startup logs show public keys and current writability;
admission can take time to replicate. Add writers by updating the manager's
configured list and restarting it. There is no remote admission tool.

Continue using the normal acquire → review → release calls through SAM. If
sharing fails or admission has not arrived, the review still returns, with a
workspace status note. Workspace membership is separate from SAM enrollment.

For the existing Helm example, provide these variables via `service.env` and
mount a separate persistent directory into each application container. The stock
example chart does not provision workspace volumes: configure these mounts in
your deployment before enabling sharing. The manager's default local API token
is still `devtoken`; a chart-generated token must instead be provided through
`SAM_API_TOKEN` or a mounted file and `SAM_API_TOKEN_PATH`.

Do not run the offline CLI against a directory held open by the manager or a
reviewer. Query `workspace_info` for a running service instead.

## Container builds

Use the example root as build context so both images include `shared/`:

```sh
docker build -f reviewer/Dockerfile -t reviewer:local .
docker build -f manager/Dockerfile -t pool-manager:local .
```

Supply `GEMINI_API_KEY` at runtime, preferably from a Secret. It is not baked into
the reviewer image. Hyperswarm requires its own network connectivity; SAM router
connectivity alone does not establish workspace replication.

## Boundaries of this spike

The manager is the sole Autobase indexer. Its absence can stop new signed
checkpoints; findings are informational and their tentative order can change.
The view reducer never invokes tools or performs external effects.

File publication and record publication are separate writes. A failed append
can leave an unreferenced report; this spike has no durable retry queue. Missing
artifacts return `ARTIFACT_UNAVAILABLE` after a bounded wait. There is no guarantee
of replication or availability once all peers retaining the data disappear.

The workspace is **not configured for confidential storage**. Use intentionally
shared test material. Public bootstrap/discovery keys are not encryption keys or
read authorization. SAM permissions do not apply to the separate Hyperswarm data
network. Findings are untrusted reference material, not instructions or evidence
of correctness.

The example's existing single-manager leases and restart limitations remain.
There is no new scheduler, fixed roster, organization framework or automatic
software update mechanism. Pear is not needed for this experiment.
