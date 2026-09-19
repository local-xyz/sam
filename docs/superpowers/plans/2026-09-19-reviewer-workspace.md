# Shared Workspace for SAM’s Reviewer Pool — Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development or superpowers:executing-plans when implementation is requested. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let reviewers in SAM’s existing code-reviewer pool publish findings and read one another’s previous work through a replicated shared workspace.

**Architecture:** Keep the existing manager, leases, reviewer tools and SAM communication. Add a small workspace module using Autobase for shared records and Hyperdrive for review files, backed by Hypercore. Use Hyperswarm for that stack’s replication connections.

**Tech Stack:** Existing Node/MCP example + Corestore, Autobase, Hyperdrive and Hyperswarm. Hypercore is their underlying storage; Pear is a possible subsequent distribution step.

**Spec:** This document is the complete scope of the spike. It replaces the previous scheduler/recovery proposal. Implementation is authorized in the SAM fork on branch `feat/reviewer-shared-workspace`. This plan now lives with that branch.

## Global Constraints

- Implement directly on the new feature branch of the existing SAM fork checkout, as requested.
- Keep one pool manager and its current allocation behavior.
- No fixed worker roster, job hashing, new request-signing scheme, SQLite scheduler, or custom execution protocol.
- No changes to SAM’s Go components or wire protocols.
- Shared records inform reviews; replication never starts jobs or changes permissions by itself.

## Review Focus

- Adding tools must not cause the manager to select a workspace tool as a reviewer.
- A disconnected reviewer must retain its locally published work and replicate it after reconnection.
- A visible record may reference a file that has not arrived yet; report it as unavailable and retry retrieval.
- Replicated notes are attributed input, not instructions or established truth.
- A sharing failure must not discard an otherwise successful code review.

---

## The experiment

Today, a reviewer returns its answer to the caller. Add one capability: **the reviewer can also put that answer in a workspace other reviewers can read.**

Demonstration:

1. The existing manager assigns a review to reviewer A.
2. A completes the review, writes its report to its Hyperdrive, and publishes a reference in Autobase.
3. Reviewer B synchronizes the shared records and retrieves A’s report.
4. B’s next review of that code includes A’s findings as attributed background.

This demonstrates shared memory across agents. Whether that memory improves review quality is a subsequent evaluation; replication alone does not establish improvement.

## Where each system fits

| System | Responsibility |
|---|---|
| **[SAM](https://github.com/google/sam)** | Existing discovery, authorized MCP calls and reviewer invocation. |
| **[Hypercore](https://github.com/holepunchto/hypercore)** | Authenticated log storage and replication underneath the workspace libraries. No separate application layer to invent. |
| **[Autobase](https://github.com/holepunchto/autobase)** | Combine admitted reviewers’ records into a shared index of findings and their file references. |
| **[Hyperdrive](https://github.com/holepunchto/hyperdrive)** | Store review reports. Each reviewer owns its own writable drive; the shared index points into those drives. |
| **[Hyperswarm](https://github.com/holepunchto/hyperswarm)** | Find and connect workspace replicas using the workspace discovery topic. SAM does not already transport Hypercore replication. |
| **[Pear](https://github.com/holepunchto/pear)** | Potentially distribute the resulting application later. It adds nothing necessary to this first shared-memory demonstration. |

The workspace is a module inside the existing application processes. SAM and Hyperswarm provide separate connections: tool calls travel through SAM; workspace data replicates through Hyperswarm.

## Initialization

The existing manager creates the Autobase and acts as its initial administrator/indexer. Reviewers receive its public bootstrap key through example configuration, open their local replica and provide their writer keys to the operator. The operator configures admitted writer keys in the manager environment; its workspace instance admits them with `indexer:false` at startup. No administrative MCP endpoint is added.

This is a small extension of the demo’s existing deployment setup. Discovering a SAM service does not automatically admit its writer to the workspace. Writer admission is explicit; we do not add a general organization framework.

Each process keeps its Corestore on a persistent local directory. Hyperdrive uses a named namespace within that store. Joining peers use the same Autobase discovery topic and attach replication streams to Hyperswarm connections. The workspace module owns opening referenced remote drives through that store so their files can replicate as well.

The manager is initially the only indexer. Its absence can stall new signed checkpoints; reviewers can still retain their own contributions locally. This spike uses shared findings as informational records, not committed execution decisions.

## Code boundaries

Reviewed SAM baseline: [`adb56e2`](https://github.com/google/sam/tree/adb56e2bfb8fc6b42dd7377a0a6e36375b403e6d/development/examples/code-reviewer-pool).

All paths below are relative to `development/examples/code-reviewer-pool/` on this feature branch:

| File | Change |
|---|---|
| `shared/workspace.mjs` — new | Open/store/replicate the workspace, publish a finding, list records and retrieve a report. Own all Hypercore-family integration. |
| `reviewer/review_server.mjs` | Open the workspace at startup; retrieve prior findings before reviewing; publish the result afterward; expose workspace read tools. |
| `manager/server.mjs` | Open the founder workspace at startup; filter discovered worker tools to exactly `review_code`. Keep lease allocation and release logic. |
| `reviewer/package.json`, `manager/package.json`, Dockerfiles | Add workspace dependencies and include the shared module in both images. Build from the example root so Docker can copy `shared/`. |
| Existing example values/configuration | Add bootstrap-key configuration and persistent workspace directories. |
| `test/workspace.test.mjs` — new | Test replication, artifact retrieval and reviewer integration. |

The tool filter is necessary because the current manager accepts every tool under `mcp://code-reviewer/`; adding workspace tools could otherwise overwrite its selected review tool. [Current discovery loop](https://github.com/google/sam/blob/adb56e2bfb8fc6b42dd7377a0a6e36375b403e6d/development/examples/code-reviewer-pool/manager/server.mjs#L33).

```js
if (r.tool_name !== `mcp://${POOL_SERVICE}/review_code`) continue;
```

## Workspace interface

Keep the application-facing interface small:

```ts
openWorkspace({ directory, bootstrapKey }): Promise<Workspace>

interface Workspace {
  info(): { baseKey: string; writerKey: string; driveKey: string };
  admitWriter(writerKey: string): Promise<void>; // founder's local operator action
  publishFinding({ codeHash, report }): Promise<Finding>;
  listFindings({ codeHash }): Promise<Finding[]>;
  readFinding(finding: Finding): Promise<string>;
  close(): Promise<void>;
}

type Finding = {
  id: string;
  author: string; // derived from the Autobase writer, not trusted from input
  codeHash: string;
  artifact: { driveKey: string; version: number; path: string; sha256: string };
};
```

`publishFinding` writes a uniquely named report into the local Hyperdrive, captures its version and content hash, then appends its reference to Autobase. These are two writes, not one transaction: an unreferenced file is acceptable for the spike. A failed append is reported as a sharing failure.

Autobase’s deterministic `apply` appends validated records to its managed view and derives authorship from `node.from.key`. Only the founder’s writer can admit another writer. No LLM calls, drive writes or mutable external maps run inside `apply`. [Autobase’s replay constraints](https://github.com/holepunchto/autobase/blob/846103a277edc6ef309c95765e95f918a6ec1b60/README.md#reordering).

`readFinding` opens the referenced drive version, retrieves the path and checks its hash. A missing peer/file returns `ARTIFACT_UNAVAILABLE`; it does not substitute different content. Reads use bounded timeouts. For this controlled demo, only intentionally shared review material goes into the workspace; joining a discovery topic is not a privacy mechanism.

## Implementation steps

### Task 1: Add the workspace module

- [ ] Write a failing test with two isolated Corestores: A publishes a report; after replication, B lists it and retrieves the same bytes.
- [ ] Implement the interface above with Autobase, one Hyperdrive per reviewer and Hyperswarm connections. Use in-memory replication streams for deterministic tests.
- [ ] Test disconnect → local publication → reconnect → eventual retrieval. Also test a known record with an unavailable artifact and a mismatched content hash.
- [ ] Commit the module and tests on the feature branch.

### Task 2: Attach it to the existing reviewer flow

- [ ] Add a failing manager-discovery test containing `review_code` and a workspace read tool; assert only `review_code` is selected.
- [ ] Apply the exact-name filter and open the founder/reviewer workspace instances at startup.
- [ ] Add `list_findings` and `read_finding` MCP tools to the reviewer service, delegating directly to the workspace interface.
- [ ] Extend `runGemini(code)` to `runGemini(code, priorFindings)`. Retrieve up to three available reports for the same code hash, cap combined context at 16 KiB, and label them as attributed, untrusted review material.
- [ ] After `runGemini` returns, publish its report. If workspace reading or publishing fails, return the normal review with a sharing-status note. Do not rerun the review to repair replication.
- [ ] Test using an injected fake reviewer: B receives A’s prior finding as context; unavailable workspace data does not prevent a review result.
- [ ] Commit the reviewer integration.

The change attaches around [the existing `runGemini` call](https://github.com/google/sam/blob/adb56e2bfb8fc6b42dd7377a0a6e36375b403e6d/development/examples/code-reviewer-pool/reviewer/review_server.mjs#L64):

```text
read available prior findings → existing review → publish report → return review
```

### Task 3: Package and demonstrate the basics

- [ ] Provide an executable local replication demo with the same workspace/review modules and a fake reviewer; document how to enable it in the existing SAM deployment.
- [ ] Support file-based local API-token configuration; document the existing chart-generated token requirement.
- [ ] Run the local demo: review on A, retrieve on B, and demonstrate B receives A’s attributed report as context.
- [ ] Verify reopen and disconnected publication/reconnection in integration tests. Run repository checks and record unavailable infrastructure honestly.
- [ ] Record the observed behavior and the few reproduction commands in the example README. No quality or recovery claims beyond the checks actually run.

## What happened to the allocation concern?

It remains a limitation of a future multi-manager scheduler. The original example already has one manager. Keeping it lets us investigate shared agent memory without redesigning allocation.

The earlier proposal combined these independent questions and introduced unnecessary fixed routing, durable execution machinery and new APIs. Those requirements are removed. This proposal layers a shared workspace onto the existing review mesh; it does not claim to fix the example’s existing lease/restart limitations.

## Implementation scope

Workspace sharing is opt-in through `SAM_WORKSPACE_DIR`; without it the example retains its existing review behavior. `shared/` has its own pinned npm package and lockfile. A small operator CLI initializes/inspects a stopped workspace; startup logs public keys for running services. The first implementation verifies real storage/replication locally, without requiring an LLM key or a running Kubernetes cluster. Live SAM deployment remains documented and is only claimed tested if actually run.
