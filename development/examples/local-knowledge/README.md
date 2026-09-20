# Peer agents

One generic Gemini-backed MCP service, following the original reviewer example.
Deploy the same service on multiple SAM nodes. Every instance exposes `ask` and
can discover and ask peers through SAM. There are no predefined specialist roles.

`agent_server.mjs` passes a question and this instance's `LOCAL_CONTEXT` environment
value to Gemini CLI. Gemini owns the tool loop; the Dockerfile connects it to SAM
using `gemini mcp add`. `LOCAL_CONTEXT` is a temporary input for this scaffold;
real app/device memory access is not implemented. Context defaults to “not connected.”

```text
Question → agent → Gemini → SAM discovery / peer calls → answer
```

From this directory:

```sh
npm ci
npm test
docker build -t knowledge-agent:local .
```

Deploy with `charts/sam-node` and this `values.yaml`, using Helm release name
`knowledge-agent`. It expects Secret `knowledge-agent-gemini` with key `api-key`.
The chart supplies the node-token Secret; `SAM_NODE_URL` includes `/mcp`.
Discover `mcp://knowledge-agent/ask` and call it with `{"question":"..."}`.

Tests cover the subprocess and MCP wrapper using a fake model runner. Live
Gemini/SAM collaboration has not been tested. Peer selection is prompted behavior;
SAM policy controls access. The busy guard rejects overlapping or cyclic calls.
Shared memory, background learning, and organization formation are not implemented.
