# Debug shared Android mesh

Build Go with `sam_debug` and the JNI shim with `SAM_DEBUG`. The existing
`build_android.py --debug-fixtures` does both and verifies every mesh export;
release builds check that those symbols are absent. No new Go dependencies.

## Development host

From the SAM checkout:

```sh
go run -tags sam_debug ./cmd/sam-dev-mesh \
  -data-dir /tmp/sam-dev-mesh \
  -listen 127.0.0.1:18080 \
  -external-url http://10.0.2.2:18080 \
  -config-out /tmp/sam-dev-mesh/device-config.json
```

The CLI runs the existing standalone SAM control plane and WebSocket router.
Only `bootstrapUrl` and `joinToken` enter the mode-0600 device config file.
Keep the database, admin token, issuer key and router key on the host. The join
token admits development nodes without pairwise approval; do not publish it.
For native host tests use an external URL of `http://127.0.0.1:18080` instead.
For physical devices use a host LAN address with a corresponding listener.
The emulator URL intentionally uses the emulator's host-loopback alias.

## Mobile contract

`SamMeshNative.start` takes UTF-8 JSON bytes with `dataDir` (absolute app-private
path), `bootstrapUrl`, `joinToken`, and `displayName`. A publishing device also
supplies `backendUrl` such as `http://127.0.0.1:43123/mcp` and `backendToken`.
`stop` and `start` return null on success, error bytes on failure. `status`,
`discover`, and `call` return UTF-8 JSON; an `error` member denotes failure.
Each returned C string must be freed with `FreeString` (the JNI shim does this).

The backend must speak MCP Streamable HTTP. Native probes, lists and calls send
`Authorization: Bearer <backendToken>` and `X-Peer-Id`. For a remote call the
peer header is the authenticated libp2p caller; probes use the publisher's own
peer ID. These are replaced after hop-by-hop header removal. Backend URLs must
be literal loopback IP addresses over HTTP; redirects are not followed.

A discovered entry has `peerId`, `serviceName`, `toolName`, `description`, and
`inputSchema`. Pass `toolName` back unchanged, e.g.
`mcp://android-notes/read_demo_note`; the call body is
`{ "peerId": "...", "toolName": "...", "arguments": {} }`.
The operator's display name appears in the description and is only a label.
Status contains `state`, `peerId`, `connectedPeers`, and `published`.
Publication must successfully initialize the backend before start succeeds.

The native peer private key persists under `dataDir/shared-mesh-v1`. Enrollment
uses the normal signed bootstrap challenge and real Biscuit membership checks.
The runtime verifies provider credentials even without label constraints.
Development nodes explicitly reserve their authenticated private routers and
advertise only circuit addresses. Direct peer dials are disabled, so emulator
loopback addresses cannot silently bypass the router in host tests. Reservations
are renewed during the node lifetime. This avoids AutoRelay's public-address
filter, which excludes private emulator gateway and LAN router addresses.
Discovery reports a safe aggregate error when published providers exist but
all authenticated catalogs or tool lists fail; it does not expose credentials.
Network operations, including initialization, have a 20-second deadline.
Status remains responsive with `state: starting` while initialization runs.
Stop cancels and joins pending startup before returning; a successful startup
detaches its temporary deadline from the long-lived node context.
Stop cancels outgoing operations
and resets their libp2p stream, including a pending authentication handshake.
A remote backend's already-executing operation may finish after the caller
stops; cancellation is not a rollback guarantee.

The debug host uses the standalone development policy permitting all enrolled
node members to call explicitly published services. It is not a public-mesh
pairing or human identity proof. Bootstrap HTTP is intended for the local demo;
configure HTTPS before sending a join token over an untrusted network.

## Verification

```sh
go test -tags sam_debug ./mobile/sam-node-ffi/ffi ./internal/node -run TestSharedMesh -count=1
go test -race -tags sam_debug ./mobile/sam-node-ffi/ffi ./internal/node \
  -run 'TestSharedMesh|TestLocalTestNode|TestMCP|TestHandleMCPStream' -count=1
go vet -tags sam_debug ./mobile/sam-node-ffi/... ./internal/node ./cmd/sam-dev-mesh
```

Integration tests start actual standalone routers/control planes, discover
Bob without supplying his peer ID, call a real MCP backend, verify Alice's
forwarded peer ID, reject another issuer, preserve Bob's key across restart,
and stop an in-flight call. Separate tests cover spoofed hop headers.
