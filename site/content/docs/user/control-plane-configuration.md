---
title: "Control Plane & Router Configuration Guide"
linkTitle: "Control Plane & Router Configuration"
weight: 10
---

The SAM architecture separates the OIDC capabilities control plane (`sam-control-plane`) from the GossipSub network routers (`sam-router`). 

---

## 1. SAM Control Plane (`sam-control-plane`)

The Control Plane is responsible for bridging user identities from trusted OIDC providers, issuing cryptographically signed Biscuit authorization tokens, and distributing network/tool policies to routers and nodes.

### Command-Line Arguments & Environment Variables

| CLI Flag | Environment Variable | Default Value | Description |
| :--- | :--- | :--- | :--- |
| `--issuer` | `SAM_OIDC_ISSUER` | *None* (Required) | Comma-separated list of trusted OIDC Provider URLs. |
| `--bind-address` | *None* | `0.0.0.0:8080` | Host and port to listen on for HTTP web API service. |
| `--db-driver` | *None* | `sqlite` | Database driver (`sqlite` or `postgres`). |
| `--db-dsn` | *None* | `control-plane.db` | Database DSN/Connection URL (e.g. `postgres://user:pass@host:5432/db`). |
| `--allowed-audiences` | *None* | `sam-mesh-audience` | Comma-separated list of allowed JWT audiences. |
| `--admin-token-path` (or env `SAM_ADMIN_TOKEN`) | *None* | *None* | File containing the secret token required in the HTTP Header `Authorization: Bearer <token>` for admin operations. |
| `--insecure-skip-tls-verify` | *None* | `false` | Set to `true` to skip certificate validation for development/testing OIDC providers. |
| `--biscuit-ttl` | *None* | `24h` | Lifespan minted into every issued Biscuit token. Capped to the OIDC token's own expiry when shorter. |
| `--oidc-session-ttl` | *None* | `2160h` (90 days) | How long an OIDC enrollment stays refreshable before the identity must re-authenticate with the OIDC provider. Shorter values keep the provider authoritative for offboarding, at the cost of more frequent interactive re-enrollment. |
| `--key-rotation-interval` | *None* | `24h` | Key rotation interval (e.g. `24h`). `0s` disables rotation. |
| `--key-grace-period` | *None* | `1h` | How long a rotated-out signing key stays accepted. Once it is retired, Biscuits it signed can no longer be verified or refreshed; see [Signing-Key Retirement and Recovery](#signing-key-retirement-and-recovery). |
| `--lease-duration` | *None* | `15m` | Router lease registration TTL. |

---

## 2. SAM Router (`sam-router`)

The Router is a dedicated GossipSub helper that maintains stable network addresses (multiaddrs) and relays mesh overlays for discovery.

### Command-Line Arguments & Environment Variables

| CLI Flag | Default Value | Description |
| :--- | :--- | :--- |
| `--control-plane` | `http://127.0.0.1:8080` | Control Plane web service URL. |
| `--listen` | `/ip4/0.0.0.0/tcp/5001`, `/ip6/::/tcp/5001` | Comma-separated libp2p multiaddrs to listen on. |
| `--external-addr` | *None* | External multiaddrs to announce to control plane. |
| `--keys-path` | `router.key` | Path to save/load persistent private key (determines Peer ID). |
| `--jwt-path` | *None* | Path to file containing OIDC JWT token for enrollment. |
| `--oidc-token` | *None* | Direct OIDC ID token or bootstrap secret token for enrollment. |
| `--keys-sync-interval` | `5m` | Key synchronization polling interval. |
| `--lease-renew-interval` | `300s` | Lease renewal registration interval. |
| `--allow-loopback` | `false` | Allow loopback and link-local addresses for discovery (development only). |

---

## 3. Configuring Role-Based Policies (Dynamic API)

The Control Plane dynamically issues permissions inside the Biscuit token based on identity claims (users or groups) mapped to specific roles in the database.

The policy defines what endpoints and services agents are permitted to use:
* **`allowed_targets`**: Restricts which logical endpoints the agent can route connections to. Use resolved Biscuit facts: `group:<name>`, `user:<sub-id>`, `email:<email>`, `role:<role-name>`, or `node:<peer-id>`.
* **`allowed_services`**: Restricts the application-level services the agent can invoke. Services are prefixed by their protocol type and URI scheme (e.g., `mcp://local-shell-tools` or `inference://openrouter`). Wildcards are supported (e.g., `mcp://*`). The service is deliberately the unit of authorization: a grant offers the service's whole tool surface, so publish different privilege tiers as different services (e.g. `mcp://db-reader` vs `mcp://db-writer`) rather than expecting the mesh to filter tools inside one backend.
* **`allowed_agents`**: The agent namespaces a node with this role can use. When a node forwards a request for a sandboxed agent, it sends the agent's name with it. The receiving node accepts that name only if it falls inside one of these namespaces. A node with no `allowed_agents` grant cannot name any agent. Accepted patterns are `*.prod.acme.example`, `acme.*`, an exact ID such as `reviewer-7.prod.acme.example`, or `*` for any agent.
* **`allowed_labels`**: The labels a node with this role may declare when it enrolls, as `*`, `key=*` or `key=value`. A node sends its own labels in its enrollment request, so this is what decides which of them the control plane is willing to sign into `label()` facts. A role granting none means a node holding it can declare none. Peers gate on those facts with `required_labels`, so a node that could declare anything could satisfy any such requirement.

> **`allowed_agents` and `allowed_targets` do different things.** `allowed_targets` controls which agents a node can send requests *to*. `allowed_agents` controls which agents a node can claim to be acting *for*. Setting `allowed_agents` to `*` lets any node with that role claim any agent identity in the mesh, so nodes log a warning when they receive such a grant.

> **`sam:system:authenticated` means everyone your issuer vouches for.** That
> special member matches every identity able to obtain a token from the
> configured OIDC provider — and enrollment is open to all of them. Binding it
> to a role with wildcard `allowed_services` therefore grants every tool on
> every node to anyone the issuer will authenticate, which for a public
> provider is the whole internet. Reserve it for intentionally public meshes,
> and pair it only with narrowly scoped roles (e.g. `system://sam.catalog`).

### Seeding Policies via REST API
Admins manage policies by sending a JSON payload to the `/policies` endpoint.

```json
{
  "roles": [
    {
      "name": "developer-role",
      "allowed_targets": ["group:dev-nodes", "email:dev-lead@example.com", "user:auth0|123456", "node:12D3KooWSpecificDevNodeId"],
      "allowed_services": ["mcp://local-shell-tools", "mcp://git-helper", "inference://openrouter"],
      "allowed_agents": ["*.dev.example.com"]
    },
    {
      "name": "admin-role",
      "allowed_targets": ["group:all-nodes", "role:admin"],
      "allowed_services": ["mcp://*", "inference://*", "system://*"]
    }
  ],
  "bindings": [
    {
      "role": "admin-role",
      "members": ["email:alice@example.com", "user:auth0|123456"]
    },
    {
      "role": "developer-role",
      "members": ["group:eng-team"]
    }
  ]
}
```

### 3.1 Binary Capability Roles (Zero Trust)
To enforce the principle of least privilege, the Sovereign Agent Mesh implements binary-level capability authorization. Every binary connecting to the mesh must request its specific target role during enrollment:
- `sam-node` requests `sam:role:node` (Default agent capability)
- `sam-box` requests `sam:role:sambox` (Secure Gateway sidecar)
- `sam-router` requests `sam:role:router` (P2P routing and relay service)

The control plane control plane validates that the enrolling client is authorized for the requested role before issuing the Biscuit identity token:
1. **Explicit Bindings**: Every capability role — including `sam:role:node` — must be bound to the enrolling identity in mesh policy. There is no fallback: a mesh with no `sam:role:node` binding enrolls no nodes. To open node enrollment to every identity the OIDC issuer authenticates (an intentionally public mesh), bind it explicitly:

```json
"bindings": [
  {
    "role": "sam:role:node",
    "members": ["group:eng-team"]
  },
  {
    "role": "sam:role:router",
    "members": ["group:mesh-routers"]
  },
  {
    "role": "sam:role:sambox",
    "members": ["user:gateway-pod-sa"]
  }
]
```

If a binary requests a capability role it is not authorized for, enrollment fails immediately. If a client attempts to start using a token that lacks its binary's required role, startup aborts.

---

## 4. Bootstrapping Example

Here is a script demonstrating how to boot both services in a secure development environment:

```bash
# 1. Start the Control Plane (using SQLite)
./bin/sam-control-plane \
  --issuer "https://accounts.google.com" \
  --allowed-audiences "my-google-client-id.apps.googleusercontent.com" \
  --bind-address "0.0.0.0:8080" \
  --admin-token-path /etc/sam/admin-token

# 2. Seed baseline policy via REST API
curl -X POST \
  -H "Authorization: Bearer super-secret-admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "roles": [{"name": "sam:role:node", "allowed_services": ["mcp://*"], "allowed_targets": ["*"]}],
    "bindings": [{"role": "sam:role:node", "members": ["group:developers"]}]
  }' \
  http://127.0.0.1:8080/policies

# 3. In another shell, start the Router using a bootstrap JWT or token
./bin/sam-router \
  --control-plane "http://127.0.0.1:8080" \
  --listen "/ip4/0.0.0.0/tcp/5001" \
  --listen "/ip4/0.0.0.0/udp/5001/quic-v1" \
  --keys-path "./router.key" \
  --oidc-token "my-router-jwt-token"
```

---

## 5. Token Refresh & Session Revocation

To enforce centralized access control without sacrificing offline verification performance at the edge, SAM implements a decoupled token refresh and session revocation model.

### Lifespan Model

1. **Short-Lived Biscuit Tokens (TTL = 24 Hours)**:
   All minted Biscuit tokens are cryptographically bound to a strict 24-hour expiration. Peers verify this expiration locally without hitting the Control Plane.
2. **Long-Lived Sessions (The Right to Refresh)**:
   * **OIDC Interactive Enrollment**: 90-day database session limit. After 90 days, the user must re-enroll interactively.
   * **Bootstrap Flow (Headless Nodes/Routers)**: Infinite session limit (sessions never expire). In practice the signing key's grace period bounds how long such a node can stay offline and still refresh; see [Signing-Key Retirement and Recovery](#signing-key-retirement-and-recovery).

### Proactive Refresh Lifecycle

Nodes and Routers run a background task that periodically checks the remaining Biscuit expiration:
* **Check Interval**: Every 10 minutes (`api.TokenRefreshCheckInterval`).
* **Threshold**: When the remaining token lifespan is less than 20% of its initial TTL (~4.8 hours remaining), the daemon proactively trades the expiring Biscuit for a fresh one.
* **Challenge Handshake**: The client signs a peer- and endpoint-bound timestamp challenge (`sam:refresh:<peer_id>:<unix-millis>`) with its private key and sends it to the Control Plane `/refresh` endpoint along with its expiring Biscuit in the `Authorization: Bearer <token>` header. The Control Plane verifies the signature against the registered node's public key in the database before issuing a new Biscuit.

The bootstrap surface requires the same proof of possession end to end. `POST /enroll` carries a signed timestamp challenge in the request body (`timestamp`/`challenge_signature`, and `peer_id` must be derived from the submitted `public_key`), so a bootstrap token alone can never mint — or re-fetch — another peer's Biscuit. `GET /enroll/status` answers only when the caller signs the peer-bound challenge with that same key, sent in the `X-Sam-Challenge-Ts` and `X-Sam-Challenge-Sig` headers (headers rather than query parameters, so signatures stay out of access logs). Anything else — no signature, a stale timestamp, another key, an unknown peer — receives a uniform `401`, so an approved enrollment's Biscuit is only ever released to the enrollee itself.

All three challenges share one shape — the UTF-8 bytes of `sam:<endpoint>:<peer_id>:<unix-millis>` (`sam:enroll:…`, `sam:enroll-status:…`, `sam:refresh:…`), signed by the peer's identity key and accepted within a ±5-minute freshness window. Binding the peer and the endpoint into the signed payload means a signature captured from any one request verifies nowhere else.

### Signing-Key Retirement and Recovery

Every `--key-rotation-interval` the Control Plane mints a new signing key. The previous key stays accepted for `--key-grace-period`, then it is retired: Biscuits it signed can no longer be verified by anyone, including the Control Plane. A node whose Biscuit is signed by a retired key is refused on `/refresh` (`401`), fails its role check at daemon start, and — for a router — has its lease renewal rejected. This is deliberate: the grace period is the deadline after which a node that has gone quiet cannot come back on its own, so a forgotten or stolen machine does not rejoin the mesh unnoticed.

How a node gets past that deadline depends on how it was enrolled.

* **OIDC nodes** recover on their own. The daemon exchanges its stored refresh grant for a fresh ID token and re-enrolls under the current key, keeping its PeerID. The identity provider stays authoritative: revoking the grant there ends this.
* **Bootstrap nodes and routers** (headless enrollment) have no such grant. By default they need an operator: mint a new bootstrap token and re-run `sam-node join` (or restart the router with the new token). `POST /enroll` for a peer that is already approved re-mints a fresh Biscuit under the active key instead of replaying the stored one — the role and labels come from the enrolled node record, never from the request, the peer must still prove possession of its key, a banned peer is refused, and the re-enrollment consumes one use of the token. The token's `max_usages` is therefore the operator's cap on how many times a given node can be brought back this way.

#### Autonomous recovery (opt-in)

For fleets where an operator round-trip per stale node is impractical, a bootstrap node can be allowed to recover on proof of possession alone. This is a per-node flag, `autonomous_recovery`, held only on the Control Plane's node record and never asserted by the node. It is **off by default**: a node carrying it can always renew on its own private key, so that key effectively becomes a credential that never expires. Only a ban (`POST /admin/revoke`) stops it.

Set it either when minting the bootstrap token — every node that token enrolls inherits it — or per node afterwards:

```bash
# At mint time (admin only): nodes enrolled with this token may recover autonomously
curl -X POST -H "Authorization: Bearer <your-admin-token>" -H "Content-Type: application/json" \
  -d '{"role": "sam:role:router", "ttl_hours": 24, "max_usages": 3, "autonomous_recovery": true}' \
  http://<control-plane-ip>:8080/admin/bootstrap-tokens

# Per node, for one that is already enrolled (toggle back with "enabled": false)
curl -X POST -H "Authorization: Bearer <your-admin-token>" -H "Content-Type: application/json" \
  -d '{"enabled": true}' \
  http://<control-plane-ip>:8080/admin/nodes/<peer-id>/autonomous-recovery
```

The console shows the flag in the **Recovery** column of the Nodes and Bootstrap Tokens views, with an enable/disable action for administrators.

With the flag set, `/refresh` accepts a Biscuit it can no longer verify when all of the following hold:

1. the request carries the node's `peer_id`, and an enrolled record exists for it with `autonomous_recovery` on;
2. the presented Biscuit is byte-for-byte the last one the Control Plane issued to that node — a replayed, superseded Biscuit is refused, and this is what authenticates the Biscuit in place of the signature that cannot be checked;
3. the fresh challenge is signed by the node's registered private key;
4. the node is not banned and its session has not expired.

The new Biscuit is minted under the active key with the role and labels from the node record. Until steps 1–3 all succeed, a request through this path is answered exactly like any other bad Biscuit, so the fallback does not reveal which peer IDs are enrolled. Nodes and routers send `peer_id` on every refresh; when the Biscuit verifies normally it is only cross-checked against the token.

### Administrative Revocation

Administrators can immediately revoke any active session to disable a node's ability to renew its token.
* **Endpoint**: `POST /admin/revoke`
* **Authentication**: Requires the admin token in the headers.
* **Payload**:
  ```json
  {
    "peer_id": "12D3KooW..."
  }
  ```
* **Enforcement**: Revoked nodes are marked as banned in the database. When the node next attempts a proactive `/refresh` handshake, the request is denied with a `403 Forbidden` status, and the node's local daemon immediately terminates.

---

## 6. Node Service Catalog

Each enrolled node periodically self-reports its locally registered services so the admin console's **Services** view can show what is running where, without the Control Plane joining the P2P mesh.

* **Endpoint**: `POST /nodes/catalog`
* **Authentication**: The node's own Biscuit as a `Bearer` token. The reporting peer is taken from the verified token, never from the body, so a node can only ever describe itself; reports from banned or expired enrollments are rejected.
* **Payload**: An `api.NodeCatalogReport` protobuf (`application/x-protobuf`) with up to 512 services per report.
* **Cadence**: Every minute by default (`node.Options.CatalogReportInterval`), with jitter.
* **Semantics**: A live-status cache, not authoritative state. It is display-only and never feeds authorization; the cache is in-memory and rebuilt by the nodes' next reports after a Control Plane restart. If you front the Control Plane with a Gateway allow-list, `/nodes/catalog` must be routed like the other node-facing endpoints.

---

## 7. Headless Node Enrollment (Bootstrap Token Flow)

To enroll a headless server, router, or background daemon that cannot complete interactive OIDC authentication, SAM supports a **Bootstrap Token** flow.

### Step 1: Generate a Bootstrap Token

An administrator with the `admin-token` can dynamically generate a time-bounded, single-use bootstrap token:

```bash
curl -X POST \
  -H "Authorization: Bearer <your-admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"role": "sam:role:node", "ttl_hours": 24, "max_usages": 1, "description": "Headless node deployment token"}' \
  http://<control-plane-ip>:8080/admin/bootstrap-tokens
```

This returns a JSON response containing the plaintext token:
```json
{
  "id": "62e92ffca...",
  "token": "sam-bt-72fb0175788dee0...",
  "role": "sam:role:node",
  "expires_at": "2026-07-12T15:00:00Z"
}
```

The request also accepts `"autonomous_recovery": true` (admin only), which lets every node enrolled with the token refresh its Biscuit after the signing key that issued it has been retired; see [Autonomous recovery](#autonomous-recovery-opt-in) before turning it on.

A token that is no longer wanted — a multi-use token being decommissioned early, or one that leaked — can be revoked before it expires. Revocation is a soft state on the token (it stays listed, marked revoked, so the audit trail of what it enrolled is kept), is idempotent, and is enforced on every `/enroll`, including re-enrollment of a node it previously approved:

```bash
curl -X DELETE -H "Authorization: Bearer <your-admin-token>" \
  http://<control-plane-ip>:8080/admin/bootstrap-tokens/<token-id>
```

### Step 2: Request Enrollment on the Node

Run the node `join` command with the generated token:

```bash
sam-node join --bootstrap-token sam-bt-72fb0175788dee0... http://<control-plane-ip>:8080
```

The node submits its enrollment request and waits (polls) for approval.

### Step 3: Approve the Enrollment

Administrators can review pending enrollment requests:

```bash
# List all pending enrollments
curl -H "Authorization: Bearer <your-admin-token>" http://<control-plane-ip>:8080/admin/enrollments
```

To approve the request and issue the node its identity Biscuit:

```bash
curl -X POST \
  -H "Authorization: Bearer <your-admin-token>" \
  http://<control-plane-ip>:8080/admin/enrollments/<request-id>/approve
```

Alternatively, you can boot the control plane with `--auto-approve-enrollment` to automatically approve all valid bootstrap token requests without manual gates.

### Re-enrolling a node that is already approved

Running `sam-node join` again for a peer the Control Plane has already approved — after `sam-node reset`, or because its Biscuit was signed by a key that has since been retired — does not go back through the approval queue. As long as the token is valid, unrevoked and has usages left, the peer proves possession of the same key, its role matches the token's, and it is not banned, `POST /enroll` mints a fresh Biscuit under the current signing key from the stored node record and returns it immediately. This is the manual recovery path described in [Signing-Key Retirement and Recovery](#signing-key-retirement-and-recovery); no database intervention is needed.

