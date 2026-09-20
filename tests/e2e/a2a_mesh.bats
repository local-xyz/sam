#!/usr/bin/env bats

load "lib/container_mesh.bash"

A2A_ECHO_IMAGE="sam-a2a-echo:local"

build_a2a_echo_image() {
  if ! docker image inspect "${A2A_ECHO_IMAGE}" >/dev/null 2>&1; then
    docker build -t "${A2A_ECHO_IMAGE}" \
      -f tests/e2e/docker/a2a-echo/Dockerfile \
      tests/e2e/docker/a2a-echo >/dev/null
  fi
}

start_a2a_echo() {
  local name="${MESH_PREFIX}-a2a-echo"
  docker run -d \
    --name "${name}" \
    --network "${MESH_NETWORK}" \
    --network-alias a2a-echo \
    "${A2A_ECHO_IMAGE}" >/dev/null
  MESH_CONTAINERS+=("${name}")
  mesh_wait_for_log "${name}" "Uvicorn running on" 30
}

setup() {
  mesh_setup_env
  build_a2a_echo_image
}

teardown() {
  mesh_cleanup_env
}

# CUJ: bring a stock a2a-sdk agent onto the mesh via node config, then use a
# stock a2a-sdk client on another node — bootstrapping from the regenerated
# agent card — plus the fail-closed labels gate on the raw a2a egress path.
@test "a2a: stock SDK client chats with a mesh-hosted agent via the regenerated card" {
  run mesh_start_mock_oidc
  [[ "$status" -eq 0 ]]

  mesh_start_router

  echo "[$(date +%T)] Starting Node 1 (consumer)"
  mesh_start_node 1 "--log-level debug"
  mesh_wait_for_log "${MESH_PREFIX}-node-1" "SAM Node Online" 60
  mesh_wait_for_mcp_ready 1 20

  echo "[$(date +%T)] Starting a2a echo agent backend"
  start_a2a_echo

  echo "[$(date +%T)] Starting Node 2 (provider, region=eu) with the echo service"
  mesh_start_node 2 \
    "--log-level debug" \
    "tests/e2e/docker/a2a-echo/sam-node-config.yaml"
  mesh_wait_for_log "${MESH_PREFIX}-node-2" "SAM Node Online" 20
  mesh_wait_for_mcp_ready 2 20

  local node2_peer_id
  node2_peer_id=$(docker logs "${MESH_PREFIX}-node-2" 2>&1 | grep "PeerID:" | head -n 1 | awk '{print $2}' | tr -d '\r')

  echo "[$(date +%T)] Connecting Node 1 to Node 2"
  local node2_addr="/dns4/${MESH_PREFIX}-node-2/tcp/5002/p2p/${node2_peer_id}"
  run mesh_connect_peer 1 "${node2_addr}"
  [[ "$status" -eq 0 ]]
  mesh_wait_for_peer_connection 1 "${node2_peer_id}" 20

  local mesh_base="http://${MESH_PREFIX}-node-1:8080/sam/${node2_peer_id}/a2a/echo"

  # Stock python client: resolves the card through the mesh (client.py asserts
  # the regenerated URLs, the gRPC drop and streaming preservation) and gets an echo.
  echo "[$(date +%T)] Running stock a2a-sdk client against ${mesh_base}"
  run docker run --rm --network "${MESH_NETWORK}" \
    -e SAM_API_TOKEN="secret-token" \
    "${A2A_ECHO_IMAGE}" python3 /workspace/client.py "${mesh_base}" "hello mesh"
  echo "client output: $output"
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"agent> echo: hello mesh"* ]]

  local send_body='{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{}}'

  # The label the provider attests (region=eu) is admitted end to end over
  # the real attestation chain — same stock client, labels via header.
  # Retried: the gate fail-closes a slow biscuit-fetch handshake into the
  # same 403 as a denial ("labels unverifiable: ... context deadline
  # exceeded", seen under CI load); a genuine denial fails all attempts.
  echo "[$(date +%T)] Labelled send (region=eu) must be admitted"
  local attempt
  for attempt in 1 2 3; do
    run docker run --rm --network "${MESH_NETWORK}" \
      -e SAM_API_TOKEN="secret-token" \
      -e SAM_REQUIRED_LABELS="region=eu" \
      "${A2A_ECHO_IMAGE}" python3 /workspace/client.py "${mesh_base}" "hello eu"
    [[ "$status" -eq 0 ]] && break
    echo "labelled attempt ${attempt} failed, node-1 label gate verdicts:"
    docker logs "${MESH_PREFIX}-node-1" 2>&1 | grep -F '[A2A]' || true
    sleep 2
  done
  echo "labelled client output: $output"
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"agent> echo: hello eu"* ]]

  # A label the provider does not attest refuses fail-closed before egress:
  # the 403 comes from the caller-side gate before the body is even parsed.
  echo "[$(date +%T)] Labelled send (region=us-east-1) must fail closed"
  run docker run --rm --network "${MESH_NETWORK}" python:3.12 curl -s -o /dev/null -w '%{http_code}' \
    -X POST "${mesh_base}/" \
    -H "X-Sam-Authentication: Bearer secret-token" \
    -H "X-Sam-Required-Labels: region=us-east-1" \
    -H "Content-Type: application/json" \
    --max-time 30 \
    -d "${send_body}"
  echo "mismatched-label status: $output"
  [[ "$status" -eq 0 ]]
  [[ "$output" == "403" ]]
}
