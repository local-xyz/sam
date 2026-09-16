//go:build sam_debug

package ffi

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"

	"github.com/google/sam/api"
	"github.com/google/sam/internal/node"
)

// SharedMeshA2APublication asks the running shared mesh to advertise the
// app's loopback A2A server as an a2a:// service.
type SharedMeshA2APublication struct {
	Name         string `json:"name"`
	DisplayName  string `json:"displayName"`
	BackendURL   string `json:"backendUrl"`
	BackendToken string `json:"backendToken"`
}

// SharedMeshA2AProvider is one a2a:// service advertised by a mesh peer.
type SharedMeshA2AProvider struct {
	PeerID      string `json:"peerId"`
	ServiceName string `json:"serviceName"`
	Description string `json:"description"`
}

// SharedMeshA2ADiscovery is a complete report of one discovery attempt,
// including partial failures, matching the MCP discovery contract.
type SharedMeshA2ADiscovery struct {
	Providers []SharedMeshA2AProvider           `json:"providers"`
	Failures  []node.SharedMeshDiscoveryFailure `json:"failures"`
}

// a2aGateway is the loopback egress listener for the current shared mesh.
// It exists so the app can speak plain HTTP to /sam/<peer>/a2a/<svc>/...
// and inherit the node's biscuit, label gating and agent-card regeneration.
// Guarded by mu; bound to one sharedMesh instance so a gateway for a closed
// mesh is never reused.
type a2aGateway struct {
	mesh   *sharedMesh
	server *http.Server
	url    string
	token  string
}

var activeA2AGateway *a2aGateway

func (r *sharedMesh) publishA2A(ctx context.Context, p SharedMeshA2APublication) error {
	if p.Name == "" || p.BackendURL == "" || p.BackendToken == "" {
		return errors.New("name, backendUrl and backendToken are required")
	}
	return r.node.RegisterSharedMeshA2ABackend(ctx, p.Name, p.DisplayName, p.BackendURL, p.BackendToken)
}

func (r *sharedMesh) discoverA2A(ctx context.Context) (SharedMeshA2ADiscovery, error) {
	discovery, err := r.node.DiscoverSharedMeshA2AProviders(ctx, r.admitConnection)
	if err != nil {
		return SharedMeshA2ADiscovery{}, err
	}
	result := SharedMeshA2ADiscovery{Providers: []SharedMeshA2AProvider{}, Failures: append([]node.SharedMeshDiscoveryFailure{}, discovery.Failures...)}
	for _, p := range discovery.Providers {
		result.Providers = append(result.Providers, SharedMeshA2AProvider{PeerID: p.PeerId, ServiceName: p.SrvName, Description: p.SrvDescription})
	}
	return result, nil
}

// startA2AGateway starts (or returns the already-running) loopback egress
// listener for this mesh. The bearer token gates the local port: on Android
// any app can dial loopback, so an ungated listener would let another app
// spend this node's mesh identity. The token travels in X-Sam-Authentication,
// which the egress chokepoint already strips before anything leaves the node,
// so it can never ride a forwarded request; Authorization stays untouched and
// passes through to the remote agent as its own credential.
func (r *sharedMesh) startA2AGateway() (gatewayURL, token string, err error) {
	if existing := activeA2AGateway; existing != nil && existing.mesh == r {
		return existing.url, existing.token, nil
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	secret := base64.RawURLEncoding.EncodeToString(raw)
	expected := []byte("Bearer " + secret)
	upstream := r.node.SharedMeshEgressHandler()
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		presented := []byte(req.Header.Get(api.HeaderSamAuthentication))
		if subtle.ConstantTimeCompare(expected, presented) != 1 {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		upstream.ServeHTTP(w, req)
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", "", err
	}
	server := &http.Server{Handler: handler}
	gateway := &a2aGateway{mesh: r, server: server, url: "http://" + listener.Addr().String(), token: secret}
	go func() { _ = server.Serve(listener) }()
	// The gateway lives exactly as long as its mesh: close() cancels r.ctx.
	go func() {
		<-r.ctx.Done()
		_ = server.Close()
		mu.Lock()
		if activeA2AGateway == gateway {
			activeA2AGateway = nil
		}
		mu.Unlock()
	}()
	activeA2AGateway = gateway
	return gateway.url, gateway.token, nil
}

// PublishSharedMeshA2AService registers the app's loopback A2A backend on
// the running shared mesh. Returns {} on success or {"error": ...}.
func PublishSharedMeshA2AService(requestJSON string) string {
	r, ctx, cancel := sharedSnapshot()
	defer cancel()
	if r == nil {
		return `{"error":"shared mesh is stopped"}`
	}
	var p SharedMeshA2APublication
	if err := json.Unmarshal([]byte(requestJSON), &p); err != nil {
		return `{"error":"invalid A2A publication request"}`
	}
	if err := r.publishA2A(ctx, p); err != nil {
		return sharedJSON(nil, err)
	}
	return `{}`
}

// StartSharedMeshA2AGateway starts the loopback egress listener and returns
// {"url": ..., "token": ...}. Idempotent while the same mesh is running.
func StartSharedMeshA2AGateway() string {
	mu.Lock()
	r := activeSharedMesh
	if r == nil {
		mu.Unlock()
		return `{"error":"shared mesh is stopped"}`
	}
	gatewayURL, token, err := r.startA2AGateway()
	mu.Unlock()
	return sharedJSON(map[string]string{"url": gatewayURL, "token": token}, err)
}

// DiscoverSharedMeshA2AServices lists a2a:// providers on the mesh.
func DiscoverSharedMeshA2AServices() string {
	r, ctx, cancel := sharedSnapshot()
	defer cancel()
	if r == nil {
		return `{"error":"shared mesh is stopped"}`
	}
	v, err := r.discoverA2A(ctx)
	return sharedJSON(v, err)
}
