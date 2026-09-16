//go:build sam_debug

package ffi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/google/sam/api"
	"github.com/google/sam/internal/standalone"
)

// TestSharedMeshA2ACardAndCall proves the full mobile A2A slice: Bob's app
// publishes a loopback A2A backend as a2a://personal-agent; Alice discovers
// it by type, then talks plain HTTP to her local gateway, which attaches her
// biscuit, fetches Bob's agent card over the mesh, and regenerates it so the
// interfaces point back through her node.
func TestSharedMeshA2ACardAndCall(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	host, err := standalone.New(standalone.Options{BindAddress: "127.0.0.1:0", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err = host.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer host.Close()

	var lock sync.Mutex
	var callerPeer, callerAuth, leakedBiscuit string
	card := `{"name":"personal-agent","description":"Bob's personal agent","version":"0.1.0",` +
		`"supportedInterfaces":[{"url":"http://127.0.0.1/","protocolBinding":"JSONRPC","protocolVersion":"1.0"}],` +
		`"capabilities":{},"skills":[{"id":"review_pr","name":"review_pr","description":"Review a pull request","tags":["code"]}],` +
		`"defaultInputModes":["application/json"],"defaultOutputModes":["application/json"]}`
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer a2a-secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, card)
			return
		}
		lock.Lock()
		callerPeer = r.Header.Get("X-Peer-Id")
		callerAuth = r.Header.Get("Authorization")
		leakedBiscuit = r.Header.Get(api.HeaderSamBiscuit)
		lock.Unlock()
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"1","result":{"echo":` + string(body) + `}}`))
	}))
	defer backend.Close()

	cfg := SharedMeshConfig{DataDir: t.TempDir(), BootstrapURL: "http://" + host.Addr(), JoinToken: host.JoinToken(), DisplayName: "Bob"}
	bob, err := newSharedMesh(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer bob.close()
	if err := bob.publishA2A(ctx, SharedMeshA2APublication{
		Name: "personal-agent", DisplayName: "Bob", BackendURL: backend.URL, BackendToken: "a2a-secret",
	}); err != nil {
		t.Fatal(err)
	}

	alice, err := newSharedMesh(ctx, SharedMeshConfig{DataDir: t.TempDir(), BootstrapURL: cfg.BootstrapURL, JoinToken: cfg.JoinToken, DisplayName: "Alice"})
	if err != nil {
		t.Fatal(err)
	}
	defer alice.close()

	var discovery SharedMeshA2ADiscovery
	for ctx.Err() == nil {
		discovery, err = alice.discoverA2A(ctx)
		if err == nil && len(discovery.Providers) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(discovery.Providers) != 1 || discovery.Providers[0].ServiceName != "personal-agent" {
		t.Fatalf("want one a2a provider, got %+v (err=%v)", discovery, err)
	}
	if discovery.Providers[0].PeerID != bob.node.Host.ID().String() {
		t.Fatalf("provider peer = %q, want Bob", discovery.Providers[0].PeerID)
	}

	mu.Lock()
	gatewayURL, token, err := alice.startA2AGateway()
	mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	base := gatewayURL + "/sam/" + discovery.Providers[0].PeerID + "/a2a/personal-agent"

	// The local port is bearer-gated: without the token nothing moves.
	ungated, err := http.Get(base + "/.well-known/agent-card.json")
	if err != nil {
		t.Fatal(err)
	}
	_ = ungated.Body.Close()
	if ungated.StatusCode != http.StatusUnauthorized {
		t.Fatalf("ungated gateway request: HTTP %d, want 401", ungated.StatusCode)
	}

	client := &http.Client{Timeout: sharedMeshTimeout}
	get := func(url string) *http.Response {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(api.HeaderSamAuthentication, "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	// Agent card is fetched over the mesh and regenerated for mesh use.
	cardResp := get(base + "/.well-known/agent-card.json")
	defer func() { _ = cardResp.Body.Close() }()
	if cardResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(cardResp.Body)
		t.Fatalf("card fetch: HTTP %d: %s", cardResp.StatusCode, body)
	}
	var fetched a2a.AgentCard
	if err := json.NewDecoder(cardResp.Body).Decode(&fetched); err != nil {
		t.Fatal(err)
	}
	if len(fetched.Skills) != 1 || fetched.Skills[0].ID != "review_pr" {
		t.Fatalf("card lost its skills: %+v", fetched.Skills)
	}
	if len(fetched.SupportedInterfaces) != 1 || !strings.Contains(fetched.SupportedInterfaces[0].URL, "/sam/"+discovery.Providers[0].PeerID+"/a2a/personal-agent") {
		t.Fatalf("card interface not regenerated for the mesh: %+v", fetched.SupportedInterfaces)
	}

	// JSON-RPC POST rides the same path; Bob's backend sees Alice's
	// transport-verified peer ID and its own bearer, never her biscuit.
	body := `{"jsonrpc":"2.0","id":"1","method":"message/send","params":{}}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(api.HeaderSamAuthentication, "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(payload), `"echo"`) {
		t.Fatalf("message/send: HTTP %d: %s", resp.StatusCode, payload)
	}
	lock.Lock()
	defer lock.Unlock()
	if callerPeer != alice.node.Host.ID().String() {
		t.Fatalf("backend saw peer %q, want Alice", callerPeer)
	}
	if callerAuth != "Bearer a2a-secret" {
		t.Fatalf("backend saw credential %q", callerAuth)
	}
	if leakedBiscuit != "" {
		t.Fatal("Alice's biscuit leaked to Bob's backend")
	}
}
