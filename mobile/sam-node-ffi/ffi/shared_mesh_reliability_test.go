//go:build sam_debug

package ffi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/sam/internal/node"
	"github.com/google/sam/internal/standalone"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/time/rate"
)

func newReliabilityMeshPair(t *testing.T, ctx context.Context) (*sharedMesh, *sharedMesh) {
	t.Helper()
	host, err := standalone.New(standalone.Options{BindAddress: "127.0.0.1:0", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err = host.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	server := mcp.NewServer(&mcp.Implementation{Name: "bob", Version: "1"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "read_demo_note"}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "sentinel"}}}, nil, nil
	})
	backend := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true}))
	t.Cleanup(backend.Close)
	cfg := SharedMeshConfig{DataDir: t.TempDir(), BootstrapURL: "http://" + host.Addr(), JoinToken: host.JoinToken(), DisplayName: "Bob", BackendURL: backend.URL, BackendToken: "secret"}
	bob, err := newSharedMesh(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bob.close() })
	alice, err := newSharedMesh(ctx, SharedMeshConfig{DataDir: t.TempDir(), BootstrapURL: cfg.BootstrapURL, JoinToken: cfg.JoinToken, DisplayName: "Alice"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = alice.close() })
	return bob, alice
}

func waitForReliabilityTool(t *testing.T, ctx context.Context, alice *sharedMesh) SharedMeshTool {
	t.Helper()
	for ctx.Err() == nil {
		discovery, err := alice.discover(ctx)
		if err == nil && len(discovery.Tools) == 1 {
			return discovery.Tools[0]
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("published service never became discoverable")
	return SharedMeshTool{}
}

func TestSharedMeshPacingKeepsRepeatedDiscoveryAndCallsReliable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 9*time.Second)
	defer cancel()
	_, alice := newReliabilityMeshPair(t, ctx)
	tool := waitForReliabilityTool(t, ctx, alice)
	for range 3 {
		discovery, err := alice.discover(ctx)
		if err != nil || len(discovery.Tools) != 1 || len(discovery.Failures) != 0 {
			t.Fatalf("paced discovery failed: tools=%d failures=%+v err=%v", len(discovery.Tools), discovery.Failures, err)
		}
		result, err := alice.call(ctx, SharedMeshCall{PeerID: tool.PeerID, ToolName: tool.ToolName, Arguments: map[string]any{}})
		if err != nil {
			t.Fatalf("paced call failed: %v", err)
		}
		if len(result.Content) != 1 || result.Content[0].(*mcp.TextContent).Text != "sentinel" {
			t.Fatalf("wrong paced result: %+v", result)
		}
	}
	target, err := peer.Decode(tool.PeerID)
	if err != nil {
		t.Fatal(err)
	}
	admissionFailure := errors.New("admission fixture")
	admissionCalls := 0
	_, err = alice.node.CallSharedMeshToolOnce(ctx, target, tool.ToolName, map[string]any{}, func(context.Context, peer.ID) error {
		admissionCalls++
		return admissionFailure
	})
	if !errors.Is(err, admissionFailure) || admissionCalls != 1 {
		t.Fatalf("single-attempt boundary retried admission: calls=%d err=%v", admissionCalls, err)
	}

	cancelled, stop := context.WithCancel(context.Background())
	if err := alice.admitConnection(cancelled, target); err != nil {
		t.Fatal(err)
	}
	stop()
	if err := alice.admitConnection(cancelled, target); !errors.Is(err, context.Canceled) {
		t.Fatalf("paced wait ignored cancellation: %v", err)
	}
}

func TestSharedMeshConnectionLimitersAreBoundedAndRetainActivePeers(t *testing.T) {
	cache, err := lru.New[peer.ID, *rate.Limiter](node.RateLimiterSize)
	if err != nil {
		t.Fatal(err)
	}
	mesh := &sharedMesh{admission: cache}
	active := peer.ID("active-peer")
	activeLimiter := mesh.connectionLimiter(active)
	for i := range node.RateLimiterSize - 1 {
		mesh.connectionLimiter(peer.ID(fmt.Sprintf("peer-%d", i)))
	}
	if mesh.admission.Len() != node.RateLimiterSize {
		t.Fatalf("limiter cache size=%d want=%d", mesh.admission.Len(), node.RateLimiterSize)
	}
	// Touching an active peer makes it most-recently used before another peer arrives.
	if mesh.connectionLimiter(active) != activeLimiter {
		t.Fatal("active peer limiter was evicted before its reuse")
	}
	mesh.connectionLimiter(peer.ID("one-more-peer"))
	if mesh.admission.Len() != node.RateLimiterSize || !mesh.admission.Contains(active) {
		t.Fatalf("peer churn evicted active limiter or exceeded bound: size=%d active=%v", mesh.admission.Len(), mesh.admission.Contains(active))
	}
}
