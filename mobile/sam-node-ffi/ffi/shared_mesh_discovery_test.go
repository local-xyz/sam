//go:build sam_debug

package ffi

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/google/sam/api"
	"github.com/google/sam/internal/node"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func discoveryTestPeer(t *testing.T) peer.ID {
	t.Helper()
	key, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := peer.IDFromPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestSharedMeshDiscoveryRetainsSuccessfulToolsAndEveryFailure(t *testing.T) {
	id := discoveryTestPeer(t)
	services := node.SharedMeshServiceDiscovery{
		Providers: []*api.DiscoveredProvider{
			{PeerId: id.String(), SrvName: "healthy"},
			{PeerId: id.String(), SrvName: "broken"},
		},
		Failures: []node.SharedMeshDiscoveryFailure{node.SharedMeshFailure(id, "", "service_catalog", io.EOF)},
	}
	result, err := collectSharedMeshTools(context.Background(), services,
		func(_ context.Context, p *api.DiscoveredProvider) ([]*mcp.Tool, string, error) {
			if p.SrvName == "broken" {
				return nil, "tools_list", fmt.Errorf("secret remote payload: %w", network.ErrReset)
			}
			return []*mcp.Tool{{Name: "greet", Description: "Greeting", InputSchema: map[string]any{"type": "object"}}}, "", nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Tools) != 1 || result.Tools[0].ServiceName != "healthy" {
		t.Fatalf("successful tools lost: %+v", result)
	}
	if len(result.Failures) != 2 || result.Failures[0].Stage != "service_catalog" || result.Failures[1].ServiceName != "broken" || result.Failures[1].Reason != "stream_reset" {
		t.Fatalf("failures lost: %+v", result)
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "secret") {
		t.Fatalf("remote error text leaked: %s", data)
	}
}

func TestSharedMeshDiscoveryDistinguishesEmptyFromUnavailable(t *testing.T) {
	id := discoveryTestPeer(t)
	for _, unavailable := range []bool{false, true} {
		services := node.SharedMeshServiceDiscovery{}
		if unavailable {
			services.Failures = []node.SharedMeshDiscoveryFailure{node.SharedMeshFailure(id, "", "service_catalog", io.EOF)}
		}
		result, err := collectSharedMeshTools(context.Background(), services, nil)
		if err != nil {
			t.Fatal(err)
		}
		if result.Tools == nil || result.Failures == nil {
			t.Fatal("wire arrays must not be null")
		}
		if (len(result.Failures) != 0) != unavailable {
			t.Fatalf("incomplete discovery marked complete: %+v", result)
		}
	}
}

func TestSharedMeshDiscoveryCancellationIsNotPartialSuccess(t *testing.T) {
	id := discoveryTestPeer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := collectSharedMeshTools(ctx, node.SharedMeshServiceDiscovery{Providers: []*api.DiscoveredProvider{{PeerId: id.String(), SrvName: "test"}}},
		func(context.Context, *api.DiscoveredProvider) ([]*mcp.Tool, string, error) {
			cancel()
			return nil, "connect", ctx.Err()
		})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation swallowed: %v", err)
	}
}

func TestSharedMeshFailureUsesSafeWrappedErrorReasons(t *testing.T) {
	id := discoveryTestPeer(t)
	for _, tc := range []struct {
		err    error
		reason string
	}{
		{node.ErrAuthRejected, "authentication_rejected"},
		{context.DeadlineExceeded, "timeout"},
		{network.ErrReset, "stream_reset"},
		{io.ErrUnexpectedEOF, "connection_closed"},
		{errors.New("private provider details"), "unavailable"},
	} {
		failure := node.SharedMeshFailure(id, "test", "connect", fmt.Errorf("private wrapper: %w", tc.err))
		if failure.Reason != tc.reason {
			t.Errorf("%v: got %s want %s", tc.err, failure.Reason, tc.reason)
		}
	}
}
