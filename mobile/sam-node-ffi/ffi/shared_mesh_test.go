//go:build sam_debug

package ffi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"github.com/google/sam/api"
	"github.com/google/sam/internal/identity"
	"github.com/google/sam/internal/node"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"google.golang.org/protobuf/proto"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/sam/internal/standalone"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestSharedMeshDiscoveryCallRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
	var caller string
	server := mcp.NewServer(&mcp.Implementation{Name: "bob", Version: "1"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "read_demo_note", Description: "Read the published note"}, func(ctx context.Context, req *mcp.CallToolRequest, args struct{}) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Bob native transport sentinel"}}}, nil, nil
	})
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" || r.Header.Get("X-Peer-Id") == "" {
			http.Error(w, "unauthorized", 401)
			return
		}
		lock.Lock()
		caller = r.Header.Get("X-Peer-Id")
		lock.Unlock()
		handler.ServeHTTP(w, r)
	}))
	defer backend.Close()
	cfg := SharedMeshConfig{DataDir: t.TempDir(), BootstrapURL: "http://" + host.Addr(), JoinToken: host.JoinToken(), DisplayName: "Bob", BackendURL: backend.URL, BackendToken: "secret"}
	startupCtx, finishStartup := context.WithCancel(ctx)
	bob, err := newSharedMesh(startupCtx, cfg)
	finishStartup()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if bob != nil {
			bob.close()
		}
	}()
	if bob.ctx.Err() != nil {
		t.Fatal("completed startup retained parent cancellation")
	}
	alice, err := newSharedMesh(ctx, SharedMeshConfig{DataDir: t.TempDir(), BootstrapURL: cfg.BootstrapURL, JoinToken: cfg.JoinToken, DisplayName: "Alice"})
	if err != nil {
		t.Fatal(err)
	}
	defer alice.close()
	var discovery SharedMeshDiscovery
	var discovered []SharedMeshTool
	for ctx.Err() == nil {
		discovery, err = alice.discover(ctx)
		discovered = discovery.Tools
		if err == nil && len(discovered) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(discovered) != 1 {
		t.Fatalf("want one published tool, got %d: %v", len(discovered), err)
	}
	result, err := alice.call(ctx, SharedMeshCall{PeerID: discovered[0].PeerID, ToolName: discovered[0].ToolName, Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Content) != 1 || result.Content[0].(*mcp.TextContent).Text != "Bob native transport sentinel" {
		t.Fatalf("wrong provider result: %+v", result)
	}
	relayed := false
	for _, conn := range alice.node.Host.Network().ConnsToPeer(bob.node.Host.ID()) {
		if strings.Contains(conn.RemoteMultiaddr().String(), "/p2p-circuit") {
			relayed = true
		}
	}
	if !relayed {
		t.Fatal("native call bypassed router over direct peer connection")
	}
	lock.Lock()
	gotCaller := caller
	lock.Unlock()
	if gotCaller != alice.node.Host.ID().String() {
		t.Fatalf("verified caller=%q", gotCaller)
	}
	id := bob.node.Host.ID()
	bob.close()
	bob = nil
	bob, err = newSharedMesh(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if bob.node.Host.ID() != id {
		t.Fatal("identity changed")
	}
	encoded, _ := json.Marshal(discovered)
	t.Log(string(encoded))
}

func TestSharedMeshForeignIssuerAndStop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	makeHost := func() *standalone.Server {
		h, e := standalone.New(standalone.Options{BindAddress: "127.0.0.1:0", DataDir: t.TempDir()})
		if e != nil {
			t.Fatal(e)
		}
		if e = h.Start(ctx); e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { h.Close() })
		return h
	}
	host := makeHost()
	server := mcp.NewServer(&mcp.Implementation{Name: "bob", Version: "1"}, nil)
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	mcp.AddTool(server, &mcp.Tool{Name: "slow"}, func(ctx context.Context, req *mcp.CallToolRequest, args struct{}) (*mcp.CallToolResult, any, error) {
		select {
		case started <- struct{}{}:
		default:
		}
		select {
		case <-ctx.Done():
		case <-release:
		}
		return nil, nil, context.Canceled
	})
	backend := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true}))
	defer backend.Close()
	defer close(release)
	bob, e := newSharedMesh(ctx, SharedMeshConfig{DataDir: t.TempDir(), BootstrapURL: "http://" + host.Addr(), JoinToken: host.JoinToken(), BackendURL: backend.URL, BackendToken: "secret"})
	if e != nil {
		t.Fatal(e)
	}
	defer bob.close()
	rogue, e := newSharedMesh(ctx, SharedMeshConfig{DataDir: t.TempDir(), BootstrapURL: "http://" + host.Addr(), JoinToken: host.JoinToken()})
	if e != nil {
		t.Fatal(e)
	}
	defer rogue.close()
	// Keep a usable authorized relay channel, but present a validly formed node
	// credential signed by a foreign issuer to Bob's application handshake.
	_, foreignKey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	foreignToken, e := identity.MintBootstrapBiscuitToken(foreignKey, rogue.node.Host.ID(), api.RoleNode, time.Now().Add(time.Hour), nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = rogue.store.SaveIdentity(foreignToken); e != nil {
		t.Fatal(e)
	}
	rogue.node.SetIdentityCache(foreignToken)
	rogue.node.Host.Peerstore().AddAddrs(bob.node.Host.ID(), bob.node.Host.Addrs(), time.Minute)
	_, e = rogue.call(ctx, SharedMeshCall{PeerID: bob.node.Host.ID().String(), ToolName: "mcp://android-notes/slow"})
	if !errors.Is(e, node.ErrAuthRejected) {
		t.Fatalf("foreign issuer accepted or wrong error: %v", e)
	}
	select {
	case <-started:
		t.Fatal("foreign issuer reached backend")
	default:
	}
	config := SharedMeshConfig{DataDir: t.TempDir(), BootstrapURL: "http://" + host.Addr(), JoinToken: host.JoinToken()}
	encoded, _ := json.Marshal(config)
	if e = StartSharedMesh(string(encoded)); e != nil {
		t.Fatal(e)
	}
	defer StopSharedMesh()
	call, _ := json.Marshal(SharedMeshCall{PeerID: bob.node.Host.ID().String(), ToolName: "mcp://android-notes/slow"})
	// Discovery primes the real SAM DHT and relay address path.
	tools := DiscoverSharedMeshTools()
	if !strings.Contains(tools, "slow") {
		t.Fatalf("discovery failed: %s", tools)
	}
	finished := make(chan string, 1)
	go func() { finished <- CallSharedMeshTool(string(call)) }()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("backend never called")
	}
	before := time.Now()
	if e = StopSharedMesh(); e != nil {
		t.Fatal(e)
	}
	select {
	case result := <-finished:
		if !strings.Contains(result, "error") {
			t.Fatalf("stopped call succeeded: %s", result)
		}
	case <-time.After(time.Second):
		t.Fatal("stop failed to cancel invocation")
	}
	if time.Since(before) > time.Second {
		t.Fatal("stop was not bounded")
	}
	if !strings.Contains(SharedMeshStatus(), `"state":"stopped"`) {
		t.Fatal(SharedMeshStatus())
	}
}

// A real libp2p peer accepts the router auth stream but never answers it.
// The enrollment proxy only changes the router address; credentials remain real.
func stalledSharedMeshConfig(t *testing.T) (SharedMeshConfig, <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	authority, err := standalone.New(standalone.Options{BindAddress: "127.0.0.1:0", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err = authority.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { authority.Close() })
	router, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { router.Close() })
	entered := make(chan struct{}, 1)
	router.SetStreamHandler(api.AuthProtocolID, func(s network.Stream) {
		select {
		case entered <- struct{}{}:
		default:
		}
		defer s.Close()
		_, _ = io.Copy(io.Discard, s)
	})
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := http.NewRequestWithContext(r.Context(), r.Method, "http://"+authority.Addr()+r.URL.Path, r.Body)
		if err != nil {
			http.Error(w, "request", 500)
			return
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, "upstream", 500)
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if r.URL.Path == "/enroll" {
			enrolled := new(api.BootstrapEnrollResponse)
			if err := proto.Unmarshal(body, enrolled); err != nil {
				http.Error(w, "decode", 500)
				return
			}
			enrolled.RouterAddresses = []string{router.Addrs()[0].String() + "/p2p/" + router.ID().String()}
			body, _ = proto.Marshal(enrolled)
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
	}))
	t.Cleanup(proxy.Close)
	return SharedMeshConfig{DataDir: t.TempDir(), BootstrapURL: proxy.URL, JoinToken: authority.JoinToken()}, entered
}
func TestSharedMeshStartupDeadline(t *testing.T) {
	cfg, entered := stalledSharedMeshConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	before := time.Now()
	r, err := newSharedMesh(ctx, cfg)
	if r != nil {
		r.close()
	}
	if err == nil {
		t.Fatal("stalled startup succeeded")
	}
	select {
	case <-entered:
	default:
		t.Fatal("test did not reach native router handshake")
	}
	if elapsed := time.Since(before); elapsed > time.Second {
		t.Fatalf("startup ignored deadline: %s", elapsed)
	}
	store, err := node.NewStore(filepath.Join(cfg.DataDir, "shared-mesh-v1"))
	if err != nil {
		t.Fatalf("startup leaked store: %v", err)
	}
	store.Close()
}
func TestSharedMeshStopDuringStartup(t *testing.T) {
	for name, stop := range map[string]func() error{"shared": StopSharedMesh, "generic": StopNode} {
		t.Run(name, func(t *testing.T) { testSharedMeshStopDuringStartup(t, stop) })
	}
}
func testSharedMeshStopDuringStartup(t *testing.T, stop func() error) {
	cfg, entered := stalledSharedMeshConfig(t)
	data, _ := json.Marshal(cfg)
	finished := make(chan error, 1)
	go func() { finished <- StartSharedMesh(string(data)) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("startup did not reach handshake")
	}
	if err := StartLocalTestNode(t.TempDir()); err == nil {
		t.Fatal("local fixture stole startup slot")
	}
	if err := StartSharedMesh(string(data)); err == nil {
		t.Fatal("second startup stole slot")
	}
	status := make(chan string, 1)
	go func() { status <- SharedMeshStatus() }()
	select {
	case s := <-status:
		if !strings.Contains(s, `"state":"starting"`) {
			t.Fatalf("startup state: %s", s)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("status blocked behind startup")
	}
	stopped := make(chan error, 1)
	go func() { stopped <- stop() }()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("stop did not cancel initialization")
	}
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("canceled start succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("startup orphaned")
	}
	if !strings.Contains(SharedMeshStatus(), `"state":"stopped"`) {
		t.Fatal(SharedMeshStatus())
	}
	store, err := node.NewStore(filepath.Join(cfg.DataDir, "shared-mesh-v1"))
	if err != nil {
		t.Fatalf("stop leaked startup store: %v", err)
	}
	store.Close()
}
