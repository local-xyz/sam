//go:build sam_debug

package ffi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/sam/api"
	"github.com/google/sam/internal/identity"
	"github.com/google/sam/internal/node"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/multiformats/go-multiaddr"
	"golang.org/x/time/rate"
	"google.golang.org/protobuf/proto"
)

const sharedMeshService = "android-notes"
const sharedMeshTimeout = 20 * time.Second

type SharedMeshConfig struct {
	DataDir      string `json:"dataDir"`
	BootstrapURL string `json:"bootstrapUrl"`
	JoinToken    string `json:"joinToken"`
	DisplayName  string `json:"displayName"`
	BackendURL   string `json:"backendUrl,omitempty"`
	BackendToken string `json:"backendToken,omitempty"`
}
type SharedMeshTool struct {
	PeerID      string `json:"peerId"`
	ServiceName string `json:"serviceName"`
	ToolName    string `json:"toolName"`
	Description string `json:"description"`
	InputSchema any    `json:"inputSchema"`
}
type SharedMeshCall struct {
	PeerID    string         `json:"peerId"`
	ToolName  string         `json:"toolName"`
	Arguments map[string]any `json:"arguments"`
}
type sharedMesh struct {
	node        *node.SamNode
	store       *node.Store
	ctx         context.Context
	cancel      context.CancelFunc
	published   bool
	once        sync.Once
	closeErr    error
	admissionMu sync.Mutex
	admission   *lru.Cache[peer.ID, *rate.Limiter]
}

var activeSharedMesh *sharedMesh

func newSharedMesh(parent context.Context, cfg SharedMeshConfig) (r *sharedMesh, err error) {
	if !filepath.IsAbs(cfg.DataDir) {
		return nil, errors.New("dataDir must be an absolute private directory")
	}
	u, e := url.Parse(cfg.BootstrapURL)
	if e != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || cfg.JoinToken == "" {
		return nil, errors.New("bootstrapUrl and joinToken are required")
	}
	store, err := node.NewStore(filepath.Join(cfg.DataDir, "shared-mesh-v1"))
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			store.Close()
		}
	}()
	key, err := localTestPeerKey(store)
	if err != nil {
		return nil, err
	}
	id, err := peer.IDFromPrivateKey(key)
	if err != nil {
		return nil, err
	}
	pub, err := crypto.MarshalPublicKey(key.GetPublic())
	if err != nil {
		return nil, err
	}
	stamp := time.Now().UnixMilli()
	signature, err := key.Sign(api.EnrollChallenge(id.String(), stamp))
	if err != nil {
		return nil, err
	}
	enrollment, _ := proto.Marshal(&api.BootstrapEnrollRequest{BootstrapToken: cfg.JoinToken, PeerId: id.String(), PublicKey: pub, RequestedRole: api.RoleNode, Timestamp: stamp, ChallengeSignature: signature})
	req, err := http.NewRequestWithContext(parent, "POST", cfg.BootstrapURL+"/enroll", bytes.NewReader(enrollment))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-protobuf")
	client := &http.Client{Timeout: sharedMeshTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("enrollment request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("enrollment rejected: HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024))
	if err != nil {
		return nil, err
	}
	enrolled := new(api.BootstrapEnrollResponse)
	if err = proto.Unmarshal(data, enrolled); err != nil {
		return nil, err
	}
	if enrolled.Status != api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED {
		return nil, errors.New("bootstrap enrollment was not approved")
	}
	if len(enrolled.ControlPlanePublicKey) != ed25519.PublicKeySize || len(enrolled.RouterAddresses) == 0 {
		return nil, errors.New("invalid enrollment response")
	}
	authority := ed25519.PublicKey(enrolled.ControlPlanePublicKey)
	if _, err = identity.VerifyBiscuit(enrolled.BiscuitToken, id, []ed25519.PublicKey{authority}, identity.DefaultAuthorizerTimeout); err != nil {
		return nil, err
	}
	if err = identity.VerifyBiscuitRole(enrolled.BiscuitToken, authority, api.RoleNode, identity.DefaultAuthorizerTimeout); err != nil {
		return nil, err
	}
	if err = store.SaveIdentity(enrolled.BiscuitToken); err != nil {
		return nil, err
	}
	if err = store.SaveIdentityExpiration(enrolled.Expiration); err != nil {
		return nil, err
	}
	if err = store.SaveMeshConfig(authority, enrolled.RouterAddresses); err != nil {
		return nil, err
	}
	if err = store.SaveTrustedKeys(nil); err != nil {
		return nil, err
	}
	if err = store.SaveControlPlaneURL(cfg.BootstrapURL); err != nil {
		return nil, err
	}
	var addrs []multiaddr.Multiaddr
	for _, raw := range enrolled.RouterAddresses {
		a, e := multiaddr.NewMultiaddr(raw)
		if e != nil {
			return nil, e
		}
		addrs = append(addrs, a)
	}
	announce := false
	instance, err := node.NewSamNode(node.Options{Store: store, PrivKey: key, ControlPlanePubKey: authority, RouterAddrs: addrs, AllowLoopback: true, AnnouncePrivateAddrs: &announce, RequiredRole: api.RoleNode, RequirePeerIdentity: true, RouterRelayOnly: true, ListenAddrs: []string{"/ip4/0.0.0.0/tcp/0"}, DiscoveryInterval: "1s", AutoRelayMinInterval: time.Second, AutoRelayBootDelay: time.Millisecond, AutoRelayBackoff: time.Second})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	// The node retains this context for its background loops. Link initialization
	// cancellation only until startup succeeds, so the startup deadline does not
	// later shut down a healthy running node.
	detachStartup := context.AfterFunc(parent, cancel)
	defer detachStartup()
	defer func() {
		if err != nil {
			cancel()
			instance.Teardown()
		}
	}()
	if err = instance.Start(ctx); err != nil {
		return nil, err
	}
	// Explicitly establish authenticated router connectivity before publication.
	for _, addr := range addrs {
		if err = instance.ConnectAndAuthWithRouter(parent, addr); err == nil {
			break
		}
	}
	if err != nil {
		return nil, err
	}
	if err = instance.ReserveSharedMeshRouters(parent, ctx); err != nil {
		return nil, err
	}
	admission, err := lru.New[peer.ID, *rate.Limiter](node.RateLimiterSize)
	if err != nil {
		return nil, fmt.Errorf("create connection admission cache: %w", err)
	}
	r = &sharedMesh{node: instance, store: store, ctx: ctx, cancel: cancel, admission: admission}
	if cfg.BackendURL != "" {
		if err = instance.RegisterSharedMeshBackend(parent, sharedMeshService, cfg.DisplayName, cfg.BackendURL, cfg.BackendToken); err != nil {
			return nil, err
		}
		r.published = true
	}
	if !detachStartup() || parent.Err() != nil {
		return nil, parent.Err()
	}
	return r, nil
}
func (r *sharedMesh) close() error {
	r.once.Do(func() { r.cancel(); r.closeErr = errors.Join(r.node.Teardown(), r.store.Close()) })
	return r.closeErr
}

func (r *sharedMesh) admitConnection(ctx context.Context, target peer.ID) error {
	return r.connectionLimiter(target).Wait(ctx)
}

func (r *sharedMesh) connectionLimiter(target peer.ID) *rate.Limiter {
	r.admissionMu.Lock()
	defer r.admissionMu.Unlock()
	limiter, ok := r.admission.Get(target)
	if !ok {
		// Keep a safety margin below the server's exported per-peer rate. A
		// burst of one prevents this integration from consuming the remote
		// peer's entire security burst before unrelated traffic is counted.
		limiter = rate.NewLimiter(rate.Limit(node.PeerRateLimit)*0.8, 1)
		r.admission.Add(target, limiter)
	}
	return limiter
}

// SharedMeshDiscovery is a complete report of this attempt, including partial failures.
type SharedMeshDiscovery struct {
	Tools    []SharedMeshTool                  `json:"tools"`
	Failures []node.SharedMeshDiscoveryFailure `json:"failures"`
}

func (r *sharedMesh) discover(ctx context.Context) (SharedMeshDiscovery, error) {
	services, err := r.node.DiscoverSharedMeshServices(ctx, r.admitConnection)
	if err != nil {
		return SharedMeshDiscovery{}, err
	}
	return collectSharedMeshTools(ctx, services, func(ctx context.Context, p *api.DiscoveredProvider) ([]*mcp.Tool, string, error) {
		id, err := peer.Decode(p.PeerId)
		if err != nil {
			return nil, "connect", err
		}
		if err := r.admitConnection(ctx, id); err != nil {
			return nil, "connect", err
		}
		session, cleanup, err := r.node.ConnectMCPSession(ctx, id, "mcp://"+p.SrvName, nil)
		if err != nil {
			return nil, "connect", err
		}
		defer cleanup()
		tools, err := session.ListTools(ctx, nil)
		if err != nil {
			return nil, "tools_list", err
		}
		return tools.Tools, "", nil
	})
}

func collectSharedMeshTools(ctx context.Context, services node.SharedMeshServiceDiscovery,
	list func(context.Context, *api.DiscoveredProvider) ([]*mcp.Tool, string, error),
) (SharedMeshDiscovery, error) {
	result := SharedMeshDiscovery{Tools: []SharedMeshTool{}, Failures: append([]node.SharedMeshDiscoveryFailure{}, services.Failures...)}
	for _, p := range services.Providers {
		tools, stage, err := list(ctx, p)
		if err != nil {
			id, decodeErr := peer.Decode(p.PeerId)
			if decodeErr != nil {
				return result, errors.New("invalid discovered peer identity")
			}
			result.Failures = append(result.Failures, node.SharedMeshFailure(id, p.SrvName, stage, err))
			continue
		}
		for _, t := range tools {
			result.Tools = append(result.Tools, SharedMeshTool{PeerID: p.PeerId, ServiceName: p.SrvName, ToolName: "mcp://" + p.SrvName + "/" + t.Name, Description: t.Description + " (" + p.SrvDescription + ")", InputSchema: t.InputSchema})
		}
	}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	return result, nil
}
func (r *sharedMesh) call(ctx context.Context, c SharedMeshCall) (*mcp.CallToolResult, error) {
	id, err := peer.Decode(c.PeerID)
	if err != nil {
		return nil, errors.New("invalid peerId")
	}
	return r.node.CallSharedMeshToolOnce(ctx, id, c.ToolName, c.Arguments, r.admitConnection)
}
func StartSharedMesh(configJSON string) error {
	var cfg SharedMeshConfig
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return errors.New("invalid shared mesh config")
	}
	ctx, cancel := context.WithTimeout(context.Background(), sharedMeshTimeout)
	defer cancel()
	startup := &nodeStartup{cancel: cancel, done: make(chan struct{})}
	mu.Lock()
	if activeNode != nil || unauthSrv != nil || pendingStart != nil {
		mu.Unlock()
		return errors.New("node is already running")
	}
	pendingStart = startup
	mu.Unlock()

	// No state lock spans network initialization. Stop cancels ctx and joins done.
	r, err := newSharedMesh(ctx, cfg)
	mu.Lock()
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		mu.Unlock()
		if r != nil {
			_ = r.close()
		}
		mu.Lock()
		pendingStart = nil
		close(startup.done)
		mu.Unlock()
		return err
	}
	activeSharedMesh = r
	activeModeStop = stopSharedMeshInternal
	activeNode = r.node
	activeStore = r.store
	cancelFunc = r.cancel
	pendingStart = nil
	close(startup.done)
	mu.Unlock()
	return nil
}
func StopSharedMesh() error {
	mu.Lock()
	if pendingStart != nil {
		startup := pendingStart
		startup.cancel()
		mu.Unlock()
		<-startup.done
		return nil
	}
	defer mu.Unlock()
	return stopSharedMeshInternal()
}
func stopSharedMeshInternal() error {
	if activeSharedMesh == nil {
		if activeNode != nil || unauthSrv != nil {
			return errors.New("active node belongs to another mode")
		}
		return nil
	}
	err := activeSharedMesh.close()
	activeSharedMesh = nil
	activeModeStop = nil
	activeNode = nil
	activeStore = nil
	cancelFunc = nil
	return err
}
func SharedMeshStatus() string {
	mu.Lock()
	defer mu.Unlock()
	if pendingStart != nil {
		return `{"state":"starting","connectedPeers":0,"published":false}`
	}
	if activeSharedMesh == nil {
		return `{"state":"stopped","connectedPeers":0,"published":false}`
	}
	r := activeSharedMesh
	return sharedJSON(map[string]any{"state": "running", "peerId": r.node.Host.ID().String(), "connectedPeers": len(r.node.Host.Network().Peers()), "published": r.published}, nil)
}
func sharedJSON(v any, err error) string {
	if err != nil {
		v = map[string]string{"error": err.Error()}
	}
	b, e := json.Marshal(v)
	if e != nil {
		return `{"error":"JSON encoding failed"}`
	}
	return string(b)
}
func sharedSnapshot() (*sharedMesh, context.Context, context.CancelFunc) {
	mu.Lock()
	defer mu.Unlock()
	r := activeSharedMesh
	if r == nil {
		return nil, nil, func() {}
	}
	ctx, cancel := context.WithTimeout(r.ctx, sharedMeshTimeout)
	return r, ctx, cancel
}
func DiscoverSharedMeshTools() string {
	r, ctx, cancel := sharedSnapshot()
	defer cancel()
	if r == nil {
		return `{"error":"shared mesh is stopped"}`
	}
	v, err := r.discover(ctx)
	return sharedJSON(v, err)
}
func CallSharedMeshTool(requestJSON string) string {
	r, ctx, cancel := sharedSnapshot()
	defer cancel()
	if r == nil {
		return `{"error":"shared mesh is stopped"}`
	}
	var c SharedMeshCall
	if err := json.Unmarshal([]byte(requestJSON), &c); err != nil {
		return `{"error":"invalid call request"}`
	}
	v, err := r.call(ctx, c)
	return sharedJSON(v, err)
}
