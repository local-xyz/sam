//go:build sam_debug

package node

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/google/sam/api"
)

// RegisterSharedMeshA2ABackend registers an a2a:// service whose backend is
// the app's loopback A2A HTTP server (agent card + JSON-RPC). Only available
// in debug builds, mirroring RegisterSharedMeshBackend: the backend
// credential never enters the mesh, and the peer header the backend sees
// comes from the authenticated libp2p stream, never from the caller.
func (n *SamNode) RegisterSharedMeshA2ABackend(ctx context.Context, name, displayName, endpoint, token string) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		net.ParseIP(u.Hostname()) == nil || !net.ParseIP(u.Hostname()).IsLoopback() || token == "" {
		return fmt.Errorf("backend requires an HTTP loopback IP URL and token")
	}
	svc := &sharedMeshA2AService{
		A2AService: A2AService{baseService: baseService{
			info:    &api.ServiceInfo{Name: name, Type: api.ServiceType_SERVICE_TYPE_A2A, Description: "A2A agent of " + displayName},
			backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: endpoint},
		}},
		endpoint: endpoint,
		token:    token,
	}
	if err := svc.Probe(ctx); err != nil {
		return fmt.Errorf("backend is not ready: %w", err)
	}
	return n.services.Register(ctx, svc)
}

// sharedMeshA2AService is an A2AService whose backend requires a bearer
// credential on every request, including probes. The registry's reprovide
// loop re-probes services periodically; without the credential those probes
// would 401 and the service would silently drop out of DHT advertisement.
type sharedMeshA2AService struct {
	A2AService
	endpoint string
	token    string
}

// Init builds a reverse proxy that authenticates to the loopback backend and
// forwards only the transport-verified peer identity. Ingress sets X-Peer-Id
// after biscuit verification; an inbound "Connection: X-Peer-Id" would make
// the proxy's hop-by-hop pass erase it from Out, so it is restored from In
// explicitly. Everything else spoofable or secret-bearing is dropped.
func (s *sharedMeshA2AService) Init(ctx context.Context) error {
	target, err := url.Parse(s.endpoint)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}
	token := s.token
	s.handler = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			noTrailingSlash := pr.In.Header.Get(api.HeaderSamNoTrailingSlash) == "true"
			pr.SetURL(target)
			pr.Out.Host = target.Host
			for _, name := range []string{
				"Authorization", api.HeaderPeerID, api.HeaderSamBiscuit,
				api.HeaderSamAgent, api.HeaderSamAuthentication, api.HeaderSamNoTrailingSlash,
			} {
				pr.Out.Header.Del(name)
			}
			pr.Out.Header.Set("Authorization", "Bearer "+token)
			if peer := pr.In.Header.Get(api.HeaderPeerID); peer != "" {
				pr.Out.Header.Set(api.HeaderPeerID, peer)
			}
			if noTrailingSlash && pr.Out.URL.Path == "/" {
				pr.Out.URL.Path = ""
			}
		},
	}
	return nil
}

// Probe fetches the backend's agent card with the backend credential; the
// card is the A2A protocol's own definition of ready. Redirects are refused:
// a loopback backend has no business redirecting, and following one could
// carry the credential elsewhere.
func (s *sharedMeshA2AService) Probe(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint+"/"+a2aAgentCardPath, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	client := &http.Client{
		Timeout:       20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch agent card of %q: %w", s.info.GetName(), err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("agent card of %q: %s", s.info.GetName(), resp.Status)
	}
	var card map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxAgentCardBytes)).Decode(&card); err != nil {
		return fmt.Errorf("agent card of %q is not JSON: %w", s.info.GetName(), err)
	}
	return nil
}

// SharedMeshEgressHandler exposes the node's standard egress proxy
// (/sam/{peer}/{type}/{svc}/...) for the debug shared-mesh integration. It
// carries the node's biscuit, enforces the egress label floor, and runs the
// per-type egress middleware — for a2a that means agent cards are fetched
// over the mesh and regenerated so their interface URLs point back through
// this node.
func (n *SamNode) SharedMeshEgressHandler() http.Handler {
	return createEgressProxy(n)
}

// DiscoverSharedMeshA2AProviders lists a2a:// services advertised by mesh
// peers, preserving each unreachable provider as an explicit failure, the
// same contract as DiscoverSharedMeshServices for MCP.
func (n *SamNode) DiscoverSharedMeshA2AProviders(ctx context.Context, admit SharedMeshConnectionAdmission) (SharedMeshServiceDiscovery, error) {
	result := SharedMeshServiceDiscovery{Providers: []*api.DiscoveredProvider{}, Failures: []SharedMeshDiscoveryFailure{}}
	peers, err := n.FindProvidersByType(ctx, api.ServiceType_SERVICE_TYPE_A2A)
	if err != nil {
		return result, err
	}
	for _, p := range peers {
		if p.ID == n.Host.ID() {
			continue
		}
		if admit != nil {
			if err := admit(ctx, p.ID); err != nil {
				result.Failures = append(result.Failures, SharedMeshFailure(p.ID, "", "service_catalog", err))
				continue
			}
		}
		services, err := n.fetchRemoteServiceCatalog(ctx, p.ID, api.ServiceTypeStringA2A)
		if err != nil {
			result.Failures = append(result.Failures, SharedMeshFailure(p.ID, "", "service_catalog", err))
			continue
		}
		for _, svc := range services {
			result.Providers = append(result.Providers, &api.DiscoveredProvider{PeerId: p.ID.String(), SrvName: svc.Name, SrvDescription: svc.Description})
		}
	}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	return result, nil
}
