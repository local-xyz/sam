//go:build sam_debug

package node

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	relayclient "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/multiformats/go-multiaddr"
)

// RegisterSharedMeshBackend is only available in debug builds. The backend
// credential never enters the mesh; the peer header comes from the authenticated
// libp2p stream, never JSON-RPC parameters or an inbound HTTP header.
func (n *SamNode) RegisterSharedMeshBackend(ctx context.Context, name, displayName, endpoint, token string) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || net.ParseIP(u.Hostname()) == nil || !net.ParseIP(u.Hostname()).IsLoopback() || token == "" {
		return fmt.Errorf("backend requires an HTTP loopback IP URL and token")
	}
	svc := &MCPService{baseService: baseService{info: &api.ServiceInfo{Name: name, Type: api.ServiceType_SERVICE_TYPE_MCP, Description: "Published Android demo note from " + displayName}, backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: endpoint}}}
	svc.backendForPeer = func(id peer.ID) (mcp.Transport, error) {
		if id == "" {
			id = n.Host.ID()
		} // local probes are explicitly attributed to this node
		client := &http.Client{Transport: sharedMeshRoundTripper{base: http.DefaultTransport, token: token, peerID: id.String()}, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		return &mcp.StreamableClientTransport{Endpoint: endpoint, HTTPClient: client}, nil
	}
	if err := svc.Probe(ctx); err != nil {
		return fmt.Errorf("backend is not ready: %w", err)
	}
	return n.services.Register(ctx, svc)
}

type sharedMeshRoundTripper struct {
	base          http.RoundTripper
	token, peerID string
}

func (t sharedMeshRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	out := r.Clone(r.Context())
	out.Header = r.Header.Clone()
	for _, v := range out.Header.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			out.Header.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade", "Authorization", "X-Peer-Id"} {
		out.Header.Del(name)
	}
	out.Header.Set("Authorization", "Bearer "+t.token)
	out.Header.Set("X-Peer-Id", t.peerID)
	return t.base.RoundTrip(out)
}

// ReserveSharedMeshRouters explicitly reserves the provisioned private routers.
// AutoRelay intentionally advertises only public IPs, which excludes emulator
// host gateways and LAN development routers. SAM router authentication is still
// mandatory and its relay ACL enforces membership for each reservation.
func (n *SamNode) ReserveSharedMeshRouters(startup, lifetime context.Context) error {
	for _, addr := range n.config.RouterAddrs {
		info, err := peer.AddrInfoFromP2pAddr(addr)
		if err != nil {
			return err
		}
		reservation, err := relayclient.Reserve(sharedReservationContext(startup), sharedReservationHost{n.Host}, *info)
		if err != nil {
			return fmt.Errorf("private mesh relay reservation failed: %w", err)
		}
		go n.renewSharedMeshReservation(lifetime, addr, *info, reservation.Expiration)
	}
	return nil
}

// Reserve's stream reads use an internal fixed deadline; reset on context
// cancellation as well so native startup/stop retain their public bounds.
type sharedReservationHost struct{ host.Host }

func (h sharedReservationHost) NewStream(ctx context.Context, id peer.ID, protocols ...protocol.ID) (network.Stream, error) {
	s, err := h.Host.NewStream(ctx, id, protocols...)
	if err != nil {
		return nil, err
	}
	return &sharedReservationStream{Stream: s, stop: context.AfterFunc(ctx, func() { _ = s.Reset() })}, nil
}

type sharedReservationStream struct {
	network.Stream
	stop func() bool
}

func (s *sharedReservationStream) Close() error { s.stop(); return s.Stream.Close() }
func sharedReservationContext(ctx context.Context) context.Context {
	return network.WithAllowLimitedConn(ctx, "shared-mesh-reservation")
}
func (n *SamNode) renewSharedMeshReservation(ctx context.Context, addr multiaddr.Multiaddr, info peer.AddrInfo, expiry time.Time) {
	for {
		delay := time.Until(expiry) / 2
		// Re-check periodically so reconnecting after a dropped router connection
		// restores the reservation rather than waiting half its original TTL.
		if delay > 30*time.Second {
			delay = 30 * time.Second
		}
		if delay < time.Second {
			delay = time.Second
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		attempt, cancel := context.WithTimeout(ctx, 20*time.Second)
		err := n.ConnectAndAuthWithRouter(attempt, addr)
		if err == nil {
			var r *relayclient.Reservation
			r, err = relayclient.Reserve(sharedReservationContext(attempt), sharedReservationHost{n.Host}, info)
			if err == nil {
				expiry = r.Expiration
			}
		}
		cancel()
		if err != nil {
			expiry = time.Now().Add(10 * time.Second)
		}
	}
}

// SharedMeshDiscoveryFailure contains safe diagnostic codes, never remote error text
// (which can contain credentials, URLs, or backend responses).
type SharedMeshDiscoveryFailure struct {
	PeerID      string `json:"peerId"`
	ServiceName string `json:"serviceName,omitempty"`
	Stage       string `json:"stage"`
	Reason      string `json:"reason"`
}

type SharedMeshServiceDiscovery struct {
	Providers []*api.DiscoveredProvider
	Failures  []SharedMeshDiscoveryFailure
}

// SharedMeshConnectionAdmission lets a debug integration pace authenticated
// stream creation without changing the server's security limits.
type SharedMeshConnectionAdmission func(context.Context, peer.ID) error

func SharedMeshFailure(id peer.ID, service, stage string, err error) SharedMeshDiscoveryFailure {
	reason := "unavailable"
	var timedOut net.Error
	switch {
	case errors.Is(err, ErrAuthRejected):
		reason = "authentication_rejected"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &timedOut) && timedOut.Timeout():
		reason = "timeout"
	case errors.Is(err, network.ErrReset):
		reason = "stream_reset"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		reason = "connection_closed"
	}
	return SharedMeshDiscoveryFailure{PeerID: id.String(), ServiceName: service, Stage: stage, Reason: reason}
}

// DiscoverSharedMeshServices preserves each unreachable provider even when another
// provider succeeds. Absence of a tool is not evidence that its catalog was queried.
func (n *SamNode) DiscoverSharedMeshServices(ctx context.Context, admit SharedMeshConnectionAdmission) (SharedMeshServiceDiscovery, error) {
	result := SharedMeshServiceDiscovery{Providers: []*api.DiscoveredProvider{}, Failures: []SharedMeshDiscoveryFailure{}}
	peers, err := n.FindProvidersByType(ctx, api.ServiceType_SERVICE_TYPE_MCP)
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
		services, err := n.fetchRemoteServiceCatalog(ctx, p.ID, "mcp")
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

// CallSharedMeshToolOnce performs one paced call attempt. Transport failures are
// returned as uncertain outcomes and are never retried by this debug boundary.
func (n *SamNode) CallSharedMeshToolOnce(ctx context.Context, target peer.ID, toolName string, arguments any, admit SharedMeshConnectionAdmission) (*mcp.CallToolResult, error) {
	n.preparePeerAddrs(ctx, target)
	if admit != nil {
		if err := admit(ctx, target); err != nil {
			return nil, err
		}
	}
	return n.callMCPToolOnce(ctx, target, toolName, arguments, nil)
}
