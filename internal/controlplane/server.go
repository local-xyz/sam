// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2/parser"
	"github.com/coreos/go-oidc/v3/oidc"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/sam/api"
	"github.com/google/sam/internal/identity"
	"github.com/google/sam/internal/storage"
	golog "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/time/rate"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

var logger = golog.Logger("sam-control-plane")

const (
	EnrollRateLimit        = 10
	EnrollBurst            = 20
	JWTVerificationTimeout = 10 * time.Second
	// maxRequestBodyBytes caps request bodies read into memory to guard
	// against memory-exhaustion from oversized payloads.
	maxRequestBodyBytes = 1 << 20 // 1 MiB

	// adminNodeActionAutonomousRecovery is the action segment of
	// POST /admin/nodes/{peer_id}/autonomous-recovery, the per-node toggle
	// for storage.EnrolledNode.AutonomousRecovery. Admin-console only: the
	// node-facing side of #367 is TokenRefreshRequest.peer_id in sam.proto.
	adminNodeActionAutonomousRecovery = "autonomous-recovery"
)

// Server implements the SAM Control Plane web app.
type Server struct {
	config     Options
	store      storage.Store
	httpServer *http.Server
	listener   net.Listener
	limiter    *rate.Limiter

	meshMu sync.RWMutex
	mesh   MeshAdapter

	providersMu sync.RWMutex
	providers   map[string]*oidc.Provider

	// catalogMu/catalog cache each node's self-reported local service list
	// (see HandleNodeCatalog), keyed by peer ID. In-memory only: this is a
	// live-status view, not authoritative state, so it's fine to lose on
	// restart - every node re-reports on its own next periodic push.
	catalogMu sync.RWMutex
	catalog   map[string]nodeCatalogEntry

	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	shutdown bool
}

// NewServer initializes the control plane server and stores configuration.
func NewServer(config Options, store storage.Store) (*Server, error) {
	config.Default()
	if err := config.Validate(); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Server{
		config:    config,
		store:     store,
		mesh:      NewNopMeshAdapter(),
		limiter:   rate.NewLimiter(rate.Limit(EnrollRateLimit), EnrollBurst),
		providers: make(map[string]*oidc.Provider),
		catalog:   make(map[string]nodeCatalogEntry),
		ctx:       ctx,
		cancel:    cancel,
	}, nil
}

// SetMeshAdapter sets a custom MeshAdapter implementation for the control plane.
func (s *Server) SetMeshAdapter(m MeshAdapter) {
	if m != nil {
		s.meshMu.Lock()
		s.mesh = m
		s.meshMu.Unlock()
	}
}

func (s *Server) getMeshAdapter() MeshAdapter {
	s.meshMu.RLock()
	defer s.meshMu.RUnlock()
	return s.mesh
}

// Start boots up HTTP services, sets up OIDC providers, loads initial keys and policies, and schedules rotations.
// Start boots up HTTP services, sets up OIDC providers, loads initial keys and policies, and schedules rotations.
func (s *Server) Start() error {
	if err := s.Init(); err != nil {
		return err
	}

	// Setup listener
	l, err := net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		return err
	}
	s.listener = l

	mux := http.NewServeMux()
	s.RegisterRoutes(mux)

	s.httpServer = &http.Server{
		Handler: mux,
		// Mitigate Slowloris-style resource exhaustion from slow/malicious clients.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		logger.Infof("SAM Control Plane listening on http://%s", s.config.ListenAddr)
		if err := s.httpServer.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Errorf("HTTP Server error: %v", err)
		}
	}()

	return nil
}

// Init prepares the control plane without binding a listener: it bootstraps
// the signing keyring, discovers OIDC providers and starts the key-rotation
// loop. Embedders that own their own listener call Init + RegisterRoutes
// instead of Start.
func (s *Server) Init() error {
	// Initialize Keyring
	ctx := context.Background()
	_, _, err := s.store.GetCurrentKey(ctx)
	if err == storage.ErrNotFound {
		logger.Info("Generating initial control plane signing keys...")
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("failed to generate initial key: %w", err)
		}
		if err := s.store.SaveInitialKey(ctx, priv, pub); err != nil {
			return fmt.Errorf("failed to save initial key: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to query initial keyring status: %w", err)
	}

	// Bootstrap Policy is now disabled; starting default closed.

	// Initialize OIDC Providers
	if err := s.discoverProviders(); err != nil {
		return fmt.Errorf("failed OIDC discovery: %w", err)
	}

	// Start key rotation routine
	s.wg.Add(1)
	go s.runKeyRotationLoop()

	return nil
}

// RegisterRoutes registers every control-plane HTTP handler on mux.
func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/healthz", s.HandleHealthz)
	mux.HandleFunc("/readyz", s.HandleReadyz)
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/info", s.HandleInfo)
	mux.HandleFunc("/register", s.HandleRegister)
	mux.HandleFunc("/keys", s.HandleKeys)
	mux.HandleFunc("/routers/lease", s.HandleRouterLease)
	mux.HandleFunc("/policies", s.HandlePolicies)
	mux.HandleFunc("/enroll", s.HandleEnroll)
	mux.HandleFunc("/enroll/status", s.HandleEnrollStatus)
	mux.HandleFunc("/refresh", s.HandleRefresh)
	mux.HandleFunc("/nodes/catalog", s.HandleNodeCatalog)
	mux.HandleFunc("/admin/bootstrap-tokens", s.HandleAdminBootstrapTokens)
	mux.HandleFunc("/admin/bootstrap-tokens/", s.HandleAdminBootstrapTokenAction)
	mux.HandleFunc("/admin/enrollments", s.HandleAdminEnrollments)
	mux.HandleFunc("/admin/enrollments/", s.HandleAdminEnrollmentAction)
	mux.HandleFunc("/admin/nodes/", s.HandleAdminNodeAction)
	mux.HandleFunc("/admin/revoke", s.HandleAdminRevoke)
	mux.HandleFunc("/admin/status", s.HandleAdminStatus)
	mux.HandleFunc("/user/status", s.HandleUserStatus)
	mux.HandleFunc("/user/bootstrap-tokens", s.HandleUserBootstrapTokens)
	mux.HandleFunc("/user/revoke", s.HandleUserRevoke)
}

func (s *Server) discoverProviders() error {
	s.providersMu.Lock()
	defer s.providersMu.Unlock()

	issuers := strings.Split(s.config.OIDCIssuer, ",")
	for _, iss := range issuers {
		iss = strings.TrimSpace(iss)
		if iss == "" {
			continue
		}
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: s.config.InsecureSkipTLSVerify}
		client := &http.Client{
			Timeout:   30 * time.Second,
			Transport: tr,
		}
		providerCtx := oidc.ClientContext(s.ctx, client)
		provider, err := discoverProviderWithRetry(providerCtx, iss, oidcDiscoveryMaxAttempts, oidcDiscoveryBaseDelay, oidcDiscoveryMaxDelay)
		if err != nil {
			return fmt.Errorf("failed to create provider for %s: %w", iss, err)
		}
		s.providers[iss] = provider
	}
	return nil
}

// Defaults for discoverProviderWithRetry; kept small enough that a real outage still
// surfaces quickly (worst case ~15s) while riding out a transient hiccup during rollouts.
const (
	oidcDiscoveryMaxAttempts = 5
	oidcDiscoveryBaseDelay   = 1 * time.Second
	oidcDiscoveryMaxDelay    = 8 * time.Second
)

// discoverProviderWithRetry retries OIDC discovery with exponential backoff so a transient
// upstream hiccup (e.g. the identity provider mid-rollout) doesn't crash the control plane.
func discoverProviderWithRetry(ctx context.Context, issuer string, maxAttempts int, baseDelay, maxDelay time.Duration) (*oidc.Provider, error) {
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			delay := baseDelay * time.Duration(1<<uint(attempt-1))
			if delay > maxDelay {
				delay = maxDelay
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}
		provider, err := oidc.NewProvider(ctx, issuer)
		if err == nil {
			return provider, nil
		}
		lastErr = err
		logger.Warnf("OIDC discovery attempt %d/%d for %s failed: %v", attempt+1, maxAttempts, issuer, err)
	}
	return nil, lastErr
}

func (s *Server) getProviders() map[string]*oidc.Provider {
	s.providersMu.RLock()
	defer s.providersMu.RUnlock()

	pCopy := make(map[string]*oidc.Provider)
	for k, v := range s.providers {
		pCopy[k] = v
	}
	return pCopy
}

func (s *Server) runKeyRotationLoop() {
	defer s.wg.Done()
	if s.config.KeyRotationInterval <= 0 {
		return
	}

	ticker := time.NewTicker(s.config.KeyRotationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Replicas share one DB but tick independently; only the replica
			// that wins this claim may rotate for the current window.
			now := time.Now()
			claimed, err := s.store.ClaimKeyRotation(s.ctx, now, s.config.KeyRotationInterval)
			if err != nil {
				logger.Errorf("Failed to claim key rotation window: %v", err)
				continue
			}
			if !claimed {
				logger.Debug("Skipping key rotation: another replica already claimed this window")
				continue
			}

			logger.Info("Rotating Biscuit signing keys...")
			newPub, newPriv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				logger.Errorf("Failed to generate key pair for rotation: %v", err)
				// Give up the window so a retry isn't stuck waiting a full interval.
				if relErr := s.store.ReleaseKeyRotationClaim(s.ctx, now, s.config.KeyRotationInterval); relErr != nil {
					logger.Errorf("Failed to release key rotation claim: %v", relErr)
				}
				continue
			}
			err = s.store.RotateKeys(s.ctx, newPriv, newPub, s.config.KeyGracePeriod)
			if err != nil {
				logger.Errorf("Failed to rotate keyring: %v", err)
				// Same as above: don't let a failed rotation strand the mesh
				// on unrotated keys until the next full interval.
				if relErr := s.store.ReleaseKeyRotationClaim(s.ctx, now, s.config.KeyRotationInterval); relErr != nil {
					logger.Errorf("Failed to release key rotation claim: %v", relErr)
				}
			} else {
				logger.Infof("Key rotation committed. New current public key: %s", hex.EncodeToString(newPub))
				if err := s.getMeshAdapter().PublishEvent(s.ctx, api.MeshEvent_KEY_ROTATION, "", newPub); err != nil {
					logger.Warnf("Failed to publish KEY_ROTATION event to mesh: %v", err)
				}
			}
		case <-s.ctx.Done():
			return
		}
	}
}

// HandleHealthz HTTP GET `/healthz`
func (s *Server) HandleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// HandleReadyz HTTP GET `/readyz`
func (s *Server) HandleReadyz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.store != nil {
		if err := s.store.Ping(r.Context()); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprintf(w, `{"status":"error","message":%q}`, err.Error())
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ready"}`))
}

// HandleInfo HTTP GET `/info`
func (s *Server) HandleInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	issuer := s.config.OIDCIssuer
	if strings.Contains(issuer, ",") {
		parts := strings.Split(issuer, ",")
		issuer = strings.TrimSpace(parts[0])
	}

	aud := api.DefaultAudience
	if len(s.config.AllowedAudiences) > 0 {
		aud = s.config.AllowedAudiences[0]
	}

	// aud == client_id only holds for id_token-model IdPs (dex, Google); an
	// explicit client id supports providers where the two differ.
	clientID := s.config.OIDCClientID
	if clientID == "" {
		clientID = aud
	}

	// Fetch active routers
	activeRouters, err := s.store.GetActiveRouters(r.Context())
	if err != nil {
		logger.Errorf("Failed to retrieve active routers: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	var routerAddrs []string
	for _, r := range activeRouters {
		routerAddrs = append(routerAddrs, r.Addresses...)
	}

	// The ban set is published here, rather than only as a MeshEvent, because
	// the event is broadcast once and gossip has no replay: a node or router
	// that restarted or was offline at the time would otherwise never learn
	// the ban. A failure to read it must not be served as an empty list --
	// that would read as "nothing is banned" and unban everyone -- so it is
	// treated like any other failure to build this response.
	bannedPeerIDs, err := s.store.ListBannedPeerIDs(r.Context())
	if err != nil {
		logger.Errorf("Failed to retrieve banned peers: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	resp := &api.ControlPlaneInfoResponse{
		OidcIssuer:      issuer,
		ClientId:        clientID,
		Audience:        aud,
		RouterAddresses: routerAddrs, // Reused this field for back-compatibility with bootstrap routers list
		BannedPeerIds:   bannedPeerIDs,
	}

	respData, err := proto.Marshal(resp)
	if err != nil {
		http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respData)
}

// HandleRegister HTTP POST `/register`
func (s *Server) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer func() { _ = r.Body.Close() }()

	var req api.EnrollRequest
	if err := proto.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	if !s.limiter.Allow() {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	logger.Infow("New enrollment request", "peer_id", req.PeerId)

	ctx, cancel := context.WithTimeout(r.Context(), JWTVerificationTimeout)
	defer cancel()

	claims, token, err := identity.VerifyJWT(ctx, req.Jwt, s.config.AllowedAudiences, s.getProviders())
	if err != nil {
		logger.Errorw("JWT verification failed", "peer_id", req.PeerId, "error", err)
		http.Error(w, "JWT validation failed: "+err.Error(), http.StatusUnauthorized)
		return
	}

	pID, err := peer.Decode(req.PeerId)
	if err != nil {
		http.Error(w, "Invalid Peer ID", http.StatusBadRequest)
		return
	}
	canonical := pID.String()

	// A ban names the device key and the identity behind it; check both, or
	// a banned node re-enrolls from a freshly generated keypair.
	if banned, err := s.store.IsNodeBanned(ctx, canonical); err != nil {
		logger.Errorf("Failed to check node ban for %s: %v", canonical, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	} else if banned {
		logger.Warnw("Banned node attempted enrollment", "peer_id", canonical)
		http.Error(w, "Node is banned", http.StatusForbidden)
		return
	}
	if key := oidcIdentityKey(claims); key != "" {
		if banned, err := s.store.IsIdentityBanned(ctx, key); err != nil {
			logger.Errorf("Failed to check identity ban for %s: %v", canonical, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		} else if banned {
			logger.Warnw("Banned identity attempted enrollment", "peer_id", canonical, "identity", key)
			http.Error(w, "Identity is banned", http.StatusForbidden)
			return
		}
	}

	// Mesh policy is distributed dynamically to the target nodes, no need to inject into token.

	// Fetch current signing private key
	privKey, pubKey, err := s.store.GetCurrentKey(ctx)
	if err != nil {
		logger.Errorf("Failed to retrieve current signing key: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if req.RequestedRole == "" {
		http.Error(w, "requested_role must be specified", http.StatusBadRequest)
		return
	}

	// Fail closed on malformed labels; they get attested into the biscuit
	// and persisted for refreshes.
	if err := api.ValidateLabels(req.Labels); err != nil {
		http.Error(w, "Invalid labels: "+err.Error(), http.StatusBadRequest)
		return
	}

	policyRoles, bindings, err := s.store.GetMeshPolicy(ctx)
	if err != nil && err != storage.ErrNotFound {
		logger.Errorf("Failed to load policy for registration: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	resolvedRoles := resolveRoles(canonical, claims, bindings)
	var customAccessRoles []string
	resolvedMap := make(map[string]bool)
	for _, r := range resolvedRoles {
		resolvedMap[r] = true
		if !strings.HasPrefix(r, "sam:role:") && r != req.RequestedRole {
			customAccessRoles = append(customAccessRoles, r)
		}
	}

	// Enrollment is a policy decision like any other: the requested role must
	// resolve from an explicit binding. There is deliberately no fallback for
	// sam:role:node — a mesh that wants open enrollment says so by binding it
	// to sam:system:authenticated, instead of getting it by omission.
	if !resolvedMap[req.RequestedRole] {
		http.Error(w, fmt.Sprintf("requested role %q is not bound to this identity; bind it in mesh policy (to sam:system:authenticated to open enrollment to every authenticated identity)", req.RequestedRole), http.StatusForbidden)
		return
	}

	finalRoles := []string{req.RequestedRole}
	finalRoles = append(finalRoles, customAccessRoles...)

	// The node declared these labels itself, so they are only worth signing if
	// a role it resolves to says it may carry them.
	if err := api.LabelPatternsAllow(allowedLabelPatterns(finalRoles, policyRoles), req.Labels); err != nil {
		logger.Warnw("Rejected undeclarable label at enrollment", "peer_id", canonical, "error", err)
		http.Error(w, "Label not permitted: "+err.Error(), http.StatusForbidden)
		return
	}

	// The session bounds how long refresh works without the identity proving
	// itself to the issuer again, so its length is the operator's re-auth
	// cadence decision (--oidc-session-ttl), not a constant.
	sessionExpiresAt := time.Now().Add(s.config.OIDCSessionTTL)

	// Mint token. A biscuit must never outlive the OIDC token that vouched
	// for it, nor the session it belongs to; its expiration is capped at
	// whichever comes first.
	biscuitExpiry := time.Now().Add(s.config.BiscuitTTL)
	if token.Expiry.Before(biscuitExpiry) {
		biscuitExpiry = token.Expiry
	}
	if sessionExpiresAt.Before(biscuitExpiry) {
		biscuitExpiry = sessionExpiresAt
	}
	biscuitData, _, err := identity.MintBiscuitToken(privKey, claims, token, pID, biscuitExpiry, finalRoles, policyRoles, req.Labels)
	if err != nil {
		logger.Errorw("Biscuit minting failed", "peer_id", canonical, "error", err)
		http.Error(w, "Failed to mint biscuit: "+err.Error(), http.StatusForbidden)
		return
	}

	primaryRole := req.RequestedRole

	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		logger.Errorf("Failed to marshal OIDC claims: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	nodeRecord := &storage.EnrolledNode{
		PeerID:         canonical,
		PublicKey:      req.PublicKey,
		Biscuit:        biscuitData,
		Role:           primaryRole,
		EnrollmentType: "OIDC",
		ClaimsJSON:     string(claimsBytes),
		Labels:         req.Labels,
		EnrolledAt:     time.Now(),
		ExpiresAt:      sessionExpiresAt,
	}

	// Save to DB
	if err := s.store.EnrollNode(ctx, nodeRecord); err != nil {
		logger.Errorf("Failed to persist node enrollment: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Fetch active routers
	activeRouters, err := s.store.GetActiveRouters(ctx)
	if err != nil {
		logger.Errorf("Failed to retrieve active routers: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	var routerAddrs []string
	for _, r := range activeRouters {
		routerAddrs = append(routerAddrs, r.Addresses...)
	}

	resp := &api.EnrollResponse{
		BiscuitToken:          biscuitData,
		ControlPlanePublicKey: pubKey,
		RouterAddresses:       routerAddrs, // routers nodes multiaddresses
		Expiration:            biscuitExpiry.Unix(),
	}

	respData, err := proto.Marshal(resp)
	if err != nil {
		http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respData)
}

// HandleRefresh HTTP POST `/refresh`
func (s *Server) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Missing current Biscuit token in Authorization header", http.StatusUnauthorized)
		return
	}
	currentBiscuitBase64 := strings.TrimPrefix(authHeader, "Bearer ")
	currentBiscuitBytes, err := base64.StdEncoding.DecodeString(currentBiscuitBase64)
	if err != nil {
		http.Error(w, "Malformed base64 token", http.StatusBadRequest)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	var req api.TokenRefreshRequest
	if err := proto.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Fetch all valid signing keys
	validKeys, err := s.store.GetAllValidKeys(ctx)
	if err != nil {
		logger.Errorf("Failed to retrieve valid signing keys: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	var trustedKeys []ed25519.PublicKey
	for _, k := range validKeys {
		trustedKeys = append(trustedKeys, k.Public)
	}

	// Verify current biscuit signature and extract peer ID. Expiry is not
	// enforced here: a node refreshes because its token lapsed. The session
	// record and the signed challenge below are what bound this request.
	pID, verifyErr := identity.VerifyExpiredAndExtractPeerID(trustedKeys, currentBiscuitBytes, s.config.BiscuitTimeout)
	// recovering marks the retired-key fallback (#367): the biscuit cannot be
	// verified, most likely because its signing key rotated out past grace
	// while the node was offline. The peer is then taken from the body and
	// the biscuit is authenticated below by byte-matching the last one this
	// control plane issued to that peer, which only the control plane and the
	// peer ever held.
	recovering := false
	if verifyErr != nil {
		if req.PeerId == "" {
			logger.Warnw("Invalid biscuit presented for refresh", "error", verifyErr)
			http.Error(w, "Invalid biscuit: "+verifyErr.Error(), http.StatusUnauthorized)
			return
		}
		claimed, err := peer.Decode(req.PeerId)
		if err != nil {
			http.Error(w, "Invalid Peer ID", http.StatusBadRequest)
			return
		}
		pID = claimed
		recovering = true
	} else if req.PeerId != "" {
		if claimed, err := peer.Decode(req.PeerId); err != nil || claimed != pID {
			logger.Warnw("Refresh peer_id does not match the presented biscuit", "peer_id", req.PeerId)
			http.Error(w, "peer_id does not match the presented biscuit", http.StatusUnauthorized)
			return
		}
	}
	canonical := pID.String()

	// Until the byte-match and challenge below succeed, a recovering caller
	// has proven nothing, so every refusal short of the ban check must read
	// exactly like the plain bad-biscuit one above: the fallback must not
	// become an oracle for which peer IDs are enrolled.
	unauthorized := func(msg string) {
		if recovering {
			msg = "Invalid biscuit: " + verifyErr.Error()
		}
		http.Error(w, msg, http.StatusUnauthorized)
	}

	// Fetch node record
	nodeRecord, err := s.store.GetNode(ctx, canonical)
	if err == storage.ErrNotFound {
		logger.Warnw("Node not found for refresh", "peer_id", canonical)
		unauthorized("Node not enrolled")
		return
	} else if err != nil {
		logger.Errorf("Failed to retrieve node record: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if err := nodeRecord.CheckAdmission(time.Now()); err != nil {
		if errors.Is(err, storage.ErrNodeBanned) {
			logger.Warnw("Banned node attempted refresh", "peer_id", canonical)
			http.Error(w, "Node is banned", http.StatusForbidden)
			return
		}
		logger.Warnw("Session expired for node", "peer_id", canonical, "expires_at", nodeRecord.ExpiresAt)
		unauthorized("Session expired, please re-enroll interactively")
		return
	}

	// Verify challenge signature using stored node public key
	pubKey, err := crypto.UnmarshalPublicKey(nodeRecord.PublicKey)
	if err != nil {
		logger.Errorf("Corrupted public key stored for node %s: %v", nodeRecord.PeerID, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if err := verifyFreshChallenge(pubKey, api.RefreshChallenge(canonical, req.Timestamp), req.Timestamp, req.ChallengeSignature); err != nil {
		logger.Warnw("Refresh challenge verification failed", "peer_id", canonical, "error", err)
		unauthorized("Challenge verification failed: " + err.Error())
		return
	}

	// Rotation with reuse detection: every issuance path persists the latest
	// biscuit, so only that one token is redeemable. A replayed refresh
	// presents an already-rotated biscuit and is refused; a node that lost the
	// rotated token recovers through its re-enrollment fallback. In the
	// retired-key fallback this is also what authenticates the biscuit at
	// all, standing in for the signature that could not be checked.
	if subtle.ConstantTimeCompare(currentBiscuitBytes, nodeRecord.Biscuit) != 1 {
		logger.Warnw("Refresh presented an already-rotated biscuit (possible replay)", "peer_id", nodeRecord.PeerID)
		unauthorized("Biscuit already rotated: only the latest issued token can be refreshed, re-enroll instead")
		return
	}

	// The caller has now proven it holds both the node key and the last
	// issued biscuit. Whether that is enough to survive the retired signing
	// key is the operator's call: off by default, because a node that can
	// always come back on its own private key holds a credential that never
	// expires, and the key grace period is what otherwise puts a deadline on
	// a stolen or forgotten machine.
	if recovering {
		if !nodeRecord.AutonomousRecovery {
			logger.Warnw("Refused retired-key refresh: node is not opted in to autonomous recovery", "peer_id", canonical, "error", verifyErr)
			http.Error(w, "Biscuit signing key has been retired and this node is not opted in to autonomous recovery: re-enroll with a new bootstrap token", http.StatusUnauthorized)
			return
		}
		logger.Infow("Autonomous recovery: re-issuing a biscuit whose signing key was retired", "peer_id", canonical, "error", verifyErr)
	}

	// Fetch current signing private key and policy config
	privKey, _, err := s.store.GetCurrentKey(ctx)
	if err != nil {
		logger.Errorf("Failed to retrieve current signing key: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	policyRoles, bindings, err := s.store.GetMeshPolicy(ctx)
	if err != nil && err != storage.ErrNotFound {
		logger.Errorf("Failed to load policy for node refresh: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	var biscuitBytes []byte
	// No live OIDC token is presented on refresh, so the session record is what
	// vouches for this node. The biscuit must not outlive it.
	biscuitExpiry := time.Now().Add(s.config.BiscuitTTL)
	if !nodeRecord.ExpiresAt.IsZero() && nodeRecord.ExpiresAt.Before(biscuitExpiry) {
		biscuitExpiry = nodeRecord.ExpiresAt
	}

	if nodeRecord.EnrollmentType == "OIDC" {
		var claims jwt.MapClaims
		if err := json.Unmarshal([]byte(nodeRecord.ClaimsJSON), &claims); err != nil {
			logger.Errorf("Failed to unmarshal OIDC claims for node %s: %v", nodeRecord.PeerID, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		resolvedRoles := resolveRoles(canonical, claims, bindings)
		var customAccessRoles []string
		resolvedMap := make(map[string]bool)
		for _, r := range resolvedRoles {
			resolvedMap[r] = true
			if !strings.HasPrefix(r, "sam:role:") && r != nodeRecord.Role {
				customAccessRoles = append(customAccessRoles, r)
			}
		}

		// Same rule as enrollment, re-evaluated against current policy: a mesh
		// that unbinds the role revokes the identity's seat at the next refresh.
		if !resolvedMap[nodeRecord.Role] {
			http.Error(w, fmt.Sprintf("role %q is no longer bound to this identity", nodeRecord.Role), http.StatusForbidden)
			return
		}

		finalRoles := []string{nodeRecord.Role}
		finalRoles = append(finalRoles, customAccessRoles...)

		bBytes, _, err := identity.MintBiscuitToken(privKey, claims, nil, pID, biscuitExpiry, finalRoles, policyRoles, nodeRecord.Labels)
		if err != nil {
			logger.Errorf("Failed to mint refreshed token for node %s: %v", nodeRecord.PeerID, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		biscuitBytes = bBytes
	} else {
		// Bootstrap node
		bBytes, err := identity.MintBootstrapBiscuitToken(privKey, pID, nodeRecord.Role, biscuitExpiry, policyRoles, nodeRecord.Labels)
		if err != nil {
			logger.Errorf("Failed to mint refreshed token for node %s: %v", nodeRecord.PeerID, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		biscuitBytes = bBytes
	}

	// Update node record with new biscuit token
	nodeRecord.Biscuit = biscuitBytes
	nodeRecord.EnrolledAt = time.Now()
	if err := s.store.EnrollNode(ctx, nodeRecord); err != nil {
		logger.Errorf("Failed to persist node refresh: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Write response
	resp := &api.TokenRefreshResponse{
		BiscuitToken: biscuitBytes,
		ExpiresAt:    biscuitExpiry.Unix(),
	}

	respData, err := proto.Marshal(resp)
	if err != nil {
		http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respData)
}

// HandleKeys HTTP GET `/keys`
func (s *Server) HandleKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	validKeys, err := s.store.GetAllValidKeys(r.Context())
	if err != nil {
		logger.Errorf("Failed to retrieve valid keys: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	var pubKeys [][]byte
	for _, k := range validKeys {
		pubKeys = append(pubKeys, k.Public)
	}

	resp := &api.KeysResponse{
		PublicKeys: pubKeys,
	}

	respData, err := proto.Marshal(resp)
	if err != nil {
		http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respData)
}

// HandleRouterLease HTTP POST `/routers/lease`
func (s *Server) HandleRouterLease(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer func() { _ = r.Body.Close() }()

	var req api.RouterLeaseRequest
	if err := proto.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	pID, err := peer.Decode(req.PeerId)
	if err != nil {
		http.Error(w, "Invalid Peer ID", http.StatusBadRequest)
		return
	}
	canonical := pID.String()

	// Fetch all valid public keys from CP to authorize router biscuit
	validKeys, err := s.store.GetAllValidKeys(r.Context())
	if err != nil {
		logger.Errorf("Failed to retrieve valid keys: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	var cpPubKeys []ed25519.PublicKey
	for _, k := range validKeys {
		cpPubKeys = append(cpPubKeys, k.Public)
	}

	// Verify Biscuit and enforce expected remote peer id
	b, verifyingKey, err := identity.VerifyBiscuitAndGetKey(req.Biscuit, pID, cpPubKeys, s.config.BiscuitTimeout)
	if err != nil {
		logger.Warnf("Router %s failed biscuit verification: %v", canonical, err)
		http.Error(w, "Biscuit verification failed: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// Enforce role("router") inside the biscuit
	if err := identity.RequireRole(b, verifyingKey, api.RoleRouter, s.config.BiscuitTimeout); err != nil {
		logger.Warnf("Router %s lacks router role in its biscuit: %v", canonical, err)
		http.Error(w, "Unauthorized: entity is not a router", http.StatusForbidden)
		return
	}

	// A lease is what /info serves to every joining node, and biscuits stay
	// valid offline until their TTL: revocation has to cut off renewals here,
	// as /refresh and /policies already do.
	routerRecord, err := s.store.GetNode(r.Context(), canonical)
	if err == storage.ErrNotFound {
		http.Error(w, "Router not enrolled", http.StatusUnauthorized)
		return
	} else if err != nil {
		logger.Errorf("Failed to retrieve router record: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if err := routerRecord.CheckAdmission(time.Now()); err != nil {
		if errors.Is(err, storage.ErrNodeBanned) {
			logger.Warnw("Revoked router attempted lease renewal", "peer_id", canonical)
			http.Error(w, "Router is banned", http.StatusForbidden)
			return
		}
		logger.Warnw("Router with expired session attempted lease renewal", "peer_id", canonical)
		http.Error(w, "Session expired, please re-enroll", http.StatusUnauthorized)
		return
	}

	// Advertised addresses are served verbatim to joining peers via /info and
	// /enroll: accept only well-formed multiaddrs terminating at the
	// authenticated router itself.
	for _, addrStr := range req.Addresses {
		ma, err := multiaddr.NewMultiaddr(addrStr)
		if err != nil {
			http.Error(w, "Invalid multiaddr in addresses: "+addrStr, http.StatusBadRequest)
			return
		}
		if _, last := peer.SplitAddr(ma); last != pID {
			http.Error(w, "Address does not terminate at the authenticated router: "+addrStr, http.StatusBadRequest)
			return
		}
	}

	// Expose lease renewal
	expiresAt := time.Now().Add(s.config.LeaseDuration)
	lease := &storage.RouterLease{
		PeerID:         canonical,
		Addresses:      req.Addresses,
		LastRenewal:    time.Now(),
		ExpiresAt:      expiresAt,
		ConnectedPeers: req.ConnectedPeers,
		DHTSize:        int(req.DhtSize),
	}

	if err := s.store.UpsertRouterLease(r.Context(), lease); err != nil {
		logger.Errorf("Failed to upsert router lease: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	resp := &api.RouterLeaseResponse{
		Success:   true,
		ExpiresAt: expiresAt.Unix(),
	}

	respData, err := proto.Marshal(resp)
	if err != nil {
		http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respData)
}

// HandlePolicies HTTP GET/POST/PUT `/policies`
func (s *Server) HandlePolicies(w http.ResponseWriter, r *http.Request) {
	// Simple HTTP admin methods for policies
	switch r.Method {
	case http.MethodGet:
		// Nodes need to fetch policies using their Biscuit token, Admins use OIDC/Bootstrap
		isAdmin := false
		user, err := s.authenticateUser(r)
		if err == nil && user.Role == "admin" {
			isAdmin = true
		}

		isNode := false
		if !isAdmin {
			// Try checking if it's a valid node biscuit
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				biscuitBytes, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authHeader, "Bearer "))
				if err == nil {
					validKeys, err := s.store.GetAllValidKeys(r.Context())
					if err == nil {
						var trustedKeys []ed25519.PublicKey
						for _, k := range validKeys {
							trustedKeys = append(trustedKeys, k.Public)
						}
						peerID, err := identity.VerifyAndExtractPeerID(trustedKeys, biscuitBytes, s.config.BiscuitTimeout)
						if err == nil {
							nodeRecord, nodeErr := s.store.GetNode(r.Context(), peerID.String())
							if nodeErr == nil && nodeRecord != nil && nodeRecord.CheckAdmission(time.Now()) == nil {
								isNode = true
							}
						}
					}
				}
			}
		}

		if !isAdmin && !isNode {
			http.Error(w, "Unauthorized: Admin or Node authentication required", http.StatusUnauthorized)
			return
		}

		roles, bindings, err := s.store.GetMeshPolicy(r.Context())
		if err != nil && err != storage.ErrNotFound {
			logger.Errorf("Failed to load policy: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		resp := &api.PolicyConfigGetResponse{
			Roles:    roles,
			Bindings: bindings,
		}
		respData, _ := proto.Marshal(resp)
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respData)

	case http.MethodPost, http.MethodPut:
		if !s.checkAdminAuth(w, r) {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}
		defer func() { _ = r.Body.Close() }()

		req := &api.PolicyConfigUpdateRequest{}
		if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			// Strict: an unknown field here is a typo like "allowed_service", and
			// discarding it would quietly drop the permission it was meant to grant.
			if err := protojson.Unmarshal(body, req); err != nil {
				http.Error(w, "Invalid JSON format: "+err.Error(), http.StatusBadRequest)
				return
			}
		} else {
			if err := proto.Unmarshal(body, req); err != nil {
				http.Error(w, "Invalid request format", http.StatusBadRequest)
				return
			}
		}

		if err := validatePolicyConfig(req); err != nil {
			http.Error(w, "Invalid policy configuration: "+err.Error(), http.StatusBadRequest)
			return
		}

		if err := s.store.SaveMeshPolicy(r.Context(), req.Roles, req.Bindings); err != nil {
			logger.Errorf("Failed to save policy: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		if err := s.getMeshAdapter().PublishEvent(r.Context(), api.MeshEvent_POLICY_UPDATE, "", nil); err != nil {
			logger.Warnf("Failed to publish POLICY_UPDATE event to mesh: %v", err)
		}

		resp := &api.PolicyConfigUpdateResponse{Success: true}
		respData, _ := proto.Marshal(resp)
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respData)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// Close shuts down background loops and HTTP server.
func (s *Server) Close() error {
	s.shutdown = true
	s.cancel()

	var errs []error
	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(context.Background()); err != nil {
			errs = append(errs, err)
		}
	}
	s.wg.Wait()
	return errors.Join(errs...)
}

// Addr returns the network address the server is listening on.
func (s *Server) Addr() string {
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

func cryptoRandUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func (s *Server) writeEnrollResponse(w http.ResponseWriter, resp *api.BootstrapEnrollResponse) {
	w.Header().Set("Cache-Control", "no-store")
	respData, err := proto.Marshal(resp)
	if err != nil {
		http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respData)
}

func (s *Server) writeEnrollError(w http.ResponseWriter, status api.EnrollmentStatus, errMsg string) {
	s.writeEnrollResponse(w, &api.BootstrapEnrollResponse{
		Status:       status,
		ErrorMessage: errMsg,
	})
}

// HandleEnroll HTTP POST `/enroll`
func (s *Server) HandleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer func() { _ = r.Body.Close() }()

	var req api.BootstrapEnrollRequest
	if err := proto.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	if !s.limiter.Allow() {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	ctx := r.Context()
	tokenID := fmt.Sprintf("%x", sha256.Sum256([]byte(req.BootstrapToken)))

	// 1. Get and validate bootstrap token
	tokenRecord, err := s.store.GetBootstrapToken(ctx, tokenID)
	if err == storage.ErrNotFound {
		logger.Errorw("Invalid bootstrap token attempt", "peer_id", req.PeerId)
		s.writeEnrollError(w, api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED, "Invalid bootstrap token")
		return
	} else if err != nil {
		logger.Errorf("Failed to retrieve bootstrap token: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if time.Now().After(tokenRecord.ExpiresAt) {
		logger.Warnw("Expired bootstrap token used", "peer_id", req.PeerId, "token_id", tokenRecord.ID)
		s.writeEnrollError(w, api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED, "Bootstrap token expired")
		return
	}

	if tokenRecord.IsRevoked() {
		logger.Warnw("Revoked bootstrap token used", "peer_id", req.PeerId, "token_id", tokenRecord.ID)
		s.writeEnrollError(w, api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED, "Bootstrap token revoked")
		return
	}

	if tokenRecord.UsagesCount >= tokenRecord.MaxUsages {
		logger.Warnw("Max usages exceeded for bootstrap token", "peer_id", req.PeerId, "token_id", tokenRecord.ID)
		s.writeEnrollError(w, api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED, "Bootstrap token max usages exceeded")
		return
	}

	if req.RequestedRole == "" {
		s.writeEnrollError(w, api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED, "requested_role must be specified")
		return
	}

	if req.RequestedRole != tokenRecord.Role {
		logger.Warnw("Requested role does not match bootstrap token role", "peer_id", req.PeerId, "requested", req.RequestedRole, "token_role", tokenRecord.Role)
		s.writeEnrollError(w, api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED, fmt.Sprintf("requested role %q does not match bootstrap token role %q", req.RequestedRole, tokenRecord.Role))
		return
	}

	if err := api.ValidateLabels(req.Labels); err != nil {
		s.writeEnrollError(w, api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED, "Invalid labels: "+err.Error())
		return
	}

	pID, err := peer.Decode(req.PeerId)
	if err != nil {
		http.Error(w, "Invalid Peer ID", http.StatusBadRequest)
		return
	}
	canonical := pID.String()

	// Proof of possession: peer_id must be the submitted key's own, and the
	// caller must hold its private half. This gates the existing-request
	// branch below — a bootstrap token alone must not re-fetch another
	// peer's biscuit.
	enrolleeKey, err := crypto.UnmarshalPublicKey(req.PublicKey)
	if err != nil {
		s.writeEnrollError(w, api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED, "Invalid public key")
		return
	}
	if !pID.MatchesPublicKey(enrolleeKey) {
		logger.Warnw("Enrollment peer_id does not match public_key", "peer_id", canonical)
		s.writeEnrollError(w, api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED, "peer_id is not derived from public_key")
		return
	}
	if err := verifyFreshChallenge(enrolleeKey, api.EnrollChallenge(canonical, req.Timestamp), req.Timestamp, req.ChallengeSignature); err != nil {
		logger.Warnw("Enroll challenge verification failed", "peer_id", canonical, "error", err)
		s.writeEnrollError(w, api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED, "Invalid enrollment challenge: "+err.Error())
		return
	}

	// Bootstrap enrollments carry no OIDC identity, but the device-key ban
	// still applies, and before the existing-request lookup: a banned node
	// must not replay its old approved enrollment either.
	if banned, err := s.store.IsNodeBanned(ctx, canonical); err != nil {
		logger.Errorf("Failed to check node ban for %s: %v", canonical, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	} else if banned {
		logger.Warnw("Banned node attempted bootstrap enrollment", "peer_id", canonical)
		s.writeEnrollError(w, api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED, "Node is banned")
		return
	}

	// 2. Check for existing enrollment request
	existingReq, err := s.store.GetEnrollmentRequest(ctx, canonical)
	if err == nil {
		// Request already exists, return status
		var resp *api.BootstrapEnrollResponse
		if existingReq.Status == api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED {
			biscuitToken, resolvedAt, refreshErr := s.remintApprovedBootstrapBiscuit(ctx, existingReq, tokenRecord)
			if refreshErr != nil {
				if errors.Is(refreshErr, storage.ErrNodeBanned) || errors.Is(refreshErr, storage.ErrNodeSessionExpired) || errors.Is(refreshErr, errBootstrapRoleMismatch) {
					logger.Warnw("Refused bootstrap re-enrollment", "peer_id", req.PeerId, "error", refreshErr)
					s.writeEnrollError(w, api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED, "Enrollment no longer valid: "+refreshErr.Error())
					return
				}
				logger.Errorf("Failed to re-mint approved enrollment biscuit: %v", refreshErr)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			resp, err = s.buildApprovedBootstrapEnrollResponse(ctx, biscuitToken, resolvedAt)
			if err != nil {
				logger.Errorf("Failed to build approved response: %v", err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
		} else {
			resp = &api.BootstrapEnrollResponse{
				Status:       existingReq.Status,
				BiscuitToken: existingReq.BiscuitToken,
			}
		}
		s.writeEnrollResponse(w, resp)
		return
	} else if err != storage.ErrNotFound {
		logger.Errorf("Failed to query enrollment request: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// 3. Create new enrollment request
	enrollReq := &storage.EnrollmentRequest{
		ID:        cryptoRandUUID(),
		PeerID:    canonical,
		PublicKey: req.PublicKey,
		TokenID:   tokenRecord.ID,
		Status:    api.EnrollmentStatus_ENROLLMENT_STATUS_PENDING,
		Labels:    req.Labels,
		CreatedAt: time.Now(),
	}

	// No policy needed in token.

	// Fetch current signing private key
	privKey, _, err := s.store.GetCurrentKey(ctx)
	if err != nil {
		logger.Errorf("Failed to retrieve signing key: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if s.config.AutoApproveEnrollment {
		// Mode A: Auto-Approve
		policyRoles, _, err := s.store.GetMeshPolicy(ctx)
		if err != nil && err != storage.ErrNotFound {
			logger.Errorf("Failed to retrieve mesh policy: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		// Nobody reviews an auto-approved enrollment, so the role's
		// allowed_labels is the only thing standing between a self-declared
		// label and a signed one. Manual approval attests them separately.
		if err := api.LabelPatternsAllow(allowedLabelPatterns([]string{tokenRecord.Role}, policyRoles), req.Labels); err != nil {
			logger.Warnw("Rejected undeclarable label at bootstrap enrollment", "peer_id", canonical, "error", err)
			s.writeEnrollError(w, api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED, "Label not permitted: "+err.Error())
			return
		}
		biscuitBytes, err := identity.MintBootstrapBiscuitToken(privKey, pID, tokenRecord.Role, time.Now().Add(s.config.BiscuitTTL), policyRoles, req.Labels)
		if err != nil {
			logger.Errorf("Failed to mint bootstrap biscuit: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		enrollReq.Status = api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED
		enrollReq.BiscuitToken = biscuitBytes
		tNow := time.Now()
		enrollReq.ResolvedAt = &tNow
		enrollReq.ResolvedBy = "auto-approver"

		if err := s.store.CreateEnrollmentRequest(ctx, enrollReq); err != nil {
			logger.Errorf("Failed to save enrollment request: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		nodeRecord := &storage.EnrolledNode{
			PeerID:             canonical,
			PublicKey:          req.PublicKey,
			Biscuit:            biscuitBytes,
			Role:               tokenRecord.Role,
			OwnerID:            tokenRecord.OwnerID,
			EnrollmentType:     "BOOTSTRAP",
			Labels:             req.Labels,
			EnrolledAt:         time.Now(),
			ExpiresAt:          time.Time{},
			AutonomousRecovery: tokenRecord.AutonomousRecovery,
		}
		if err := s.store.EnrollNode(ctx, nodeRecord); err != nil {
			logger.Errorf("Failed to enroll active bootstrap node: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		if err := s.store.IncrementBootstrapTokenUsage(ctx, tokenRecord.ID); err != nil {
			logger.Errorf("Failed to increment token usage: %v", err)
		}

		resp, err := s.buildApprovedBootstrapEnrollResponse(ctx, biscuitBytes, enrollReq.ResolvedAt)
		if err != nil {
			logger.Errorf("Failed to build approved response: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		s.writeEnrollResponse(w, resp)
		return
	}

	// Mode B: Manual approval queue
	if err := s.store.CreateEnrollmentRequest(ctx, enrollReq); err != nil {
		logger.Errorf("Failed to save pending enrollment request: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	resp := &api.BootstrapEnrollResponse{
		Status:              api.EnrollmentStatus_ENROLLMENT_STATUS_PENDING,
		PollIntervalSeconds: 30,
	}
	s.writeEnrollResponse(w, resp)
}

// challengeMaxAge bounds the freshness window of every signed timestamp
// challenge on the enrollment surface (/enroll, /enroll/status, /refresh).
const challengeMaxAge = 5 * time.Minute

// verifyFreshChallenge checks a signed timestamp challenge: ts must be within
// challengeMaxAge of now and sig must verify over payload with pub. The
// payload (built by api.EnrollChallenge, api.EnrollStatusChallenge or
// api.RefreshChallenge) binds the peer and the endpoint, so a signature
// captured from one request verifies nowhere else.
func verifyFreshChallenge(pub crypto.PubKey, payload []byte, ts int64, sig []byte) error {
	if ts <= 0 {
		return errors.New("missing or invalid challenge timestamp")
	}
	challengeTime := time.UnixMilli(ts)
	now := time.Now()
	if now.Sub(challengeTime) > challengeMaxAge || challengeTime.Sub(now) > challengeMaxAge {
		return errors.New("stale or invalid challenge timestamp")
	}
	ok, err := pub.Verify(payload, sig)
	if err != nil || !ok {
		return errors.New("challenge signature verification failed")
	}
	return nil
}

// HandleEnrollStatus HTTP GET `/enroll/status`
//
// The approved response carries the enrollee's Biscuit, so polling requires
// proof of possession of the key submitted at /enroll: the
// api.HeaderChallengeTimestamp header (unix milliseconds) and the
// api.HeaderChallengeSignature header (unpadded base64url signature over
// api.EnrollStatusChallenge) must accompany `peer_id`. Every failure mode
// after the header parse answers a uniform 401 so the endpoint is not a
// peer-ID existence oracle for anonymous callers.
func (s *Server) HandleEnrollStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.limiter.Allow() {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	peerID := r.URL.Query().Get("peer_id")
	if peerID == "" {
		http.Error(w, "Missing peer_id parameter", http.StatusBadRequest)
		return
	}

	ts, tsErr := strconv.ParseInt(r.Header.Get(api.HeaderChallengeTimestamp), 10, 64)
	sig, sigErr := base64.RawURLEncoding.DecodeString(r.Header.Get(api.HeaderChallengeSignature))
	if tsErr != nil || sigErr != nil || len(sig) == 0 {
		http.Error(w, "Missing or invalid challenge headers: signed challenge required", http.StatusUnauthorized)
		return
	}

	pID, err := peer.Decode(peerID)
	if err != nil {
		http.Error(w, "Unauthorized, Invalid Peer ID", http.StatusUnauthorized)
		return
	}
	canonical := pID.String()

	ctx := r.Context()
	enrollReq, err := s.store.GetEnrollmentRequest(ctx, canonical)
	if err == storage.ErrNotFound {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	} else if err != nil {
		logger.Errorf("Failed to retrieve enrollment status: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	pubKey, err := crypto.UnmarshalPublicKey(enrollReq.PublicKey)
	if err != nil {
		logger.Errorf("Corrupted public key stored for enrollment %s: %v", canonical, err)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if err := verifyFreshChallenge(pubKey, api.EnrollStatusChallenge(canonical, ts), ts, sig); err != nil {
		logger.Warnw("Enroll status challenge verification failed", "peer_id", canonical, "error", err)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var resp *api.BootstrapEnrollResponse
	if enrollReq.Status == api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED {
		// A GET status poll must not mint credentials: unlike /enroll, this
		// endpoint checks neither a live bootstrap token nor the node
		// record's ban/admission state (banNode only flips nodes.banned; the
		// enrollment request stays APPROVED), so a banned peer or one that
		// lost its bootstrap token could otherwise poll forever for a fresh,
		// verifying biscuit using nothing but its own private key. Re-minting
		// belongs only on /enroll, where a currently-valid bootstrap token is
		// the operator's lever - see remintApprovedBootstrapBiscuit.
		resp, err = s.buildApprovedBootstrapEnrollResponse(ctx, enrollReq.BiscuitToken, enrollReq.ResolvedAt)
		if err != nil {
			logger.Errorf("Failed to build approved response: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	} else {
		resp = &api.BootstrapEnrollResponse{
			Status:       enrollReq.Status,
			BiscuitToken: enrollReq.BiscuitToken,
		}
		if enrollReq.Status == api.EnrollmentStatus_ENROLLMENT_STATUS_PENDING {
			resp.PollIntervalSeconds = 30
		}
	}
	s.writeEnrollResponse(w, resp)
}

func (s *Server) authenticateUser(r *http.Request) (*storage.User, error) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, errors.New("missing or invalid authorization header")
	}
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenStr == "" {
		return nil, errors.New("empty authorization token")
	}

	// 1. Check root admin token backdoor
	if s.config.AdminToken != "" {
		tokenHash := sha256.Sum256([]byte(tokenStr))
		adminHash := sha256.Sum256([]byte(s.config.AdminToken))
		if subtle.ConstantTimeCompare(tokenHash[:], adminHash[:]) == 1 {
			return &storage.User{
				ID:        "root-admin",
				Email:     "admin@sam-mesh.local",
				Role:      "admin",
				CreatedAt: time.Now(),
			}, nil
		}
	}

	// 2. Validate OIDC token
	ctx := r.Context()
	claims, _, err := identity.VerifyJWT(ctx, tokenStr, s.config.AllowedAudiences, s.getProviders())
	if err != nil {
		logger.Errorf("OIDC token verification failed: %v", err)
		return nil, fmt.Errorf("failed to verify OIDC token: %w", err)
	}

	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, errors.New("token subject (sub) claim is empty")
	}
	email, _ := claims["email"].(string)

	// Fetch or auto-register user
	user, err := s.store.GetUser(ctx, sub)
	if err == storage.ErrNotFound {
		user = &storage.User{
			ID:        sub,
			Email:     email,
			Role:      "user",
			CreatedAt: time.Now(),
		}
		if err := s.store.SaveUser(ctx, user); err != nil {
			return nil, fmt.Errorf("failed to register user: %w", err)
		}
		logger.Infow("Auto-registered new OIDC user", "id", sub, "email", email)
	} else if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return user, nil
}

func (s *Server) checkAdminAuth(w http.ResponseWriter, r *http.Request) bool {
	user, err := s.authenticateUser(r)
	if err != nil {
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return false
	}
	if user.Role != "admin" {
		http.Error(w, "Forbidden: Admin role required", http.StatusForbidden)
		return false
	}
	return true
}

// HandleAdminBootstrapTokens HTTP POST/GET `/admin/bootstrap-tokens`
func (s *Server) HandleAdminBootstrapTokens(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminAuth(w, r) {
		return
	}

	if r.Method == http.MethodGet {
		list, err := s.store.ListBootstrapTokens(r.Context())
		if err != nil {
			logger.Errorf("Failed to list bootstrap tokens: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(list)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Role        string `json:"role"`
		TTLHours    int    `json:"ttl_hours"`
		MaxUsages   int    `json:"max_usages"`
		Description string `json:"description"`
		// Copied onto every node this token enrolls; see
		// storage.EnrolledNode.AutonomousRecovery.
		AutonomousRecovery bool `json:"autonomous_recovery"`
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	defer func() { _ = r.Body.Close() }()

	if req.Role == "" {
		req.Role = api.RoleRouter
	}
	if req.TTLHours <= 0 {
		req.TTLHours = 24
	}
	if req.MaxUsages <= 0 {
		req.MaxUsages = 1
	}

	randBytes := make([]byte, 16)
	if _, err := rand.Read(randBytes); err != nil {
		http.Error(w, "Internal keygen error", http.StatusInternalServerError)
		return
	}
	tokenVal := fmt.Sprintf("sam-bt-%x", randBytes)
	tokenID := fmt.Sprintf("%x", sha256.Sum256([]byte(tokenVal)))

	tokenRecord := &storage.BootstrapToken{
		ID:                 tokenID,
		TokenHash:          tokenID,
		Role:               req.Role,
		MaxUsages:          req.MaxUsages,
		UsagesCount:        0,
		Description:        req.Description,
		CreatedAt:          time.Now(),
		ExpiresAt:          time.Now().Add(time.Duration(req.TTLHours) * time.Hour),
		AutonomousRecovery: req.AutonomousRecovery,
	}

	if err := s.store.SaveBootstrapToken(r.Context(), tokenRecord); err != nil {
		logger.Errorf("Failed to save bootstrap token: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id":         tokenRecord.ID,
		"token":      tokenVal,
		"role":       tokenRecord.Role,
		"expires_at": tokenRecord.ExpiresAt.Format(time.RFC3339),
	})
}

// HandleAdminBootstrapTokenAction HTTP DELETE `/admin/bootstrap-tokens/{id}`
// soft-revokes a token (see storage.BootstrapToken.RevokedAt): idempotent,
// and 404 only when the id names no token at all, per #368.
func (s *Server) HandleAdminBootstrapTokenAction(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminAuth(w, r) {
		return
	}

	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/admin/bootstrap-tokens/")
	if id == "" || strings.Contains(id, "/") {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	ctx := r.Context()
	if _, err := s.store.GetBootstrapToken(ctx, id); err == storage.ErrNotFound {
		http.Error(w, "Bootstrap token not found", http.StatusNotFound)
		return
	} else if err != nil {
		logger.Errorf("Failed to look up bootstrap token %s: %v", id, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if err := s.store.RevokeBootstrapToken(ctx, id); err != nil {
		logger.Errorf("Failed to revoke bootstrap token %s: %v", id, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// HandleAdminEnrollments HTTP GET `/admin/enrollments`
func (s *Server) HandleAdminEnrollments(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminAuth(w, r) {
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	list, err := s.store.ListEnrollmentRequests(r.Context())
	if err != nil {
		logger.Errorf("Failed to list enrollment requests: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(list)
}

// HandleAdminEnrollmentAction HTTP POST `/admin/enrollments/{id}/approve` or `/admin/enrollments/{id}/reject`
func (s *Server) HandleAdminEnrollmentAction(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminAuth(w, r) {
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/admin/enrollments/")
	parts := strings.Split(path, "/")
	if len(parts) != 2 {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	id := parts[0]
	action := parts[1]

	ctx := r.Context()
	enrollReq, err := s.store.GetEnrollmentRequestByID(ctx, id)
	if err == storage.ErrNotFound {
		http.Error(w, "Enrollment request not found", http.StatusNotFound)
		return
	} else if err != nil {
		logger.Errorf("Failed to query enrollment request: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if enrollReq.Status != api.EnrollmentStatus_ENROLLMENT_STATUS_PENDING {
		http.Error(w, "Enrollment request is already resolved", http.StatusConflict)
		return
	}

	adminIdentity := "admin"

	if action == "reject" {
		err = s.store.UpdateEnrollmentRequest(ctx, id, api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED, nil, adminIdentity)
		if err != nil {
			logger.Errorf("Failed to reject enrollment: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Enrollment rejected"))
		return
	}

	if action == "approve" {
		tokenRecord, err := s.store.GetBootstrapToken(ctx, enrollReq.TokenID)
		if err != nil {
			logger.Errorf("Failed to retrieve token for request: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		pID, err := peer.Decode(enrollReq.PeerID)
		if err != nil {
			http.Error(w, "Invalid Peer ID stored in request", http.StatusInternalServerError)
			return
		}
		canonical := pID.String()

		// No policy fetch needed.

		privKey, _, err := s.store.GetCurrentKey(ctx)
		if err != nil {
			logger.Errorf("Failed to retrieve signing key: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		policyRoles, _, err := s.store.GetMeshPolicy(ctx)
		if err != nil && err != storage.ErrNotFound {
			logger.Errorf("Failed to retrieve mesh policy: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		// Approval attests that this identity may join, but the labels came
		// from the node and nothing makes an admin read them before clicking
		// approve. Bound them by the role's grant like the other two
		// enrollment paths, so all three agree on what a node may claim.
		if err := api.LabelPatternsAllow(allowedLabelPatterns([]string{tokenRecord.Role}, policyRoles), enrollReq.Labels); err != nil {
			logger.Warnw("Refused to approve enrollment declaring an ungranted label",
				"peer_id", enrollReq.PeerID, "role", tokenRecord.Role, "error", err)
			http.Error(w, "Label not permitted: "+err.Error(), http.StatusForbidden)
			return
		}

		biscuitBytes, err := identity.MintBootstrapBiscuitToken(privKey, pID, tokenRecord.Role, time.Now().Add(s.config.BiscuitTTL), policyRoles, enrollReq.Labels)
		if err != nil {
			logger.Errorf("Failed to mint bootstrap biscuit: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		err = s.store.UpdateEnrollmentRequest(ctx, id, api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED, biscuitBytes, adminIdentity)
		if err != nil {
			logger.Errorf("Failed to approve enrollment request in DB: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		nodeRecord := &storage.EnrolledNode{
			PeerID:             canonical,
			PublicKey:          enrollReq.PublicKey,
			Biscuit:            biscuitBytes,
			Role:               tokenRecord.Role,
			OwnerID:            tokenRecord.OwnerID,
			EnrollmentType:     "BOOTSTRAP",
			Labels:             enrollReq.Labels,
			EnrolledAt:         time.Now(),
			ExpiresAt:          time.Time{},
			AutonomousRecovery: tokenRecord.AutonomousRecovery,
		}
		if err := s.store.EnrollNode(ctx, nodeRecord); err != nil {
			logger.Errorf("Failed to enroll active bootstrap node: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		if err := s.store.IncrementBootstrapTokenUsage(ctx, tokenRecord.ID); err != nil {
			logger.Errorf("Failed to increment token usage: %v", err)
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Enrollment approved"))
		return
	}

	http.Error(w, "Invalid action", http.StatusBadRequest)
}

// HandleAdminNodeAction HTTP POST `/admin/nodes/{peer_id}/autonomous-recovery`
// with body {"enabled": bool} toggles storage.EnrolledNode.AutonomousRecovery
// for one enrolled node. This is the per-node counterpart of the flag on a
// bootstrap token, for a node that is already enrolled.
func (s *Server) HandleAdminNodeAction(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminAuth(w, r) {
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/admin/nodes/"), "/")
	if len(parts) != 2 || parts[1] != adminNodeActionAutonomousRecovery {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	pID, err := peer.Decode(parts[0])
	if err != nil {
		http.Error(w, "Invalid Peer ID", http.StatusBadRequest)
		return
	}

	var req struct {
		Enabled bool `json:"enabled"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	defer func() { _ = r.Body.Close() }()

	canonical := pID.String()
	err = s.store.SetNodeAutonomousRecovery(r.Context(), canonical, req.Enabled)
	if err == storage.ErrNotFound {
		http.Error(w, "Node not found", http.StatusNotFound)
		return
	} else if err != nil {
		logger.Errorf("Failed to set autonomous recovery for node %s: %v", canonical, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	logger.Infow("Autonomous recovery toggled", "peer_id", canonical, "enabled", req.Enabled)
	w.WriteHeader(http.StatusNoContent)
}

// HandleAdminRevoke HTTP POST `/admin/revoke`
func (s *Server) HandleAdminRevoke(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminAuth(w, r) {
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	var req api.TokenRevokeRequest
	if err := proto.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	if req.PeerId == "" {
		http.Error(w, "peer_id is required", http.StatusBadRequest)
		return
	}

	pID, err := peer.Decode(req.PeerId)
	if err != nil {
		http.Error(w, "Invalid Peer ID", http.StatusBadRequest)
		return
	}
	canonical := pID.String()

	// Retrieve the node from storage to verify it exists
	node, err := s.store.GetNode(ctx, canonical)
	if err == storage.ErrNotFound {
		http.Error(w, "Node not found", http.StatusNotFound)
		return
	} else if err != nil {
		logger.Errorf("Failed to retrieve node record for revocation: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if err := s.banNode(ctx, node); err != nil {
		logger.Errorf("Failed to ban/revoke node %s: %v", canonical, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if err := s.getMeshAdapter().PublishEvent(ctx, api.MeshEvent_BANNED, node.PeerID, nil); err != nil {
		logger.Warnf("Failed to publish BANNED event for node %s to mesh: %v", node.PeerID, err)
	}

	resp := &api.TokenRevokeResponse{
		Success: true,
	}
	respData, err := proto.Marshal(resp)
	if err != nil {
		http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respData)
}

// errBootstrapRoleMismatch guards remintApprovedBootstrapBiscuit's role
// check: the bootstrap token presented at /enroll must match the role the
// peer was actually admitted under, or a stale or reused token could re-mint
// a biscuit for a role the node's enrollment record never granted it.
var errBootstrapRoleMismatch = errors.New("bootstrap token role does not match enrolled node role")

// remintApprovedBootstrapBiscuit re-mints and persists a fresh biscuit for an
// already-approved bootstrap enrollment request, sourcing role and labels
// from the enrolled node record - never from the request or the bootstrap
// token - since that record is what both approval paths wrote before ever
// returning this enrollment request as APPROVED.
//
// This runs unconditionally on every hit of the existing-request branch, not
// behind a "has the stored token aged past BiscuitTTL" check: that heuristic
// missed a router that refreshed (B1->B2 in the node record) and then
// restarted inside the TTL - it would get stale B1 back from this request and
// still 401 on every future /refresh - and it missed a biscuit that is still
// within its TTL but was signed by a key retired past its rotation grace
// period. Always re-minting here sidesteps all three by construction. It is
// safe to do unconditionally because the only caller, HandleEnroll's
// existing-request branch, already sits behind a fresh proof-of-possession
// signature and a currently-valid, non-exhausted bootstrap token - an
// operator-controlled lever. HandleEnrollStatus (a GET status poll) must
// never call this: it has no equivalent gate, only a signature check, so
// minting there would hand any peer a forever-renewable credential.
func (s *Server) remintApprovedBootstrapBiscuit(ctx context.Context, existingReq *storage.EnrollmentRequest, tokenRecord *storage.BootstrapToken) ([]byte, *time.Time, error) {
	pID, err := peer.Decode(existingReq.PeerID)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid stored peer id %q: %w", existingReq.PeerID, err)
	}

	// Look up by pID.String() (canonical), not the raw existingReq.PeerID,
	// matching every other GetNode call site (e.g. HandleRefresh) - the two
	// need not be byte-identical strings for the same peer.
	nodeRecord, err := s.store.GetNode(ctx, pID.String())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve enrolled node %s: %w", pID, err)
	}

	if tokenRecord.Role != nodeRecord.Role {
		return nil, nil, fmt.Errorf("%w: token role %q, node role %q", errBootstrapRoleMismatch, tokenRecord.Role, nodeRecord.Role)
	}
	if err := nodeRecord.CheckAdmission(time.Now()); err != nil {
		return nil, nil, err
	}

	privKey, _, err := s.store.GetCurrentKey(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve signing key: %w", err)
	}

	policyRoles, _, err := s.store.GetMeshPolicy(ctx)
	if err != nil && err != storage.ErrNotFound {
		return nil, nil, fmt.Errorf("failed to retrieve mesh policy: %w", err)
	}

	biscuitExpiry := time.Now().Add(s.config.BiscuitTTL)
	biscuitBytes, err := identity.MintBootstrapBiscuitToken(privKey, pID, nodeRecord.Role, biscuitExpiry, policyRoles, nodeRecord.Labels)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to mint refreshed bootstrap biscuit: %w", err)
	}

	if err := s.store.UpdateEnrollmentRequest(ctx, existingReq.ID, api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED, biscuitBytes, existingReq.ResolvedBy); err != nil {
		return nil, nil, fmt.Errorf("failed to persist refreshed enrollment request: %w", err)
	}

	// Keep the node record's biscuit in lockstep: /refresh's reuse-detection
	// compares a presented biscuit against exactly this field.
	nodeRecord.Biscuit = biscuitBytes
	nodeRecord.EnrolledAt = time.Now()
	if err := s.store.EnrollNode(ctx, nodeRecord); err != nil {
		return nil, nil, fmt.Errorf("failed to persist refreshed node record: %w", err)
	}

	// Re-minting consumes a use of the bootstrap token, the same as the
	// original enrollment did - it is the operator's lever on how many times
	// this can happen, per #367/#368. A failure here only means the usage
	// counter under-counts; it must not block the peer from getting its
	// (already persisted) fresh biscuit.
	if err := s.store.IncrementBootstrapTokenUsage(ctx, tokenRecord.ID); err != nil {
		logger.Errorf("Failed to increment bootstrap token usage on re-mint for %s: %v", pID, err)
	}

	resolvedAt := time.Now()
	return biscuitBytes, &resolvedAt, nil
}

func (s *Server) buildApprovedBootstrapEnrollResponse(ctx context.Context, biscuitToken []byte, resolvedAt *time.Time) (*api.BootstrapEnrollResponse, error) {
	_, pubKey, err := s.store.GetCurrentKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve signing key: %w", err)
	}

	activeRouters, err := s.store.GetActiveRouters(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve active routers: %w", err)
	}

	var routerAddrs []string
	for _, r := range activeRouters {
		routerAddrs = append(routerAddrs, r.Addresses...)
	}

	expiration := time.Now().Add(s.config.BiscuitTTL).Unix()
	if resolvedAt != nil {
		expiration = resolvedAt.Add(s.config.BiscuitTTL).Unix()
	}

	return &api.BootstrapEnrollResponse{
		Status:                api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED,
		BiscuitToken:          biscuitToken,
		ControlPlanePublicKey: pubKey,
		RouterAddresses:       routerAddrs,
		Expiration:            expiration,
	}, nil
}

func (s *Server) HandleUserStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, err := s.authenticateUser(r)
	if err != nil {
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	ctx := r.Context()
	routers, err := s.store.GetActiveRouters(ctx)
	if err != nil {
		logger.Errorf("Failed to get active routers: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	nodes := []storage.EnrolledNode{}
	if user.Role == "admin" {
		nodes, err = s.store.ListNodes(ctx)
	} else {
		allNodes, err := s.store.ListNodes(ctx)
		if err == nil {
			for _, n := range allNodes {
				if n.OwnerID == user.ID {
					nodes = append(nodes, n)
				}
			}
		}
	}
	if err != nil {
		logger.Errorf("Failed to list nodes: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	tokens := []storage.BootstrapToken{}
	allTokens, err := s.store.ListBootstrapTokens(ctx)
	if err == nil {
		for _, t := range allTokens {
			if t.OwnerID == user.ID || user.Role == "admin" {
				tokens = append(tokens, t)
			}
		}
	}
	if err != nil {
		logger.Errorf("Failed to list bootstrap tokens: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	roles, bindings, err := s.store.GetMeshPolicy(r.Context())
	if err != nil {
		logger.Errorf("Failed to list policy: %v", err)
	}

	var policyJSON string
	if rendered, err := marshalPolicyJSON(roles, bindings); err == nil {
		policyJSON = rendered
	} else {
		logger.Errorf("Failed to render policy: %v", err)
	}

	resp := map[string]any{
		"user": map[string]any{
			"id":    user.ID,
			"email": user.Email,
			"role":  user.Role,
		},
		"active_routers":   routers,
		"enrolled_nodes":   nodes,
		"bootstrap_tokens": tokens,
		"policy_json":      policyJSON,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) HandleUserBootstrapTokens(w http.ResponseWriter, r *http.Request) {
	user, err := s.authenticateUser(r)
	if err != nil {
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Role        string `json:"role"`
		OwnerID     string `json:"owner_id"`
		TTLHours    int    `json:"ttl_hours"`
		MaxUsages   int    `json:"max_usages"`
		Description string `json:"description"`
		// Copied onto every node this token enrolls; see
		// storage.EnrolledNode.AutonomousRecovery. Admin-only: it decides
		// whether a lost device can rejoin the mesh on its own.
		AutonomousRecovery bool `json:"autonomous_recovery"`
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	defer func() { _ = r.Body.Close() }()

	if req.Role == "" {
		req.Role = api.RoleNode
	}

	if user.Role != "admin" && req.Role != api.RoleNode && req.Role != api.RoleSamBox {
		http.Error(w, "Forbidden: Standard users can only generate tokens for node or box roles", http.StatusForbidden)
		return
	}
	if user.Role != "admin" && req.AutonomousRecovery {
		http.Error(w, "Forbidden: only admins can issue tokens with autonomous_recovery", http.StatusForbidden)
		return
	}

	ownerID, status, err := s.resolveTokenOwner(r.Context(), user, req.OwnerID)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}

	if req.TTLHours <= 0 {
		req.TTLHours = 24
	}
	if req.MaxUsages <= 0 {
		req.MaxUsages = 1
	}

	randBytes := make([]byte, 16)
	if _, err := rand.Read(randBytes); err != nil {
		http.Error(w, "Internal keygen error", http.StatusInternalServerError)
		return
	}
	tokenVal := fmt.Sprintf("sam-bt-%x", randBytes)
	tokenID := fmt.Sprintf("%x", sha256.Sum256([]byte(tokenVal)))

	tokenRecord := &storage.BootstrapToken{
		ID:                 tokenID,
		TokenHash:          tokenID,
		Role:               req.Role,
		OwnerID:            ownerID,
		MaxUsages:          req.MaxUsages,
		UsagesCount:        0,
		Description:        req.Description,
		CreatedAt:          time.Now(),
		ExpiresAt:          time.Now().Add(time.Duration(req.TTLHours) * time.Hour),
		AutonomousRecovery: req.AutonomousRecovery,
	}

	if err := s.store.SaveBootstrapToken(r.Context(), tokenRecord); err != nil {
		logger.Errorf("Failed to save bootstrap token: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id":         tokenRecord.ID,
		"token":      tokenVal,
		"role":       tokenRecord.Role,
		"owner_id":   tokenRecord.OwnerID,
		"expires_at": tokenRecord.ExpiresAt.Format(time.RFC3339),
	})
}

// resolveTokenOwner determines which user a bootstrap token is issued on behalf of.
// The owner defaults to the caller; only admins may override it, and only with a
// user that already exists. Returns the owner plus an HTTP status to use on error.
func (s *Server) resolveTokenOwner(ctx context.Context, caller *storage.User, requested string) (string, int, error) {
	requested = strings.TrimSpace(requested)
	if requested == "" || requested == caller.ID {
		return caller.ID, 0, nil
	}
	if caller.Role != "admin" {
		return "", http.StatusForbidden, errors.New("forbidden: only admins may issue tokens on behalf of another user")
	}
	if _, err := s.store.GetUser(ctx, requested); err != nil {
		if err == storage.ErrNotFound {
			return "", http.StatusBadRequest, fmt.Errorf("unknown owner_id %q: the user must have logged in at least once", requested)
		}
		return "", http.StatusInternalServerError, errors.New("failed to look up owner")
	}
	return requested, 0, nil
}

func (s *Server) HandleUserRevoke(w http.ResponseWriter, r *http.Request) {
	user, err := s.authenticateUser(r)
	if err != nil {
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	peerID := r.URL.Query().Get("id")
	if peerID == "" {
		http.Error(w, "Missing id parameter", http.StatusBadRequest)
		return
	}

	pID, err := peer.Decode(peerID)
	if err != nil {
		http.Error(w, "Invalid Peer ID", http.StatusBadRequest)
		return
	}
	canonical := pID.String()

	ctx := r.Context()
	node, err := s.store.GetNode(ctx, canonical)
	if err == storage.ErrNotFound {
		http.Error(w, "Node not found", http.StatusNotFound)
		return
	}
	if err != nil {
		logger.Errorf("Failed to check node owner: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if node.OwnerID != user.ID && user.Role != "admin" {
		http.Error(w, "Forbidden: You do not own this node", http.StatusForbidden)
		return
	}

	if err := s.banNode(ctx, node); err != nil {
		logger.Errorf("Failed to revoke node: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if err := s.getMeshAdapter().PublishEvent(ctx, api.MeshEvent_BANNED, node.PeerID, nil); err != nil {
		logger.Warnf("Failed to publish BANNED event for node %s to mesh: %v", node.PeerID, err)
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Node revoked successfully"))
}

// oidcIdentityKey names an enrolled OIDC identity independently of any
// keypair: issuer and subject, the pair the issuer promises stable. Empty
// when there is no subject (e.g. bootstrap enrollments).
func oidcIdentityKey(claims jwt.MapClaims) string {
	if claims == nil {
		return ""
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return ""
	}
	iss, _ := claims["iss"].(string)
	return iss + "|" + sub
}

// banNode bans the device key and, when the record carries OIDC claims, the
// enrolled identity behind it, so the ban survives keypair regeneration.
func (s *Server) banNode(ctx context.Context, node *storage.EnrolledNode) error {
	if err := s.store.SetNodeBanned(ctx, node.PeerID, true); err != nil {
		return err
	}
	s.dropCatalogEntry(node.PeerID)
	if node.ClaimsJSON == "" {
		return nil
	}
	var claims jwt.MapClaims
	if err := json.Unmarshal([]byte(node.ClaimsJSON), &claims); err != nil {
		return fmt.Errorf("stored claims for %s are unreadable: %w", node.PeerID, err)
	}
	if key := oidcIdentityKey(claims); key != "" {
		return s.store.SetIdentityBanned(ctx, key, true)
	}
	return nil
}

// allowedLabelPatterns collects the label grants of every role an identity
// resolves to. A role that names none contributes none, so an identity with no
// grant anywhere may declare no labels at all.
func allowedLabelPatterns(roles []string, policyRoles []*api.PolicyRole) []string {
	wanted := make(map[string]bool, len(roles))
	for _, r := range roles {
		wanted[r] = true
	}
	var patterns []string
	for _, pr := range policyRoles {
		if pr != nil && wanted[pr.Name] {
			patterns = append(patterns, pr.AllowedLabels...)
		}
	}
	return patterns
}

func resolveRoles(peerID string, claims jwt.MapClaims, bindings []*api.PolicyBinding) []string {
	if claims == nil {
		claims = make(jwt.MapClaims)
	}

	// Driven by the same claim->fact map that minting uses, so a claim added
	// there resolves bindings here too instead of being silently ignored.
	factValues := make(map[string][]string)
	for claim, fact := range api.OIDCClaimToFact() {
		factValues[fact] = append(factValues[fact], toStringSlice(claims[claim])...)
	}

	resolvedRoles := make(map[string]bool)
	for _, b := range bindings {
		if b == nil {
			continue
		}
		for _, m := range b.Members {
			if m == api.SystemAuthenticated {
				resolvedRoles[b.Role] = true
				continue
			}
			parts := strings.SplitN(m, ":", 2)
			if len(parts) != 2 {
				continue
			}
			prefix, value := parts[0], parts[1]
			// node is the peer presenting the request, not an OIDC claim.
			if prefix == api.FactNode {
				if peerID == value {
					resolvedRoles[b.Role] = true
				}
				continue
			}
			if slices.Contains(factValues[prefix], value) {
				resolvedRoles[b.Role] = true
			}
		}
	}

	var res []string
	for r := range resolvedRoles {
		res = append(res, r)
	}
	return res
}

func toStringSlice(val any) []string {
	if val == nil {
		return nil
	}
	switch v := val.(type) {
	case string:
		if v != "" {
			return []string{v}
		}
	case []string:
		return v
	case []any:
		var res []string
		for _, item := range v {
			if str, ok := item.(string); ok && str != "" {
				res = append(res, str)
			}
		}
		return res
	}
	return nil
}

// marshalPolicyJSON renders the stored mesh policy as protojson using the proto
// field names. Generated marshalling is the point: a hand-maintained mirror of
// PolicyRole silently drops any field it forgets, which is how custom_datalog
// went missing from the console for so long.
func marshalPolicyJSON(roles []*api.PolicyRole, bindings []*api.PolicyBinding) (string, error) {
	resp := &api.PolicyConfigGetResponse{Roles: roles, Bindings: bindings}
	marshaler := protojson.MarshalOptions{UseProtoNames: true, Multiline: true, Indent: "  "}
	out, err := marshaler.Marshal(resp)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// maxIdentityFactBudget bounds the worst-case number of Datalog facts a policy
// config could let a single identity accumulate across all of its resolved
// roles. biscuit-go's authorizer defaults to rejecting worlds beyond ~1000
// facts (datalog.ErrWorldRunLimitMaxFacts); this stays safely under that limit
// so an admin gets a clear validation error instead of users hitting
// unexplained authorization failures later.
const maxIdentityFactBudget = 900

func validatePolicyConfig(req *api.PolicyConfigUpdateRequest) error {
	roleNames := make(map[string]bool)
	factBudget := 0
	for _, r := range req.Roles {
		if r == nil {
			continue
		}
		if strings.TrimSpace(r.Name) == "" {
			return fmt.Errorf("role name cannot be empty")
		}
		if roleNames[r.Name] {
			return fmt.Errorf("duplicate role name: %s", r.Name)
		}
		roleNames[r.Name] = true

		for _, svc := range r.AllowedServices {
			if err := api.ValidateServiceFormat(svc); err != nil {
				return fmt.Errorf("invalid allowed_service %q in role %s: %w", svc, r.Name, err)
			}
		}
		for _, target := range r.AllowedTargets {
			if err := api.ValidateTargetFormat(target); err != nil {
				return fmt.Errorf("invalid allowed_target %q in role %s: %w", target, r.Name, err)
			}
		}
		for _, agent := range r.AllowedAgents {
			if err := api.ValidateAgentPattern(agent); err != nil {
				return fmt.Errorf("invalid allowed_agent %q in role %s: %w", agent, r.Name, err)
			}
		}
		for _, label := range r.AllowedLabels {
			if err := api.ValidateLabelPattern(label); err != nil {
				return fmt.Errorf("in role %s: %w", r.Name, err)
			}
		}
		for _, dl := range r.CustomDatalog {
			trimmed := strings.TrimRight(strings.TrimSpace(dl), ";")
			if trimmed == "" {
				continue
			}
			if _, err := parser.FromStringRule(trimmed); err != nil {
				if _, err := parser.FromStringFact(trimmed); err != nil {
					return fmt.Errorf("invalid custom datalog %q in role %s: %w", dl, r.Name, err)
				}
			}
		}

		// Worst case for fact-count purposes assumes a single identity could be
		// granted every role (e.g. via overlapping group/claim bindings), so we
		// sum each role's contribution rather than relying on assumptions about
		// which roles are mutually exclusive for a given identity.
		factBudget += len(api.BuildServiceDatalogFacts(r.AllowedServices))
		factBudget += len(api.BuildTargetDatalogFacts(r.AllowedTargets))
		factBudget += len(api.BuildAgentDatalogFacts(r.AllowedAgents))
		factBudget += len(r.CustomDatalog)
	}

	if factBudget > maxIdentityFactBudget {
		return fmt.Errorf("policy config would allow a single identity (via overlapping bindings) to accumulate up to %d Datalog facts across all roles, exceeding the safe budget of %d; biscuit-go's authorizer rejects tokens/checks beyond ~1000 world facts, so requests would start failing at authorization time instead of at config validation. Reduce the number of roles, grants, or custom_datalog entries", factBudget, maxIdentityFactBudget)
	}

	validPrefixes := map[string]bool{
		api.FactNode:  true,
		api.FactGroup: true,
		api.FactUser:  true,
		api.FactEmail: true,
		api.FactRole:  true,
	}

	for _, b := range req.Bindings {
		if b == nil {
			continue
		}
		if strings.TrimSpace(b.Role) == "" {
			return fmt.Errorf("binding role cannot be empty")
		}
		if !roleNames[b.Role] {
			return fmt.Errorf("binding references undefined role: %s", b.Role)
		}
		if len(b.Members) == 0 {
			return fmt.Errorf("binding for role %q must specify at least one member", b.Role)
		}
		for _, member := range b.Members {
			if member == api.SystemAuthenticated {
				continue
			}
			parts := strings.SplitN(member, ":", 2)
			if len(parts) != 2 || strings.TrimSpace(parts[1]) == "" {
				return fmt.Errorf("member %q in binding for role %q is invalid, must be in format 'type:value' or %q", member, b.Role, api.SystemAuthenticated)
			}
			prefix := parts[0]
			if !validPrefixes[prefix] {
				return fmt.Errorf("member prefix %q in member %q is invalid", prefix, member)
			}
		}
	}
	return nil
}
