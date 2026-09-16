//go:build sam_debug

package ffi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/sam/api"
	"github.com/google/sam/internal/identity"
	"github.com/google/sam/internal/node"
	"github.com/google/sam/internal/standalone"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
)

// The bootstrap endpoint permits exactly one enrollment. The real standalone
// authority and router still authenticate the resulting identity on each start.
func enrollmentFixture(t *testing.T) (context.Context, SharedMeshConfig, *atomic.Int32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	t.Cleanup(cancel)
	authority, err := standalone.New(standalone.Options{BindAddress: "127.0.0.1:0", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { authority.Close() })
	target, _ := url.Parse("http://" + authority.Addr())
	proxy := httputil.NewSingleHostReverseProxy(target)
	enrollments := new(atomic.Int32)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/enroll" && enrollments.Add(1) > 1 {
			http.Error(w, "bootstrap token exhausted", http.StatusUnauthorized)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	return ctx, SharedMeshConfig{DataDir: t.TempDir(), BootstrapURL: server.URL, JoinToken: authority.JoinToken()}, enrollments
}

func TestSharedMeshRestartUsesStoredEnrollment(t *testing.T) {
	ctx, cfg, enrollments := enrollmentFixture(t)
	mesh, err := newSharedMesh(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	id := mesh.node.Host.ID()
	token := append([]byte(nil), mesh.node.GetIdentity()...)
	pub, _, err := mesh.store.LoadMeshConfig()
	if err != nil {
		t.Fatal(err)
	}
	trusted := []node.TrustedKey{{Key: pub, ReceivedAt: time.Now()}}
	if err := mesh.store.SaveTrustedKeys(trusted); err != nil {
		t.Fatal(err)
	}
	if err := mesh.close(); err != nil {
		t.Fatal(err)
	}
	for _, joinToken := range []string{"", "expired-bootstrap-token"} {
		cfg.JoinToken = joinToken
		mesh, err = newSharedMesh(ctx, cfg)
		if err != nil {
			t.Fatalf("restart with join token %q: %v", joinToken, err)
		}
		if mesh.node.Host.ID() != id || !bytes.Equal(mesh.node.GetIdentity(), token) {
			t.Error("restart replaced persisted identity")
		}
		keys, err := mesh.store.LoadTrustedKeys()
		if err != nil || len(keys) != 1 || !bytes.Equal(keys[0].Key, pub) {
			t.Errorf("restart lost trusted keys: %v", err)
		}
		if err := mesh.close(); err != nil {
			t.Fatal(err)
		}
	}
	if got := enrollments.Load(); got != 1 {
		t.Fatalf("bootstrap enrollments=%d; want 1", got)
	}
}

func TestSharedMeshFirstJoinRequiresToken(t *testing.T) {
	ctx, cfg, enrollments := enrollmentFixture(t)
	cfg.JoinToken = ""
	mesh, err := newSharedMesh(ctx, cfg)
	if mesh != nil {
		mesh.close()
	}
	if err == nil || !strings.Contains(err.Error(), "joinToken") {
		t.Fatalf("missing join token: %v", err)
	}
	if enrollments.Load() != 0 {
		t.Fatal("tokenless first join reached enrollment")
	}
}

func TestSharedMeshStoredStateFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name, key, value string
		remove           bool
	}{
		{name: "missing identity", key: "identity_biscuit", remove: true},
		{name: "malformed identity", key: "identity_biscuit", value: "bad token"},
		{name: "missing key", key: "node_private_key", remove: true},
		{name: "corrupt key", key: "node_private_key", value: "bad key"},
		{name: "missing authority", key: "control_plane_public_key", remove: true},
		{name: "invalid authority", key: "control_plane_public_key", value: "bad key"},
		{name: "missing URL", key: "control_plane_url", remove: true},
		{name: "wrong mesh", key: "control_plane_url", value: "https://different.invalid"},
		{name: "invalid routers JSON", key: "router_addresses", value: "{"},
		{name: "invalid router", key: "router_addresses", value: `["not a multiaddr"]`},
		{name: "missing routers", key: "router_addresses", remove: true},
		{name: "missing expiration", key: "identity_expiration", remove: true},
		{name: "invalid trusted keys", key: "trusted_keys", value: "{"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cfg, enrollments := enrollmentFixture(t)
			mesh, err := newSharedMesh(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := mesh.close(); err != nil {
				t.Fatal(err)
			}
			db, err := bbolt.Open(filepath.Join(cfg.DataDir, "shared-mesh-v1", node.StoreFile), 0600, nil)
			if err != nil {
				t.Fatal(err)
			}
			err = db.Update(func(tx *bbolt.Tx) error {
				b := tx.Bucket([]byte("identity"))
				if tc.remove {
					return b.Delete([]byte(tc.key))
				}
				return b.Put([]byte(tc.key), []byte(tc.value))
			})
			if closeErr := db.Close(); err != nil || closeErr != nil {
				t.Fatalf("alter store: %v, %v", err, closeErr)
			}
			mesh, err = newSharedMesh(ctx, cfg)
			if mesh != nil {
				mesh.close()
			}
			if err == nil {
				t.Fatal("invalid stored enrollment was accepted")
			}
			if enrollments.Load() != 1 {
				t.Fatal("invalid stored enrollment triggered bootstrap reenrollment")
			}
		})
	}
}

func TestSharedMeshStoredIdentityRefresh(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		expired bool
		invalid bool
	}{
		{"retired key", http.StatusOK, false, false},
		{"expired identity", http.StatusOK, true, false},
		{"unauthorized", http.StatusUnauthorized, true, false},
		{"revoked", http.StatusForbidden, true, false},
		{"invalid refresh response", http.StatusOK, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status := tc.status
			ctx, cfg, enrollments := enrollmentFixture(t)
			mesh, err := newSharedMesh(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			id := mesh.node.Host.ID()
			valid := append([]byte(nil), mesh.node.GetIdentity()...)
			keyBytes, err := mesh.store.LoadKey()
			if err != nil {
				t.Fatal(err)
			}
			key, err := crypto.UnmarshalPrivateKey(keyBytes)
			if err != nil {
				t.Fatal(err)
			}
			_, staleKey, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			stale, err := identity.MintBootstrapBiscuitToken(staleKey, id, api.RoleNode, time.Now().Add(-time.Hour), nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			var refreshes, unexpected atomic.Int32
			recovery := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/refresh" {
					unexpected.Add(1)
					http.Error(w, "unexpected request", 404)
					return
				}
				refreshes.Add(1)
				bearer, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
				data, readErr := io.ReadAll(r.Body)
				req := new(api.TokenRefreshRequest)
				decodeErr := proto.Unmarshal(data, req)
				ok, sigErr := key.GetPublic().Verify(api.RefreshChallenge(req.PeerId, req.Timestamp), req.ChallengeSignature)
				if err != nil || readErr != nil || decodeErr != nil || !bytes.Equal(bearer, stale) || req.PeerId != id.String() || !ok || sigErr != nil {
					http.Error(w, "bad refresh proof", 400)
					return
				}
				if status != http.StatusOK {
					http.Error(w, "recovery denied", status)
					return
				}
				replacement := valid
				if tc.invalid {
					replacement = []byte("malformed refreshed identity")
				}
				response, _ := proto.Marshal(&api.TokenRefreshResponse{BiscuitToken: replacement, ExpiresAt: time.Now().Add(time.Hour).Unix()})
				_, _ = w.Write(response)
			}))
			defer recovery.Close()
			if tc.expired {
				if err := mesh.store.SaveTrustedKeys([]node.TrustedKey{{Key: staleKey.Public().(ed25519.PublicKey), ReceivedAt: time.Now()}}); err != nil {
					t.Fatal(err)
				}
			}
			cfg.BootstrapURL = recovery.URL
			if err := mesh.store.SaveControlPlaneURL(cfg.BootstrapURL); err != nil {
				t.Fatal(err)
			}
			if err := mesh.store.SaveIdentity(stale); err != nil {
				t.Fatal(err)
			}
			if err := mesh.store.SaveIdentityExpiration(time.Now().Add(-time.Hour).Unix()); err != nil {
				t.Fatal(err)
			}
			if err := mesh.close(); err != nil {
				t.Fatal(err)
			}
			cfg.JoinToken = "expired-bootstrap-token"
			mesh, err = newSharedMesh(ctx, cfg)
			if mesh != nil {
				defer mesh.close()
			}
			if status == http.StatusOK && !tc.invalid {
				if err != nil {
					t.Fatalf("recover stored identity: %v", err)
				}
				if mesh.node.Host.ID() != id || !bytes.Equal(mesh.node.GetIdentity(), valid) {
					t.Fatal("refresh did not preserve PeerID and adopt replacement identity")
				}
			} else {
				if err == nil {
					t.Fatal("rejected recovery succeeded")
				}
				store, err := node.NewStore(filepath.Join(cfg.DataDir, "shared-mesh-v1"))
				if err != nil {
					t.Fatal(err)
				}
				stored, err := store.LoadIdentity()
				store.Close()
				if err != nil || !bytes.Equal(stored, stale) {
					t.Fatal("rejected refresh replaced stored identity")
				}
			}
			if unexpected.Load() != 0 {
				t.Fatal("recovery attempted a non-refresh endpoint")
			}
			if refreshes.Load() != 1 {
				t.Fatalf("refresh attempts=%d; want 1", refreshes.Load())
			}
			if enrollments.Load() != 1 {
				t.Fatal("refresh triggered bootstrap reenrollment")
			}
		})
	}
}

func TestSharedMeshExplicitMembershipResetKeepsPeerID(t *testing.T) {
	ctx, cfg, _ := enrollmentFixture(t)
	mesh, err := newSharedMesh(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	id := mesh.node.Host.ID()
	if err := mesh.close(); err != nil {
		t.Fatal(err)
	}
	store, err := node.NewStore(filepath.Join(cfg.DataDir, "shared-mesh-v1"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ResetMeshIdentity(); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	_, newMesh, enrollments := enrollmentFixture(t)
	newMesh.DataDir = cfg.DataDir
	mesh, err = newSharedMesh(ctx, newMesh)
	if err != nil {
		t.Fatal(err)
	}
	defer mesh.close()
	if mesh.node.Host.ID() != id {
		t.Fatal("explicit membership reset changed PeerID")
	}
	if enrollments.Load() != 1 {
		t.Fatal("explicit reset did not enroll into the new mesh")
	}
}

func TestSharedMeshRefreshHonorsStartupDeadline(t *testing.T) {
	ctx, cfg, _ := enrollmentFixture(t)
	mesh, err := newSharedMesh(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, staleKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := identity.MintBootstrapBiscuitToken(staleKey, mesh.node.Host.ID(), api.RoleNode, time.Now().Add(-time.Hour), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/refresh" {
			http.Error(w, "unexpected request", 404)
			return
		}
		entered <- struct{}{}
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer server.Close()
	defer close(release)
	cfg.BootstrapURL = server.URL
	cfg.JoinToken = ""
	if err := mesh.store.SaveControlPlaneURL(cfg.BootstrapURL); err != nil {
		t.Fatal(err)
	}
	if err := mesh.store.SaveIdentity(stale); err != nil {
		t.Fatal(err)
	}
	if err := mesh.close(); err != nil {
		t.Fatal(err)
	}
	startup, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	defer cancel()
	before := time.Now()
	mesh, err = newSharedMesh(startup, cfg)
	if mesh != nil {
		mesh.close()
	}
	if err == nil {
		t.Fatal("stalled refresh succeeded")
	}
	if time.Since(before) > time.Second {
		t.Fatal("refresh ignored startup deadline")
	}
	select {
	case <-entered:
	default:
		t.Fatal("startup did not reach refresh")
	}
	store, err := node.NewStore(filepath.Join(cfg.DataDir, "shared-mesh-v1"))
	if err != nil {
		t.Fatalf("refresh failure leaked store: %v", err)
	}
	store.Close()
}

func TestSharedMeshInvalidEnrollmentResponseDoesNotPersist(t *testing.T) {
	for _, invalid := range []string{"router", "expiration"} {
		t.Run(invalid, func(t *testing.T) {
			store, err := node.NewStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			key, err := localTestPeerKey(store)
			if err != nil {
				t.Fatal(err)
			}
			id, err := peer.IDFromPrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			pub, priv, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			exp := time.Now().Add(time.Hour)
			token, err := identity.MintBootstrapBiscuitToken(priv, id, api.RoleNode, exp, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			response := &api.BootstrapEnrollResponse{Status: api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED, ControlPlanePublicKey: pub, BiscuitToken: token, Expiration: exp.Unix(), RouterAddresses: []string{"/ip4/127.0.0.1/tcp/1234/p2p/" + id.String()}}
			if invalid == "router" {
				response.RouterAddresses = []string{"not an address"}
			} else {
				response.Expiration = 0
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { data, _ := proto.Marshal(response); _, _ = w.Write(data) }))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err = bootstrapSharedMesh(ctx, SharedMeshConfig{BootstrapURL: server.URL, JoinToken: "join"}, store, key)
			if err == nil {
				t.Fatal("invalid bootstrap response accepted")
			}
			if saved, _ := store.LoadIdentity(); len(saved) != 0 {
				t.Fatal("invalid response persisted enrollment")
			}
		})
	}
}
