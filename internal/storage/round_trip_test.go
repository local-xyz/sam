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

package storage

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/sam/api"
)

// Every record here is taken apart into named columns on the way in and put
// back together on the way out, and the two lists are written by hand. A field
// added to the struct but not to both lists is stored nowhere and read back
// zero, with nothing failing: the caller saves, the API returns what it was
// given, and the value quietly does not exist. That is how a role's
// allowed_agents shipped inert.
//
// These tests are built so that adding a field breaks them. requireAllFieldsSet
// runs over the value being saved, so a new field left out of the literal fails
// before any database work happens, which is the moment to ask whether the
// store writes it.

// requireAllFieldsSet fails when an exported field is still at its zero value.
// skip names fields a save path deliberately ignores; each needs a reason.
func requireAllFieldsSet(t *testing.T, v any, skip ...string) {
	t.Helper()
	skipped := make(map[string]bool, len(skip))
	for _, s := range skip {
		skipped[s] = true
	}

	val := reflect.ValueOf(v)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	for i := 0; i < val.NumField(); i++ {
		field := val.Type().Field(i)
		if !field.IsExported() || skipped[field.Name] {
			continue
		}
		if val.Field(i).IsZero() {
			t.Fatalf("%s.%s is not set in this test: populate it and check the store persists it",
				val.Type().Name(), field.Name)
		}
	}
}

// requireFieldsRoundTrip compares exported fields one by one so a failure names
// the field that was dropped rather than dumping two structs.
func requireFieldsRoundTrip(t *testing.T, want, got any, skip ...string) {
	t.Helper()
	skipped := make(map[string]bool, len(skip))
	for _, s := range skip {
		skipped[s] = true
	}

	w := reflect.ValueOf(want)
	g := reflect.ValueOf(got)
	if w.Kind() == reflect.Ptr {
		w, g = w.Elem(), g.Elem()
	}
	for i := 0; i < w.NumField(); i++ {
		field := w.Type().Field(i)
		if !field.IsExported() || skipped[field.Name] {
			continue
		}
		if !valuesEqual(w.Field(i), g.Field(i)) {
			t.Errorf("%s.%s did not round trip: saved %v, loaded %v",
				w.Type().Name(), field.Name, w.Field(i).Interface(), g.Field(i).Interface())
		}
	}
}

// valuesEqual compares at the coarsest precision any of these columns store,
// which is whole seconds for the timestamps written with Unix().
func valuesEqual(w, g reflect.Value) bool {
	switch wv := w.Interface().(type) {
	case time.Time:
		gv, ok := g.Interface().(time.Time)
		return ok && wv.Unix() == gv.Unix()
	case *time.Time:
		gv, ok := g.Interface().(*time.Time)
		if !ok || (wv == nil) != (gv == nil) {
			return false
		}
		return wv == nil || wv.Unix() == gv.Unix()
	}
	return reflect.DeepEqual(w.Interface(), g.Interface())
}

func TestEnrolledNodeRoundTripsEveryField(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	want := &EnrolledNode{
		PeerID:         "12D3KooWRoundTrip",
		PublicKey:      []byte("public-key-bytes"),
		Biscuit:        []byte("biscuit-bytes"),
		Role:           api.RoleNode,
		EnrollmentType: "OIDC",
		ClaimsJSON:     `{"sub":"alice"}`,
		OwnerID:        "owner-1",
		Labels:         map[string]string{"region": "emea"},
		EnrolledAt:     time.Now().Add(-time.Hour),
		ExpiresAt:      time.Now().Add(time.Hour),
		// Non-default so the round trip proves the column is read back.
		AutonomousRecovery: true,
	}
	// Banned is never set by enrollment; a node cannot un-ban itself by
	// re-enrolling. TestReEnrollmentKeepsAnExistingBan covers that.
	requireAllFieldsSet(t, want, "Banned")

	if err := store.EnrollNode(ctx, want); err != nil {
		t.Fatalf("EnrollNode: %v", err)
	}

	got, err := store.GetNode(ctx, want.PeerID)
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	requireFieldsRoundTrip(t, want, got, "Banned")

	// ListNodes selects its own column list, so it can drift from GetNode.
	listed, err := store.ListNodes(ctx)
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("ListNodes returned %d nodes, want 1", len(listed))
	}
	requireFieldsRoundTrip(t, want, &listed[0], "Banned")
}

// Autonomous recovery is a per-node, server-side opt-in: it must default
// off, flip on and off via SetNodeAutonomousRecovery, and report ErrNotFound
// for a peer that was never enrolled (so an admin toggle can 404 instead of
// silently updating zero rows).
func TestSetNodeAutonomousRecovery(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	node := &EnrolledNode{
		PeerID:         "12D3KooWRecover",
		PublicKey:      []byte("pub"),
		Biscuit:        []byte("biscuit"),
		Role:           api.RoleRouter,
		EnrollmentType: "BOOTSTRAP",
		EnrolledAt:     time.Now(),
	}
	if err := store.EnrollNode(ctx, node); err != nil {
		t.Fatalf("EnrollNode: %v", err)
	}
	got, err := store.GetNode(ctx, node.PeerID)
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	if got.AutonomousRecovery {
		t.Fatal("AutonomousRecovery must default to false")
	}

	if err := store.SetNodeAutonomousRecovery(ctx, node.PeerID, true); err != nil {
		t.Fatalf("SetNodeAutonomousRecovery(true): %v", err)
	}
	got, err = store.GetNode(ctx, node.PeerID)
	if err != nil {
		t.Fatalf("GetNode after enable: %v", err)
	}
	if !got.AutonomousRecovery {
		t.Fatal("SetNodeAutonomousRecovery(true) did not persist")
	}
	if err := store.SetNodeAutonomousRecovery(ctx, node.PeerID, false); err != nil {
		t.Fatalf("SetNodeAutonomousRecovery(false): %v", err)
	}
	got, err = store.GetNode(ctx, node.PeerID)
	if err != nil {
		t.Fatalf("GetNode after disable: %v", err)
	}
	if got.AutonomousRecovery {
		t.Fatal("SetNodeAutonomousRecovery(false) did not persist")
	}

	if err := store.SetNodeAutonomousRecovery(ctx, "12D3KooWNobody", true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SetNodeAutonomousRecovery(unknown peer) = %v, want ErrNotFound", err)
	}
}

// A ban is the mesh's way of turning a node off. Re-enrolling must not clear
// it, or revocation would last only until the node asked again.
func TestReEnrollmentKeepsAnExistingBan(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	node := &EnrolledNode{
		PeerID:         "12D3KooWBanned",
		PublicKey:      []byte("pub"),
		Biscuit:        []byte("biscuit"),
		Role:           api.RoleNode,
		EnrollmentType: "OIDC",
		EnrolledAt:     time.Now(),
	}
	if err := store.EnrollNode(ctx, node); err != nil {
		t.Fatalf("EnrollNode: %v", err)
	}
	if err := store.SetNodeBanned(ctx, node.PeerID, true); err != nil {
		t.Fatalf("SetNodeBanned: %v", err)
	}

	// The same node enrols again, as it would after a restart.
	if err := store.EnrollNode(ctx, node); err != nil {
		t.Fatalf("re-EnrollNode: %v", err)
	}

	got, err := store.GetNode(ctx, node.PeerID)
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	if !got.Banned {
		t.Error("re-enrolling cleared the ban; a banned node could restart its way back in")
	}
	banned, err := store.IsNodeBanned(ctx, node.PeerID)
	if err != nil {
		t.Fatalf("IsNodeBanned: %v", err)
	}
	if !banned {
		t.Error("IsNodeBanned disagrees with the loaded record")
	}
}

func TestBootstrapTokenRoundTripsEveryField(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	want := &BootstrapToken{
		ID:          "token-id",
		TokenHash:   "hash",
		Role:        api.RoleNode,
		OwnerID:     "owner-1",
		MaxUsages:   5,
		UsagesCount: 2,
		Description: "a description",
		CreatedAt:   time.Now().Add(-time.Hour),
		ExpiresAt:   time.Now().Add(time.Hour),
		// Non-default so the round trip proves the column is read back.
		AutonomousRecovery: true,
	}
	// RevokedAt is never set at creation - only RevokeBootstrapToken sets it,
	// covered separately below.
	requireAllFieldsSet(t, want, "RevokedAt")

	if err := store.SaveBootstrapToken(ctx, want); err != nil {
		t.Fatalf("SaveBootstrapToken: %v", err)
	}

	got, err := store.GetBootstrapToken(ctx, want.ID)
	if err != nil {
		t.Fatalf("GetBootstrapToken: %v", err)
	}
	requireFieldsRoundTrip(t, want, got)
	if got.IsRevoked() {
		t.Error("a freshly saved token must not start out revoked")
	}

	listed, err := store.ListBootstrapTokens(ctx)
	if err != nil {
		t.Fatalf("ListBootstrapTokens: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("ListBootstrapTokens returned %d, want 1", len(listed))
	}
	requireFieldsRoundTrip(t, want, &listed[0])

	if err := store.RevokeBootstrapToken(ctx, want.ID); err != nil {
		t.Fatalf("RevokeBootstrapToken: %v", err)
	}
	revoked, err := store.GetBootstrapToken(ctx, want.ID)
	if err != nil {
		t.Fatalf("GetBootstrapToken after revoke: %v", err)
	}
	if !revoked.IsRevoked() {
		t.Fatal("RevokedAt was not persisted by RevokeBootstrapToken")
	}

	// Idempotent: revoking an already-revoked token is not an error and does
	// not un-set RevokedAt.
	if err := store.RevokeBootstrapToken(ctx, want.ID); err != nil {
		t.Fatalf("RevokeBootstrapToken (second call): %v", err)
	}
	revokedAgain, err := store.GetBootstrapToken(ctx, want.ID)
	if err != nil {
		t.Fatalf("GetBootstrapToken after second revoke: %v", err)
	}
	if !revokedAgain.IsRevoked() {
		t.Error("a second RevokeBootstrapToken call must not un-revoke the token")
	}

	// Revoking an unknown id is also not an error - the HTTP layer is what
	// distinguishes "unknown" via a preceding GetBootstrapToken.
	if err := store.RevokeBootstrapToken(ctx, "no-such-token"); err != nil {
		t.Errorf("RevokeBootstrapToken(unknown id) = %v, want nil", err)
	}
}

func TestEnrollmentRequestRoundTripsEveryField(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	resolvedAt := time.Now().Add(-time.Minute)
	want := &EnrollmentRequest{
		ID:        "request-id",
		PeerID:    "12D3KooWPending",
		PublicKey: []byte("pub"),
		TokenID:   "token-id",
		Status:    api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED,
		// Labels decide what the minted biscuit attests, so losing them here
		// would silently drop a node's attested claims.
		Labels:       map[string]string{"region": "emea"},
		BiscuitToken: []byte("biscuit"),
		CreatedAt:    time.Now().Add(-time.Hour),
		ResolvedAt:   &resolvedAt,
		ResolvedBy:   "admin",
	}
	requireAllFieldsSet(t, want)

	if err := store.CreateEnrollmentRequest(ctx, want); err != nil {
		t.Fatalf("CreateEnrollmentRequest: %v", err)
	}

	byPeer, err := store.GetEnrollmentRequest(ctx, want.PeerID)
	if err != nil {
		t.Fatalf("GetEnrollmentRequest: %v", err)
	}
	requireFieldsRoundTrip(t, want, byPeer)

	byID, err := store.GetEnrollmentRequestByID(ctx, want.ID)
	if err != nil {
		t.Fatalf("GetEnrollmentRequestByID: %v", err)
	}
	requireFieldsRoundTrip(t, want, byID)

	listed, err := store.ListEnrollmentRequests(ctx)
	if err != nil {
		t.Fatalf("ListEnrollmentRequests: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("ListEnrollmentRequests returned %d, want 1", len(listed))
	}
	requireFieldsRoundTrip(t, want, &listed[0])
}

func TestRouterLeaseRoundTripsEveryField(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	want := &RouterLease{
		PeerID:         "12D3KooWRouter",
		Addresses:      []string{"/ip4/127.0.0.1/tcp/4001"},
		LastRenewal:    time.Now().Add(-time.Minute),
		ExpiresAt:      time.Now().Add(time.Hour),
		ConnectedPeers: []string{"12D3KooWPeerA"},
		DHTSize:        42,
	}
	requireAllFieldsSet(t, want)

	if err := store.UpsertRouterLease(ctx, want); err != nil {
		t.Fatalf("UpsertRouterLease: %v", err)
	}

	active, err := store.GetActiveRouters(ctx)
	if err != nil {
		t.Fatalf("GetActiveRouters: %v", err)
	}
	if len(active) != 1 {
		t.Fatalf("GetActiveRouters returned %d, want 1", len(active))
	}
	requireFieldsRoundTrip(t, want, &active[0])
}

func TestUserRoundTripsEveryField(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	want := &User{
		ID:        "user-1",
		Email:     "alice@example.com",
		Role:      "admin",
		CreatedAt: time.Now().Add(-time.Hour),
	}
	requireAllFieldsSet(t, want)

	if err := store.SaveUser(ctx, want); err != nil {
		t.Fatalf("SaveUser: %v", err)
	}

	got, err := store.GetUser(ctx, want.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	requireFieldsRoundTrip(t, want, got)

	listed, err := store.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("ListUsers returned %d, want 1", len(listed))
	}
	requireFieldsRoundTrip(t, want, &listed[0])
}

// PolicyBinding is what attaches a role to an identity, so a field lost here
// would mean a binding that reads as configured and grants nothing.
func TestPolicyBindingRoundTripsEveryField(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	want := &api.PolicyBinding{
		Role:    api.RoleNode,
		Members: []string{"group:platform", api.SystemAuthenticated},
	}
	requireProtoFieldsSet(t, want)

	if err := store.SaveMeshPolicy(ctx, nil, []*api.PolicyBinding{want}); err != nil {
		t.Fatalf("SaveMeshPolicy: %v", err)
	}

	_, bindings, err := store.GetMeshPolicy(ctx)
	if err != nil {
		t.Fatalf("GetMeshPolicy: %v", err)
	}
	if len(bindings) != 1 {
		t.Fatalf("got %d bindings, want 1", len(bindings))
	}
	got := bindings[0]

	if got.Role != want.Role {
		t.Errorf("PolicyBinding.Role did not round trip: saved %q, loaded %q", want.Role, got.Role)
	}
	if !reflect.DeepEqual(got.Members, want.Members) {
		t.Errorf("PolicyBinding.Members did not round trip: saved %v, loaded %v", want.Members, got.Members)
	}
}

// requireProtoFieldsSet is requireAllFieldsSet for generated messages, whose
// unexported state and internal fields have to be stepped over.
func requireProtoFieldsSet(t *testing.T, v any) {
	t.Helper()
	val := reflect.ValueOf(v).Elem()
	for i := 0; i < val.NumField(); i++ {
		field := val.Type().Field(i)
		if !field.IsExported() || strings.HasPrefix(field.Name, "XXX_") {
			continue
		}
		switch field.Type.Kind() {
		case reflect.String, reflect.Slice, reflect.Map:
			if val.Field(i).IsZero() {
				t.Fatalf("%s.%s is not set in this test: populate it and check the store persists it",
					val.Type().Name(), field.Name)
			}
		}
	}
}
