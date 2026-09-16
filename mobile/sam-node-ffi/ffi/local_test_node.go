//go:build sam_debug

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

package ffi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/google/sam/api"
	"github.com/google/sam/internal/node"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// localTestNode identifies ownership of the shared mobile node slot. Protected by mu.
var localTestNode *node.SamNode

// StartLocalTestNode boots a real, isolated loopback node with a debug-only issuer.
// Its peer key persists in a separate store; the short-lived fixture issuer is
// regenerated each start. This is neither enrollment nor a paired-device identity.
func StartLocalTestNode(root string) error {
	mu.Lock()
	defer mu.Unlock()
	if activeNode != nil || unauthSrv != nil || pendingStart != nil {
		return errors.New("node is already running")
	}
	if !filepath.IsAbs(root) {
		return errors.New("local test storage must be an absolute private directory")
	}
	store, err := node.NewStore(filepath.Join(root, "local-test-v1"))
	if err != nil {
		return fmt.Errorf("open local test storage: %w", err)
	}
	adopted := false
	defer func() {
		if !adopted {
			_ = store.Close()
		}
	}()
	key, err := localTestPeerKey(store)
	if err != nil {
		return err
	}
	id, err := peer.IDFromPrivateKey(key)
	if err != nil {
		return err
	}
	issuerPub, issuerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	builder := biscuit.NewBuilder(issuerKey)
	for _, fact := range []biscuit.Fact{
		{Predicate: biscuit.Predicate{Name: "node", IDs: []biscuit.Term{biscuit.String(id.String())}}},
		{Predicate: biscuit.Predicate{Name: api.FactRole, IDs: []biscuit.Term{biscuit.String(api.RoleNode)}}},
		{Predicate: biscuit.Predicate{Name: api.FactExpiration, IDs: []biscuit.Term{biscuit.Date(time.Now().Add(time.Hour))}}},
	} {
		if err := builder.AddAuthorityFact(fact); err != nil {
			return err
		}
	}
	token, err := builder.Build()
	if err != nil {
		return err
	}
	encoded, err := token.Serialize()
	if err != nil {
		return err
	}
	if err := store.SaveIdentity(encoded); err != nil {
		return err
	}
	if err := store.SaveMeshConfig(issuerPub, nil); err != nil {
		return err
	}
	// Do not import persisted trust from another run of this isolated fixture.
	if err := store.SaveTrustedKeys(nil); err != nil {
		return err
	}
	instance, err := node.NewSamNode(node.Options{
		Store: store, PrivKey: key, ControlPlanePubKey: issuerPub,
		MeshID: "android-local-lifecycle-test", RequiredRole: api.RoleNode,
		ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}, AllowLoopback: true,
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := instance.Start(ctx); err != nil {
		cancel()
		_ = instance.Teardown()
		return fmt.Errorf("start local test node: %w", err)
	}
	activeNode, localTestNode, activeStore, cancelFunc = instance, instance, store, cancel
	adopted = true
	return nil
}

// Unlike GetOrGenerateKey, corrupt/unwritable storage returns an error to Android
// instead of terminating the entire application through logger.Fatalf.
func localTestPeerKey(store *node.Store) (crypto.PrivKey, error) {
	encoded, err := store.LoadKey()
	if err != nil {
		return nil, err
	}
	if len(encoded) > 0 {
		return crypto.UnmarshalPrivateKey(encoded)
	}
	key, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return nil, err
	}
	encoded, err = crypto.MarshalPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err = store.SaveKey(encoded); err != nil {
		return nil, err
	}
	return key, nil
}

// StopLocalTestNode is idempotent and never stops a node owned by another mode.
func StopLocalTestNode() error {
	mu.Lock()
	defer mu.Unlock()
	if activeNode == nil && unauthSrv == nil {
		return nil
	}
	if activeNode != localTestNode || activeNode == nil {
		return errors.New("active node is not the local test fixture")
	}
	if cancelFunc != nil {
		cancelFunc()
		cancelFunc = nil
	}
	err := errors.Join(activeNode.Teardown(), activeStore.Close())
	activeNode, localTestNode, activeStore = nil, nil, nil
	return err
}

// LocalTestNodeStatus reports process state, not authentication evidence.
func LocalTestNodeStatus() string {
	mu.Lock()
	defer mu.Unlock()
	status := struct {
		State           string   `json:"state"`
		PeerID          string   `json:"peerId,omitempty"`
		ListenAddresses []string `json:"listenAddresses,omitempty"`
	}{State: "stopped"}
	if activeNode != nil || unauthSrv != nil {
		status.State = "unavailable"
		if activeNode != nil && activeNode == localTestNode && activeNode.Host != nil {
			status.State = "running"
			status.PeerID = activeNode.Host.ID().String()
			for _, addr := range activeNode.Host.Network().ListenAddresses() {
				if _, err := addr.ValueForProtocol(multiaddr.P_TCP); err == nil {
					status.ListenAddresses = append(status.ListenAddresses, addr.String())
				}
			}
		}
	}
	encoded, _ := json.Marshal(status) // this closed struct contains only JSON-supported fields
	return string(encoded)
}
