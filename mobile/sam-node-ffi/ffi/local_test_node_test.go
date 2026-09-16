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
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/sam/internal/node"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

func TestLocalTestNodeLifecycle(t *testing.T) {
	root := t.TempDir()
	if err := StartLocalTestNode(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = StopLocalTestNode() })
	first := GetNodeID()
	if _, err := peer.Decode(first); err != nil {
		t.Fatalf("not a real node: %q: %v", first, err)
	}
	var status struct {
		State           string   `json:"state"`
		PeerID          string   `json:"peerId"`
		ListenAddresses []string `json:"listenAddresses"`
	}
	if err := json.Unmarshal([]byte(LocalTestNodeStatus()), &status); err != nil {
		t.Fatal(err)
	}
	if status.State != "running" || status.PeerID != first || len(status.ListenAddresses) != 1 {
		t.Fatalf("bad status: %+v", status)
	}
	for _, bound := range activeNode.Host.Network().ListenAddresses() {
		if bound.String() != "/p2p-circuit" && !strings.HasPrefix(bound.String(), "/ip4/127.0.0.1/tcp/") {
			t.Fatalf("unexpected listener: %s", bound)
		}
	}
	address, err := multiaddr.NewMultiaddr(status.ListenAddresses[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(address.String(), "/ip4/127.0.0.1/") {
		t.Fatalf("not loopback: %s", address)
	}
	port, err := address.ValueForProtocol(multiaddr.P_TCP)
	if err != nil {
		t.Fatal(err)
	}
	if err := StopLocalTestNode(); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		t.Fatalf("stop did not release listener: %v", err)
	}
	_ = listener.Close()
	store, err := node.NewStore(filepath.Join(root, "local-test-v1"))
	if err != nil {
		t.Fatalf("stop did not release store: %v", err)
	}
	_ = store.Close()
	if err := StartLocalTestNode(root); err != nil {
		t.Fatal(err)
	}
	if GetNodeID() != first {
		t.Fatal("restart replaced persisted peer identity")
	}
}

func TestLocalTestNodeConcurrentStart(t *testing.T) {
	root := t.TempDir()
	results := make(chan error, 2)
	var group sync.WaitGroup
	for range 2 {
		group.Add(1)
		go func() { defer group.Done(); results <- StartLocalTestNode(root) }()
	}
	group.Wait()
	close(results)
	t.Cleanup(func() { _ = StopLocalTestNode() })
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("expected one node, successful starts=%d", successes)
	}
}

func TestLocalTestNodeFailureLeavesNoActiveNode(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "local-test-v1"), []byte("occupied"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := StartLocalTestNode(root); err == nil {
		t.Fatal("expected invalid storage error")
	}
	if GetNodeID() != "" {
		t.Fatal("failed start published a node")
	}
	if err := StartLocalTestNode(t.TempDir()); err != nil {
		t.Fatalf("failure poisoned next start: %v", err)
	}
	if err := StopLocalTestNode(); err != nil {
		t.Fatal(err)
	}
}

func TestLocalTestNodeCorruptKeyDoesNotRotateIdentity(t *testing.T) {
	root := t.TempDir()
	store, err := node.NewStore(filepath.Join(root, "local-test-v1"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveKey([]byte("corrupt-key")); err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	if err := StartLocalTestNode(root); err == nil {
		t.Fatal("corrupt key must fail startup")
	}
	if GetNodeID() != "" {
		t.Fatal("corrupt storage produced a running node")
	}
	reopened, err := node.NewStore(filepath.Join(root, "local-test-v1"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	key, err := reopened.LoadKey()
	if err != nil || string(key) != "corrupt-key" {
		t.Fatal("corrupt identity was silently replaced")
	}
}

func TestLocalTestNodeCannotTakeOverEnrollmentSidecar(t *testing.T) {
	config, _ := json.Marshal(MobileConfig{DataDir: t.TempDir(), ControlPlaneURL: "https://invalid.example", BindAddr: "127.0.0.1:0"})
	if err := StartNode(string(config)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = StopNode() })
	if err := StartLocalTestNode(t.TempDir()); err == nil {
		t.Fatal("fixture took over existing node slot")
	}
	if err := StopLocalTestNode(); err == nil {
		t.Fatal("fixture stopped a mode it does not own")
	}
	if GetNodeID() != "unauthenticated" {
		t.Fatal("enrollment sidecar was changed")
	}
	var status map[string]any
	if err := json.Unmarshal([]byte(LocalTestNodeStatus()), &status); err != nil {
		t.Fatal(err)
	}
	if status["state"] != "unavailable" {
		t.Fatalf("enrollment sidecar misrepresented as running: %v", status)
	}
}
