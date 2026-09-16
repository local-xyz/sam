//go:build sam_debug

package node

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSharedMeshLoopbackHeaders(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" || r.Header.Get("X-Peer-Id") != "verified" {
			t.Errorf("trusted headers missing")
		}
		if r.Header.Get("X-Smuggled") != "" || r.Header.Get("Connection") != "" {
			t.Errorf("hop headers survived")
		}
	}))
	defer backend.Close()
	req, _ := http.NewRequest("GET", backend.URL, nil)
	req.Header.Set("Connection", "X-Peer-Id, Authorization, X-Smuggled")
	req.Header.Set("X-Peer-Id", "attacker")
	req.Header.Set("Authorization", "Bearer attacker")
	req.Header.Set("X-Smuggled", "bad")
	transport := sharedMeshRoundTripper{base: http.DefaultTransport, token: "secret", peerID: "verified"}
	res, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if req.Header.Get("X-Peer-Id") != "attacker" {
		t.Fatal("mutated inbound request")
	}
}
