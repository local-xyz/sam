// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package node

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/sam/api"
)

func TestHTTPServicePreservesRequestsAndStreamsBeforeCompletion(t *testing.T) {
	received := make(chan []string, 1)
	release := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received <- []string{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization"), string(body)}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, "data: admitted\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer backend.Close()
	defer close(release)

	req, err := buildRegisterRequest(api.ServiceConfig{Type: "http", Name: "roomlink", TargetURL: backend.URL})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewServiceFromRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer svc.Teardown()
	proxy := httptest.NewServer(svc.Handler())
	defer proxy.Close()

	call, _ := http.NewRequest(http.MethodPost, proxy.URL+"/v1/runs?after=2", strings.NewReader(`{"input":"hello"}`))
	call.Header.Set("Authorization", "HermesRoom scoped-grant")
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Do(call)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusAccepted || response.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("unexpected response: %s, %v", response.Status, response.Header)
	}
	line, err := bufio.NewReader(response.Body).ReadString('\n')
	if err != nil || line != "data: admitted\n" {
		t.Fatalf("event must arrive while backend is still running: %q, %v", line, err)
	}
	want := []string{"POST", "/v1/runs", "after=2", "HermesRoom scoped-grant", `{"input":"hello"}`}
	for i, got := range <-received {
		if got != want[i] {
			t.Fatalf("request field %d = %q, want %q", i, got, want[i])
		}
	}
}

func TestHTTPServiceRejectsCommandBackend(t *testing.T) {
	req, err := buildRegisterRequest(api.ServiceConfig{Type: "http", Name: "roomlink", Command: []string{"echo", "hello"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewServiceFromRequest(req); err == nil {
		t.Fatal("HTTP services must not accept MCP command backends")
	}
}
