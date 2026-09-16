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

package node

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/sam/api"
	"github.com/ipfs/go-cid"
)

type fakeDHT struct {
	calls   []cid.Cid
	failNth int
	count   int32
}

func (f *fakeDHT) Provide(ctx context.Context, c cid.Cid, _ bool) error {
	n := atomic.AddInt32(&f.count, 1)
	f.calls = append(f.calls, c)
	if f.failNth > 0 && int(n) == f.failNth {
		return errors.New("fake dht failure")
	}
	return nil
}

type fakeService struct {
	info          *api.ServiceInfo
	initCalls     int
	teardownCalls int
	initErr       error
	handler       http.Handler
}

func (f *fakeService) Info() *api.ServiceInfo { return f.info }
func (f *fakeService) Init(ctx context.Context) error {
	f.initCalls++
	return f.initErr
}
func (f *fakeService) Handler() http.Handler { return f.handler }
func (f *fakeService) Teardown() error {
	f.teardownCalls++
	return nil
}

func newFakeSvc(name string, st api.ServiceType) *fakeService {
	return &fakeService{
		info:    &api.ServiceInfo{Name: name, Type: st},
		handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}),
	}
}

// newServiceRegistryForTest builds a registry against the fake DHT for tests.
func newServiceRegistryForTest(d dhtProvider) *ServiceRegistry {
	return &ServiceRegistry{
		services:            map[string]Service{},
		dht:                 d,
		backendProbeTimeout: defaultDHTProbeTimeout,
	}
}

func TestServiceRegistry_RegisterCallsInitThenProvide(t *testing.T) {
	dht := &fakeDHT{}
	r := newServiceRegistryForTest(dht)

	svc := newFakeSvc("demo", api.ServiceType_SERVICE_TYPE_MCP)
	if err := r.Register(context.Background(), svc); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if svc.initCalls != 1 {
		t.Errorf("Init called %d times, want 1", svc.initCalls)
	}
	if len(dht.calls) != 2 {
		t.Fatalf("Provide called %d times, want 2 (name + type CID)", len(dht.calls))
	}
}

func TestServiceRegistry_InitErrorBlocksProvideAndInsertion(t *testing.T) {
	dht := &fakeDHT{}
	r := newServiceRegistryForTest(dht)

	svc := newFakeSvc("demo", api.ServiceType_SERVICE_TYPE_MCP)
	svc.initErr = errors.New("init failed")
	if err := r.Register(context.Background(), svc); err == nil {
		t.Fatal("expected error from Register, got nil")
	}
	if len(dht.calls) != 0 {
		t.Errorf("Provide called %d times after Init failure, want 0", len(dht.calls))
	}
	if _, ok := r.Get("demo"); ok {
		t.Error("service should not be in map after Init failure")
	}
}

func TestServiceRegistry_UnregisterRemovesAndCallsTeardown(t *testing.T) {
	dht := &fakeDHT{}
	r := newServiceRegistryForTest(dht)

	svc := newFakeSvc("demo", api.ServiceType_SERVICE_TYPE_MCP)
	_ = r.Register(context.Background(), svc)
	if err := r.Unregister(context.Background(), "demo"); err != nil {
		t.Fatalf("Unregister: %v", err)
	}
	if svc.teardownCalls != 1 {
		t.Errorf("Teardown called %d times, want 1", svc.teardownCalls)
	}
	if _, ok := r.Get("demo"); ok {
		t.Error("service still present after Unregister")
	}
}

func TestServiceRegistry_UnregisterUnknownIsNoOp(t *testing.T) {
	r := newServiceRegistryForTest(&fakeDHT{})
	if err := r.Unregister(context.Background(), "missing"); err != nil {
		t.Fatalf("Unregister missing: %v", err)
	}
}

func TestServiceRegistry_ListFiltersByType(t *testing.T) {
	r := newServiceRegistryForTest(&fakeDHT{})
	_ = r.Register(context.Background(), newFakeSvc("a", api.ServiceType_SERVICE_TYPE_MCP))
	_ = r.Register(context.Background(), newFakeSvc("b", api.ServiceType_SERVICE_TYPE_INFERENCE))

	all := r.List(api.ServiceType_SERVICE_TYPE_UNSPECIFIED)
	if len(all) != 2 {
		t.Errorf("List(all): got %d, want 2", len(all))
	}
	mcpOnly := r.List(api.ServiceType_SERVICE_TYPE_MCP)
	if len(mcpOnly) != 1 || mcpOnly[0].Name != "a" {
		t.Errorf("List(MCP): got %v, want [a]", mcpOnly)
	}
}

func TestServiceRegistry_TeardownAllContinuesOnError(t *testing.T) {
	r := newServiceRegistryForTest(&fakeDHT{})
	a := newFakeSvc("a", api.ServiceType_SERVICE_TYPE_MCP)
	b := newFakeSvc("b", api.ServiceType_SERVICE_TYPE_MCP)
	_ = r.Register(context.Background(), a)
	_ = r.Register(context.Background(), b)

	r.TeardownAll()

	if a.teardownCalls != 1 || b.teardownCalls != 1 {
		t.Errorf("teardown calls: a=%d b=%d, want both 1", a.teardownCalls, b.teardownCalls)
	}
	if len(r.List(api.ServiceType_SERVICE_TYPE_UNSPECIFIED)) != 0 {
		t.Error("registry not empty after TeardownAll")
	}
}

// probingService is a service whose backend can be asked whether it answers.
type probingService struct {
	*fakeService
	mu         sync.Mutex
	probeErr   error
	probeCalls int
}

func (p *probingService) Probe(context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.probeCalls++
	return p.probeErr
}

func (p *probingService) setProbeErr(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.probeErr = err
}

func newProbingSvc(name string, probeErr error) *probingService {
	return &probingService{
		fakeService: newFakeSvc(name, api.ServiceType_SERVICE_TYPE_MCP),
		probeErr:    probeErr,
	}
}

// A backend that is not an MCP server at all -- the canary that answers HTTP
// but fails MCP initialize -- must not be advertised as one. It stays
// registered so the reprovide loop can pick it up if it starts answering.
func TestServiceRegistry_UnreachableBackendIsRegisteredButNotAdvertised(t *testing.T) {
	dht := &fakeDHT{}
	r := newServiceRegistryForTest(dht)

	svc := newProbingSvc("dummy-http", errors.New(`calling "initialize": EOF`))
	if err := r.Register(context.Background(), svc); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if len(dht.calls) != 0 {
		t.Errorf("Provide called %d times for an unreachable backend, want 0", len(dht.calls))
	}
	if _, ok := r.Get("dummy-http"); !ok {
		t.Error("service should stay registered so it can recover")
	}
}

// A service registered after the reprovide loop's last cycle would otherwise
// wait a whole interval to be advertised, which is minutes.
func TestServiceRegistry_WithheldRegistrationAsksForAReprovide(t *testing.T) {
	r := newServiceRegistryForTest(&fakeDHT{})
	var asked int
	r.reprovideNow = func() { asked++ }

	if err := r.Register(context.Background(), newProbingSvc("late", errors.New("not up yet"))); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if asked != 1 {
		t.Errorf("reprovide requested %d times for a withheld service, want 1", asked)
	}

	if err := r.Register(context.Background(), newProbingSvc("healthy", nil)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if asked != 1 {
		t.Errorf("reprovide requested %d times, want 1: an advertised service needs no retry", asked)
	}
}

func TestServiceRegistry_ReprovideWithholdsUnreachableBackend(t *testing.T) {
	dht := &fakeDHT{}
	r := newServiceRegistryForTest(dht)

	svc := newProbingSvc("demo", nil)
	if err := r.Register(context.Background(), svc); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if len(dht.calls) != 2 {
		t.Fatalf("Provide called %d times at registration, want 2", len(dht.calls))
	}

	svc.setProbeErr(errors.New("backend went away"))
	if withheld := r.ReprovideAll(context.Background()); withheld != 1 {
		t.Errorf("ReprovideAll reported %d withheld, want 1: the retry cadence depends on it", withheld)
	}
	if len(dht.calls) != 2 {
		t.Errorf("Provide called %d times total, want 2: a backend that stopped answering must fall out of the DHT", len(dht.calls))
	}
}

func TestServiceRegistry_ReprovideResumesWhenBackendRecovers(t *testing.T) {
	dht := &fakeDHT{}
	r := newServiceRegistryForTest(dht)

	svc := newProbingSvc("demo", errors.New("not up yet"))
	if err := r.Register(context.Background(), svc); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if len(dht.calls) != 0 {
		t.Fatalf("Provide called %d times while the backend was down, want 0", len(dht.calls))
	}

	svc.setProbeErr(nil)
	if withheld := r.ReprovideAll(context.Background()); withheld != 0 {
		t.Errorf("ReprovideAll reported %d withheld after recovery, want 0", withheld)
	}
	if len(dht.calls) != 2 {
		t.Errorf("Provide called %d times after recovery, want 2 (name + type CID)", len(dht.calls))
	}
}

// slowProbingService is a backendProber whose Probe is deadline-inspecting
// and context-controlled rather than timer-based: it records the deadline
// it was given, and for the timeout case blocks on ctx.Done() instead of
// sleeping a real duration. This keeps the tests below deterministic and
// free of real-time dependencies - no CI flakiness from scheduling jitter,
// no slow test suite from real sleeps - while still exercising the same
// behavior a real command-spawned backend with a slow cold-start would hit.
type slowProbingService struct {
	*fakeService
	shouldTimeout bool
	lastDeadline  time.Time
	hasDeadline   bool
}

func newSlowProbingSvc(name string) *slowProbingService {
	return &slowProbingService{
		fakeService: newFakeSvc(name, api.ServiceType_SERVICE_TYPE_MCP),
	}
}

func (p *slowProbingService) Probe(ctx context.Context) error {
	p.lastDeadline, p.hasDeadline = ctx.Deadline()
	if p.shouldTimeout {
		<-ctx.Done()
		return ctx.Err()
	}
	return nil
}

// The bug behind #376: defaultDHTProbeTimeout was a hard-coded 2s with no way to
// raise it, so a backend whose own cold-start cost alone exceeds that -
// measured in practice for moderately-featured MCP server stacks - could
// never be advertised on its first registration. NewServiceRegistry's
// backendProbeTimeout parameter (wired from --backend-probe-timeout) is the
// fix: the same slow backend must fail to advertise under the default and
// succeed once constructed with more time.
func TestServiceRegistry_BackendProbeTimeoutIsConfigurable(t *testing.T) {
	t.Run("default timeout is too short for a slow backend", func(t *testing.T) {
		dht := &fakeDHT{}
		r := NewServiceRegistry(dht, 10*time.Millisecond)

		svc := newSlowProbingSvc("slow")
		svc.shouldTimeout = true
		if err := r.Register(context.Background(), svc); err != nil {
			t.Fatalf("Register: %v", err)
		}
		if len(dht.calls) != 0 {
			t.Errorf("Provide called %d times for a backend slower than the probe timeout, want 0", len(dht.calls))
		}
	})

	t.Run("raising the timeout applies the configured duration to the probe context", func(t *testing.T) {
		dht := &fakeDHT{}
		timeout := 500 * time.Millisecond
		r := NewServiceRegistry(dht, timeout)

		svc := newSlowProbingSvc("slow")
		if err := r.Register(context.Background(), svc); err != nil {
			t.Fatalf("Register: %v", err)
		}
		if len(dht.calls) != 2 {
			t.Errorf("Provide called %d times once given enough time to probe, want 2 (name + type CID)", len(dht.calls))
		}
		if !svc.hasDeadline {
			t.Fatal("expected probe context to have a deadline")
		}
		remaining := time.Until(svc.lastDeadline)
		if remaining > timeout || remaining < timeout-100*time.Millisecond {
			t.Errorf("expected probe deadline to be close to %v, got remaining %v", timeout, remaining)
		}
	})

	t.Run("zero or negative backendProbeTimeout falls back to defaultDHTProbeTimeout", func(t *testing.T) {
		for _, d := range []time.Duration{0, -1 * time.Second} {
			r := NewServiceRegistry(&fakeDHT{}, d)
			if got := r.backendProbeTimeout; got != defaultDHTProbeTimeout {
				t.Errorf("NewServiceRegistry(dht, %v).backendProbeTimeout = %v, want %v", d, got, defaultDHTProbeTimeout)
			}
		}
	})
}

func TestServiceRegistry_RegisterRejectsDuplicateNameWithoutDisplacing(t *testing.T) {
	dht := &fakeDHT{}
	r := newServiceRegistryForTest(dht)

	first := newFakeSvc("shared", api.ServiceType_SERVICE_TYPE_MCP)
	if err := r.Register(context.Background(), first); err != nil {
		t.Fatalf("Register first: %v", err)
	}

	// A duplicate under the same name must be rejected — same type or not —
	// before its Init runs, and the live service must stay routable.
	for _, dup := range []*fakeService{
		newFakeSvc("shared", api.ServiceType_SERVICE_TYPE_MCP),
		newFakeSvc("shared", api.ServiceType_SERVICE_TYPE_A2A),
	} {
		if err := r.Register(context.Background(), dup); err == nil {
			t.Fatalf("Register duplicate %s: want error, got nil", dup.info.Type)
		}
		if dup.initCalls != 0 {
			t.Errorf("duplicate %s: Init called %d times, want 0", dup.info.Type, dup.initCalls)
		}
	}
	if first.teardownCalls != 0 {
		t.Errorf("existing service torn down %d times by rejected duplicates, want 0", first.teardownCalls)
	}
	got, ok := r.Get("shared")
	if !ok || got != Service(first) {
		t.Fatal("existing service displaced by rejected duplicate")
	}

	// After an explicit Unregister the name is free again.
	if err := r.Unregister(context.Background(), "shared"); err != nil {
		t.Fatalf("Unregister: %v", err)
	}
	replacement := newFakeSvc("shared", api.ServiceType_SERVICE_TYPE_A2A)
	if err := r.Register(context.Background(), replacement); err != nil {
		t.Fatalf("Register after Unregister: %v", err)
	}
}

func TestServiceRegistry_ConcurrentRegisterSameNameHasOneWinner(t *testing.T) {
	r := newServiceRegistryForTest(&fakeDHT{})

	const contenders = 8
	svcs := make([]*fakeService, contenders)
	errs := make([]error, contenders)
	var wg sync.WaitGroup
	for i := 0; i < contenders; i++ {
		i := i
		svcs[i] = newFakeSvc("contested", api.ServiceType_SERVICE_TYPE_MCP)
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = r.Register(context.Background(), svcs[i])
		}()
	}
	wg.Wait()

	winners := 0
	for i, err := range errs {
		if err == nil {
			winners++
			if got, ok := r.Get("contested"); !ok || got != Service(svcs[i]) {
				t.Errorf("winner %d is not the registered service", i)
			}
		} else if svcs[i].initCalls != 0 {
			t.Errorf("loser %d: Init called %d times, want 0", i, svcs[i].initCalls)
		}
	}
	if winners != 1 {
		t.Fatalf("got %d successful registrations for one name, want exactly 1", winners)
	}
}

func TestServiceRegistry_RegisterFailureFreesReservedName(t *testing.T) {
	r := newServiceRegistryForTest(&fakeDHT{})

	failing := newFakeSvc("retry", api.ServiceType_SERVICE_TYPE_MCP)
	failing.initErr = errors.New("init failed")
	if err := r.Register(context.Background(), failing); err == nil {
		t.Fatal("expected Init failure to fail Register")
	}

	// The failed attempt must not leave the name reserved forever.
	ok := newFakeSvc("retry", api.ServiceType_SERVICE_TYPE_MCP)
	if err := r.Register(context.Background(), ok); err != nil {
		t.Fatalf("Register after failed attempt: %v", err)
	}
}
