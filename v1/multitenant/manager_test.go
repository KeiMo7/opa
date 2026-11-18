// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package multitenant

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestConcurrencyLimitIsTenantScoped(t *testing.T) {
	m := newTestManager(t, Config{Defaults: testDefaults()})
	ctx := t.Context()
	if err := m.RegisterTenant(ctx, "A", Quota{MaxConcurrent: 1, MaxQueued: 0, EvalTimeout: time.Second}); err != nil {
		t.Fatal(err)
	}
	if err := m.RegisterTenant(ctx, "B", Quota{MaxConcurrent: 2, MaxQueued: 0, EvalTimeout: time.Second}); err != nil {
		t.Fatal(err)
	}

	gateA := make(chan struct{})
	t.Cleanup(func() { close(gateA) })
	startedA := make(chan struct{})
	go func() {
		_, _ = m.Eval(ctx, "A", EvalRequest{
			Package: "a/block",
			Fn: func(c context.Context) (any, error) {
				close(startedA)
				return blockFn(gateA)(c)
			},
		})
	}()
	<-startedA

	// A is saturated: a second A request is rejected immediately with the
	// concurrency reason rather than queued (MaxQueued == 0).
	if _, err := m.Eval(ctx, "A", EvalRequest{Package: "a/x", Fn: quickFn}); !AsError(err, ReasonConcurrency) {
		t.Fatalf("expected ReasonConcurrency for saturated tenant, got %v", err)
	}

	// B's slots are independent: two concurrent B evaluations both run.
	gateB := make(chan struct{})
	var wg sync.WaitGroup
	bErrs := make(chan error, 2)
	for range 2 {
		wg.Go(func() {
			_, err := m.Eval(ctx, "B", EvalRequest{Package: "b/block", Fn: blockFn(gateB)})
			bErrs <- err
		})
	}
	waitUntil(t, func() bool {
		st, _ := m.Stats("B")
		return st.InFlight == 2
	}, "B evaluations to start")
	close(gateB)
	wg.Wait()
	for range 2 {
		if err := <-bErrs; err != nil {
			t.Fatalf("B evaluation failed while A was saturated: %v", err)
		}
	}
}

func TestTimeoutDoesNotAffectOtherTenantsOrLaterRequests(t *testing.T) {
	cfg := Config{
		Defaults: testDefaults(),
	}
	m := newTestManager(t, cfg)
	ctx := t.Context()
	// Tight timeout for A, generous for B.
	if err := m.RegisterTenant(ctx, "A", Quota{MaxConcurrent: 2, EvalTimeout: 80 * time.Millisecond, MaxQueued: 0}); err != nil {
		t.Fatal(err)
	}
	if err := m.RegisterTenant(ctx, "B", Quota{MaxConcurrent: 2, EvalTimeout: 5 * time.Second, MaxQueued: 0}); err != nil {
		t.Fatal(err)
	}

	gate := make(chan struct{}) // never released: A must be aborted by its deadline
	started := make(chan struct{})
	aDone := make(chan error, 1)
	go func() {
		_, err := m.Eval(ctx, "A", EvalRequest{
			Package: "a/slow",
			Fn: func(c context.Context) (any, error) {
				close(started)
				return blockFn(gate)(c)
			},
		})
		aDone <- err
	}()
	<-started

	// While A is stuck, B evaluates normally.
	res, err := m.Eval(ctx, "B", EvalRequest{Package: "b/fast", Fn: quickFn})
	if err != nil {
		t.Fatalf("B must not be affected by A's slow evaluation: %v", err)
	}
	if res.Result != "ok" {
		t.Fatalf("unexpected B result: %v", res.Result)
	}

	// A hits its own deadline.
	select {
	case err := <-aDone:
		if !AsError(err, ReasonTimeout) {
			t.Fatalf("expected ReasonTimeout for A, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("A evaluation was not aborted by its timeout")
	}

	// A must not be blacklisted: later requests from A run normally.
	res, err = m.Eval(ctx, "A", EvalRequest{Package: "a/fast", Fn: quickFn})
	if err != nil {
		t.Fatalf("A must serve requests after a timeout, got %v", err)
	}
	if res.Result != "ok" {
		t.Fatalf("unexpected A result after timeout: %v", res.Result)
	}

	st, _ := m.Stats("A")
	if st.Timeouts != 1 || st.Completed != 2 {
		t.Fatalf("unexpected A stats: %+v", st)
	}
	stB, _ := m.Stats("B")
	if stB.Timeouts != 0 || stB.Completed != 1 {
		t.Fatalf("unexpected B stats: %+v", stB)
	}
}

func TestQueueFIFOAndQueueTimeout(t *testing.T) {
	m := newTestManager(t, Config{Defaults: testDefaults()})
	ctx := t.Context()
	if err := m.RegisterTenant(ctx, "T", Quota{
		MaxConcurrent: 1, MaxQueued: 5, EvalTimeout: time.Second, QueueTimeout: 2 * time.Second,
	}); err != nil {
		t.Fatal(err)
	}

	headGate := make(chan struct{})
	headStarted := make(chan struct{})
	go func() {
		_, _ = m.Eval(ctx, "T", EvalRequest{Package: "p/0", Fn: func(c context.Context) (any, error) {
			close(headStarted)
			return blockFn(headGate)(c)
		}})
	}()
	<-headStarted

	// Two requests queue behind the head; launch them one at a time and wait
	// for each queue position, so enqueue order is deterministic regardless
	// of goroutine scheduling.
	var mu sync.Mutex
	var order []int
	var wg sync.WaitGroup
	launch := func(i int) {
		wg.Go(func() {
			_, _ = m.Eval(ctx, "T", EvalRequest{Package: "p/q", Fn: func(context.Context) (any, error) {
				mu.Lock()
				order = append(order, i)
				mu.Unlock()
				return "ok", nil
			}})
		})
	}
	launch(1)
	waitUntil(t, func() bool {
		st, _ := m.Stats("T")
		return st.Queued == 1
	}, "request 1 to queue")
	launch(2)
	waitUntil(t, func() bool {
		st, _ := m.Stats("T")
		return st.Queued == 2
	}, "request 2 to queue")

	// A third queued request whose own deadline expires while waiting.
	qtCtx, qtCancel := context.WithTimeout(ctx, 60*time.Millisecond)
	defer qtCancel()
	_, err := m.Eval(qtCtx, "T", EvalRequest{Package: "p/qt", Fn: quickFn})
	if !AsError(err, ReasonQueueTimeout) {
		t.Fatalf("expected ReasonQueueTimeout, got %v", err)
	}

	close(headGate)
	wg.Wait()
	mu.Lock()
	if len(order) != 2 || order[0] != 1 || order[1] != 2 {
		t.Fatalf("FIFO order violated, got %v", order)
	}
	mu.Unlock()
}

func TestGlobalFairnessPreventsStarvation(t *testing.T) {
	m := newTestManager(t, Config{
		Defaults:          testDefaults(),
		MaxConcurrentEval: 1,
	})
	ctx := t.Context()
	for _, id := range []string{"A", "B"} {
		if err := m.RegisterTenant(ctx, id, Quota{MaxConcurrent: 4, MaxQueued: 20, EvalTimeout: 5 * time.Second}); err != nil {
			t.Fatal(err)
		}
	}

	var wg sync.WaitGroup
	for _, id := range []string{"A", "B"} {
		for range 20 {
			wg.Go(func() {
				if _, err := m.Eval(ctx, id, EvalRequest{Package: "p", Fn: sleepFn(time.Millisecond)}); err != nil {
					t.Errorf("eval for %s failed: %v", id, err)
				}
			})
		}
	}
	wg.Wait()
	for _, id := range []string{"A", "B"} {
		st, ok := m.Stats(id)
		if !ok || st.Completed != 20 {
			t.Fatalf("tenant %s starved or under-served: %+v", id, st)
		}
	}
}

func TestQuotaProviderFailureDegradesToDefaults(t *testing.T) {
	provider := &failingProvider{bad: true}
	m := newTestManager(t, Config{Defaults: testDefaults(), Provider: provider})
	ctx := t.Context()

	// Lazy onboarding while the quota service is down: bounded by defaults,
	// marked degraded, never fails open.
	if _, err := m.Eval(ctx, "T", EvalRequest{Package: "p", Fn: quickFn}); err != nil {
		t.Fatalf("eval must succeed on defaults during provider outage: %v", err)
	}
	st, _ := m.Stats("T")
	if !st.Degraded {
		t.Fatal("tenant should be marked degraded after provider failure")
	}
	if st.Capacity != testDefaults().MaxConcurrent {
		t.Fatalf("expected default capacity %d, got %d", testDefaults().MaxConcurrent, st.Capacity)
	}

	// Explicit refresh during the outage reports the error but keeps serving.
	if err := m.RefreshQuota(ctx, "T"); err == nil {
		t.Fatal("expected provider error to surface from RefreshQuota")
	}
	if _, err := m.Eval(ctx, "T", EvalRequest{Package: "p", Fn: quickFn}); err != nil {
		t.Fatalf("tenant must stay usable during outage: %v", err)
	}

	// Recovery: refresh applies the provider quota and clears degraded.
	provider.setBad(false)
	if err := m.RefreshQuota(ctx, "T"); err != nil {
		t.Fatalf("refresh after recovery: %v", err)
	}
	if err := m.SetQuota(ctx, "T", Quota{MaxConcurrent: 3, EvalTimeout: time.Second}); err != nil {
		t.Fatal(err)
	}
	st, _ = m.Stats("T")
	if st.Capacity != 3 || st.Degraded {
		t.Fatalf("quota update did not apply: %+v", st)
	}
}

func TestUnknownTenantRejectedWhenRequired(t *testing.T) {
	m := newTestManager(t, Config{Defaults: testDefaults(), RequireRegisteredTenant: true})
	_, err := m.Eval(t.Context(), "ghost", EvalRequest{Package: "p", Fn: quickFn})
	if !AsError(err, ReasonUnknownTenant) {
		t.Fatalf("expected ReasonUnknownTenant, got %v", err)
	}
}

func TestStatsDimensionsAreIndependent(t *testing.T) {
	m := newTestManager(t, Config{Defaults: testDefaults()})
	ctx := t.Context()
	if err := m.RegisterTenant(ctx, "A", Quota{MaxConcurrent: 1, MaxQueued: 0, EvalTimeout: 60 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}

	gate := make(chan struct{})
	started := make(chan struct{})
	headErr := make(chan error, 1)
	go func() {
		_, err := m.Eval(ctx, "A", EvalRequest{Package: "p", Fn: func(c context.Context) (any, error) {
			close(started)
			return blockFn(gate)(c)
		}})
		headErr <- err
	}()
	<-started
	if _, err := m.Eval(ctx, "A", EvalRequest{Package: "p", Fn: quickFn}); !AsError(err, ReasonConcurrency) {
		t.Fatalf("expected concurrency rejection, got %v", err)
	}
	// Keep the head blocked so its own deadline fires: the three dimensions
	// (concurrency rejection, timeout, completion) must be counted separately.
	select {
	case err := <-headErr:
		if !AsError(err, ReasonTimeout) {
			t.Fatalf("expected head evaluation to time out, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("head evaluation did not time out")
	}
	close(gate) // release any lingering reference; head already returned

	st, _ := m.Stats("A")
	if st.Rejected != 1 {
		t.Fatalf("rejected counter wrong: %+v", st)
	}
	if st.Timeouts != 1 {
		t.Fatalf("timeout counter wrong: %+v", st)
	}
	if st.Started != 1 || st.Completed != 1 {
		t.Fatalf("concurrency counters wrong: %+v", st)
	}
}

func waitUntil(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
