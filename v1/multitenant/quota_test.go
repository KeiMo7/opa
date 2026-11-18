// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package multitenant

import (
	"testing"
	"time"
)

func TestFillQuotaDefaultsAndValidation(t *testing.T) {
	d := Quota{MaxConcurrent: 3, EvalTimeout: time.Second, MemoryLimitBytes: 1024, MaxQueued: 2, QueueTimeout: 50 * time.Millisecond}
	got, err := fillQuota(Quota{MaxConcurrent: 7, EvalTimeout: 2 * time.Second}, d)
	if err != nil {
		t.Fatal(err)
	}
	if got.MaxConcurrent != 7 || got.EvalTimeout != 2*time.Second {
		t.Fatalf("explicit fields were overwritten: %+v", got)
	}
	// Zero values with documented semantics survive fillQuota.
	if got.MemoryLimitBytes != 0 || got.MaxQueued != 0 || got.QueueTimeout != 0 {
		t.Fatalf("meaningful zero fields were overwritten by defaults: %+v", got)
	}
	// Only concurrency and timeout are taken from defaults when unset.
	got, err = fillQuota(Quota{}, d)
	if err != nil {
		t.Fatal(err)
	}
	if got.MaxConcurrent != 3 || got.EvalTimeout != time.Second {
		t.Fatalf("required fields were not defaulted: %+v", got)
	}

	if _, err := fillQuota(Quota{}, Quota{}); err == nil {
		t.Fatal("expected validation error when defaults lack concurrency and timeout")
	}
	if _, err := fillQuota(Quota{MaxConcurrent: 1}, Quota{EvalTimeout: time.Second}); err != nil {
		t.Fatalf("valid quota rejected: %v", err)
	}
}

func TestMemGuardTriggersOnGrowth(t *testing.T) {
	base := memSnapshot{heapAlloc: 1000, heapIncr: 0}
	g := newMemGuard(500, base)
	if g.exceeded(base) {
		t.Fatal("guard tripped at baseline")
	}
	if g.exceeded(memSnapshot{heapAlloc: 1400, heapIncr: 400}) {
		t.Fatal("guard tripped below the limit")
	}
	if !g.exceeded(memSnapshot{heapAlloc: 1600, heapIncr: 600}) {
		t.Fatal("guard did not trip past the limit")
	}
	// Disabled guard never trips.
	off := newMemGuard(0, base)
	if off.exceeded(memSnapshot{heapAlloc: 1_000_000, heapIncr: 999_000}) {
		t.Fatal("disabled guard tripped")
	}
}

func TestManagerCloseIsIdempotentAndStopsWatchdog(t *testing.T) {
	m := newTestManager(t, Config{Defaults: testDefaults()})
	m.Close()
	m.Close() // must not panic
	if _, err := m.Eval(t.Context(), "A", EvalRequest{Package: "p", Fn: quickFn}); !AsError(err, ReasonStopped) {
		t.Fatalf("expected ReasonStopped after Close, got %v", err)
	}
}
