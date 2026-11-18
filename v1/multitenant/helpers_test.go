// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package multitenant

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// testDefaults returns quotas tight enough for fast tests but loose enough
// not to flake under a loaded CI machine.
func testDefaults() Defaults {
	return Defaults{Quota: Quota{
		MaxConcurrent:    2,
		EvalTimeout:      2 * time.Second,
		MemoryLimitBytes: 64 << 20,
		MaxQueued:        4,
		QueueTimeout:     time.Second,
	}}
}

func newTestManager(t *testing.T, cfg Config) *Manager {
	t.Helper()
	if cfg.IDFactory == nil {
		cfg.IDFactory = testIDFactory()
	}
	if cfg.MemorySampleInterval == 0 {
		cfg.MemorySampleInterval = 10 * time.Millisecond
	}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(m.Close)
	return m
}

// idFactory hands out deterministic, process-unique decision IDs.
func testIDFactory() func() string {
	var n int64
	var mu sync.Mutex
	return func() string {
		mu.Lock()
		n++
		id := n
		mu.Unlock()
		return "dec-" + itoa(id)
	}
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// infiniteLoopModule enumerates a huge range until the evaluation context is
// cancelled. numbers.range itself is cancellation-aware and halts on the
// engine's cancel flag, and the every-expression check in the loop also runs
// on each iteration.
const infiniteLoopModule = `
package tenantloop

allow if {
	some x in numbers.range(0, 1000000000)
	x >= 0
}
`

// memoryHogModule builds a large array inside one rule. It is expected to be
// cancelled by the memory watchdog before completing.
const memoryHogModule = `
package tenantmem

allow if {
	xs := [x | some x in numbers.range(0, 200000000)]
	count(xs) > 0
}
`

// simpleModule is a well-behaved policy that returns immediately.
const simpleModule = `
package tenantgood

default allow := false

allow if {
	input.user == "alice"
}
`

// failingProvider returns err until the supplied gate is opened, letting tests
// simulate quota-service outages deterministically.
type failingProvider struct {
	mu   sync.Mutex
	bad  bool
	last string
}

func (p *failingProvider) Quota(_ context.Context, tenantID string) (Quota, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.last = tenantID
	if p.bad {
		return Quota{}, errors.New("quota service unavailable")
	}
	return Quota{}, nil
}

func (p *failingProvider) setBad(b bool) {
	p.mu.Lock()
	p.bad = b
	p.mu.Unlock()
}

// flakySink fails writes until fail is false and records every record it
// eventually accepts.
type flakySink struct {
	mu      sync.Mutex
	failing bool
	records []AuditRecord
}

func (s *flakySink) Write(_ context.Context, rec AuditRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failing {
		return errors.New("sink down")
	}
	s.records = append(s.records, rec)
	return nil
}

func (s *flakySink) setFailing(b bool) {
	s.mu.Lock()
	s.failing = b
	s.mu.Unlock()
}

func (s *flakySink) snapshot() []AuditRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]AuditRecord, len(s.records))
	copy(out, s.records)
	return out
}

// blockFn blocks until gate is closed, then returns. It honors ctx so an
// unexpected test failure cannot leak goroutines.
func blockFn(gate <-chan struct{}) func(context.Context) (any, error) {
	return func(ctx context.Context) (any, error) {
		select {
		case <-gate:
			return "done", nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func sleepFn(d time.Duration) func(context.Context) (any, error) {
	return func(ctx context.Context) (any, error) {
		select {
		case <-time.After(d):
			return "done", nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func quickFn(context.Context) (any, error) { return "ok", nil }
