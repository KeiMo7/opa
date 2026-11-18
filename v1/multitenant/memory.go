// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package multitenant

import (
	"runtime"
	"sync/atomic"
	"time"
)

// memSampler caches runtime heap stats so the per-evaluation memory guard does
// not pay for a stop-the-world runtime.ReadMemStats call itself. A single
// background goroutine owned by the Manager refreshes the snapshot at a fixed
// cadence; evaluations read an atomic pointer.
type memSampler struct {
	snapshot atomic.Pointer[memSnapshot]
	stop     chan struct{}
	done     chan struct{}
	interval time.Duration
}

type memSnapshot struct {
	// heapAlloc is bytes of allocated heap objects still in use.
	heapAlloc uint64
	// heapIncr is HeapAlloc relative to the sampler's first observation; it
	// grows and shrinks with GC and gives guards a monotonic-ish growth signal
	// that is less noisy than absolute HeapAlloc after repeated GCs.
	heapIncr int64
}

func newMemSampler(interval time.Duration) *memSampler {
	if interval <= 0 {
		interval = 10 * time.Millisecond
	}
	ms := &memSampler{
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
		interval: interval,
	}
	var ms0 runtime.MemStats
	runtime.ReadMemStats(&ms0)
	ms.snapshot.Store(&memSnapshot{heapAlloc: ms0.HeapAlloc, heapIncr: 0})
	go ms.loop(ms0.HeapAlloc)
	return ms
}

func (ms *memSampler) loop(base uint64) {
	defer close(ms.done)
	t := time.NewTicker(ms.interval)
	defer t.Stop()
	for {
		select {
		case <-ms.stop:
			return
		case <-t.C:
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			incr := max(int64(m.HeapAlloc)-int64(base), 0)
			ms.snapshot.Store(&memSnapshot{heapAlloc: m.HeapAlloc, heapIncr: incr})
		}
	}
}

func (ms *memSampler) current() memSnapshot {
	return *ms.snapshot.Load()
}

func (ms *memSampler) stopSampler() {
	close(ms.stop)
	<-ms.done
}

// memGuard tracks one evaluation's heap growth. The evaluation is considered
// over its memory quota when the sampled heap-in-use has grown by more than
// limitBytes relative to the snapshot taken when the evaluation started.
//
// Attribution note: HeapAlloc is process-wide, so in a multi-tenant process
// the delta includes allocations made by other goroutines between samples.
// The scheduler bounds how many evaluations run concurrently, and the check
// errs towards cancelling the evaluation that crosses the threshold first;
// this is documented as a cooperative guard, not a hard boundary.
type memGuard struct {
	limit      int64
	startIncr  int64
	startAlloc uint64
}

func newMemGuard(limit int64, s memSnapshot) memGuard {
	return memGuard{limit: limit, startIncr: s.heapIncr, startAlloc: s.heapAlloc}
}

// exceeded reports whether the current snapshot shows heap growth past the
// guard's quota.
func (g memGuard) exceeded(s memSnapshot) bool {
	if g.limit <= 0 {
		return false
	}
	// Prefer the growth counter; fall back to absolute delta when GC has
	// recycled the baseline (heapIncr reset toward zero relative to start).
	growth := s.heapIncr - g.startIncr
	if growth < 0 {
		growth = int64(s.heapAlloc) - int64(g.startAlloc)
	}
	return growth > g.limit
}
