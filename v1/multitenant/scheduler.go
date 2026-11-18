// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package multitenant

import (
	"context"
	"sync"
)

// fairSem is a resizable weighted semaphore with FIFO waiters. Unlike a
// buffered channel its capacity can change at runtime: growing takes effect
// immediately, shrinking takes effect as outstanding acquisitions are
// released. Waiters are woken in arrival order, so one tenant's requests
// cannot overtake another request of the same tenant.
type fairSem struct {
	mu    sync.Mutex
	size  int
	inUse int
	// waiters holds one unbuffered channel per queued acquirer. The head
	// waiter receives a token on release; closed channels mark abandoned
	// waiters whose context expired while queued.
	waiters []*waiter
}

type waiter struct {
	ch     chan struct{}
	closed bool
}

func newFairSem(size int) *fairSem {
	if size < 1 {
		size = 1
	}
	return &fairSem{size: size}
}

// tryAcquire takes a slot without queueing. It reports whether a slot was
// acquired.
func (s *fairSem) tryAcquire() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.waiters) == 0 && s.inUse < s.size {
		s.inUse++
		return true
	}
	return false
}

// acquire queues for a slot, honoring FIFO order. The returned release
// function must be called exactly once on success. queueLimit bounds the
// number of waiters; acquiring with a full queue returns an Error with
// ReasonConcurrency.
func (s *fairSem) acquire(ctx context.Context, queueLimit int) (func(), error) {
	if w := s.tryAcquire(); w {
		return s.release, nil
	}

	s.mu.Lock()
	if queueLimit >= 0 && len(s.waiters) >= queueLimit {
		s.mu.Unlock()
		return nil, &Error{Reason: ReasonConcurrency, Message: "tenant queue is full"}
	}
	w := &waiter{ch: make(chan struct{})}
	s.waiters = append(s.waiters, w)
	s.mu.Unlock()

	var ctxDone <-chan struct{}
	if ctx != nil {
		ctxDone = ctx.Done()
	}
	select {
	case <-w.ch:
		return s.release, nil
	case <-ctxDone:
		s.abandon(w)
		return nil, ctx.Err()
	}
}

// abandon removes a waiter that gave up (context/queue deadline). If it had
// already been handed a token it is released immediately instead.
func (s *fairSem) abandon(w *waiter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if w.closed {
		// Token was handed over before the context fired; release it.
		s.releaseLocked()
		return
	}
	for i, cand := range s.waiters {
		if cand == w {
			s.waiters = append(s.waiters[:i], s.waiters[i+1:]...)
			return
		}
	}
}

// resize changes the capacity. A shrink below current inUse completes
// naturally: no running evaluation is interrupted, new acquisitions wait
// until inUse drops below the new size.
func (s *fairSem) resize(size int) {
	if size < 1 {
		size = 1
	}
	s.mu.Lock()
	old := s.size
	s.size = size
	s.mu.Unlock()
	if size > old {
		s.pump()
	}
}

// pump hands free slots to queued waiters. Called after resize and release.
func (s *fairSem) pump() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for s.inUse < s.size {
		w := s.popWaiter()
		if w == nil {
			return
		}
		s.inUse++
		w.closed = true
		close(w.ch)
	}
}

func (s *fairSem) popWaiter() *waiter {
	for len(s.waiters) > 0 {
		w := s.waiters[0]
		s.waiters = s.waiters[1:]
		if w.closed {
			continue
		}
		return w
	}
	return nil
}

func (s *fairSem) release() {
	s.mu.Lock()
	s.releaseLocked()
	s.mu.Unlock()
	s.pump()
}

// releaseLocked frees one slot. It is also used when a waiter that already
// held a token abandons it.
func (s *fairSem) releaseLocked() {
	if s.inUse > 0 {
		s.inUse--
	}
}

// inflight reports the number of currently held slots.
func (s *fairSem) inflight() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inUse
}

// queued reports the number of requests waiting for a slot.
func (s *fairSem) queued() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.waiters)
}

// capacity reports the configured slot count.
func (s *fairSem) capacity() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.size
}
