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

func TestFairSemAcquireAndRelease(t *testing.T) {
	s := newFairSem(2)
	r1, err := s.acquire(t.Context(), 0)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := s.acquire(t.Context(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if s.inflight() != 2 || s.capacity() != 2 {
		t.Fatalf("unexpected state: inflight=%d cap=%d", s.inflight(), s.capacity())
	}
	r1()
	r2()
	if s.inflight() != 0 {
		t.Fatalf("slots not released: inflight=%d", s.inflight())
	}
}

func TestFairSemQueueLimitRejectsImmediately(t *testing.T) {
	s := newFairSem(1)
	gate := make(chan struct{})
	t.Cleanup(func() { close(gate) })
	held := make(chan struct{})
	go func() {
		rel, err := s.acquire(t.Context(), 0)
		if err != nil {
			return
		}
		close(held)
		<-gate
		rel()
	}()
	<-held

	_, err := s.acquire(t.Context(), 0)
	if me, ok := errors.AsType[*Error](err); !ok || me.Reason != ReasonConcurrency {
		t.Fatalf("expected immediate concurrency rejection, got %v", err)
	}
	// With one queue slot, the next request waits.
	acquired := make(chan struct{})
	go func() {
		rel, err := s.acquire(t.Context(), 1)
		if err != nil {
			return
		}
		close(acquired)
		rel()
	}()
	waitUntil(t, func() bool { return s.queued() == 1 }, "waiter to queue")
}

func TestFairSemQueuedWaiterHonoursContext(t *testing.T) {
	s := newFairSem(1)
	gate := make(chan struct{})
	held := make(chan struct{})
	go func() {
		rel, _ := s.acquire(t.Context(), 5)
		close(held)
		<-gate
		rel()
	}()
	<-held

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	_, err := s.acquire(ctx, 5)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline while queued, got %v", err)
	}
	waitUntil(t, func() bool { return s.queued() == 0 }, "abandoned waiter to be removed")
	close(gate)
}

func TestFairSemResizeWakesWaiters(t *testing.T) {
	s := newFairSem(1)
	gate := make(chan struct{})
	held := make(chan struct{})
	go func() {
		rel, _ := s.acquire(t.Context(), 5)
		close(held)
		<-gate
		rel()
	}()
	<-held

	var wg sync.WaitGroup
	got := make(chan struct{}, 2)
	for range 2 {
		wg.Go(func() {
			rel, err := s.acquire(t.Context(), 5)
			if err != nil {
				return
			}
			got <- struct{}{}
			rel()
		})
	}
	waitUntil(t, func() bool { return s.queued() == 2 }, "waiters to queue")
	s.resize(3) // two free slots appear immediately
	for range 2 {
		select {
		case <-got:
		case <-time.After(time.Second):
			t.Fatal("resize did not wake queued waiters")
		}
	}
	wg.Wait()
	close(gate)
}

func TestFairSemShrinkDoesNotInterruptHolders(t *testing.T) {
	s := newFairSem(2)
	r1, _ := s.acquire(t.Context(), 0)
	r2, _ := s.acquire(t.Context(), 0)
	s.resize(1)
	if s.capacity() != 1 || s.inflight() != 2 {
		t.Fatalf("shrink state wrong: cap=%d inflight=%d", s.capacity(), s.inflight())
	}
	r1()
	r2()
	if s.inflight() != 0 {
		t.Fatal("releases after shrink did not complete")
	}
	// Now only one slot is available.
	r3, err := s.acquire(t.Context(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.acquire(t.Context(), 0); !AsError(err, ReasonConcurrency) {
		t.Fatalf("shrunken semaphore still admits over capacity: %v", err)
	}
	r3()
}
