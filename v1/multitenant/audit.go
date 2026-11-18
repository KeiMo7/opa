// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package multitenant

import (
	"context"
	"sync"
	"time"
)

// AuditRecord is one tenant-scoped audit entry. It deliberately contains no
// policy text, no input document and no decision result: only locator fields
// that let an operator reconstruct what ran and why it ended, without
// exposing tenant sensitive data.
type AuditRecord struct {
	// TenantID is the owning tenant.
	TenantID string `json:"tenant_id"`

	// DecisionID uniquely identifies the evaluation request. It matches the
	// decision ID exposed in evaluation results/decision logs.
	DecisionID string `json:"decision_id"`

	// RequestID is the caller-supplied request correlation ID (e.g. HTTP
	// X-Request-Id). Empty when absent.
	RequestID string `json:"request_id,omitempty"`

	// Package identifies the policy package / decision path that was
	// evaluated (e.g. "app/authz/allow"). It is a path, not module contents.
	Package string `json:"package,omitempty"`

	// StartedAt is when the evaluation entered the tenant queue.
	StartedAt time.Time `json:"started_at"`

	// EndedAt is when the evaluation finished or was aborted.
	EndedAt time.Time `json:"ended_at"`

	// QueueDelay is how long the request waited before acquiring a slot.
	QueueDelay time.Duration `json:"queue_delay_ns"`

	// Duration is the actual evaluation time.
	Duration time.Duration `json:"duration_ns"`

	// Outcome is "ok", "engine_error", or one of the [Reason] values for
	// quota failures.
	Outcome string `json:"outcome"`

	// HeapGrowthBytes is the sampled heap growth observed during the
	// evaluation. Best-effort; -1 when the memory guard is disabled.
	HeapGrowthBytes int64 `json:"heap_growth_bytes"`

	// ErrorMessage carries non-sensitive error text. Sensitive data never
	// reaches this field: evaluation errors are reduced to their code/message
	// without input or policy contents.
	ErrorMessage string `json:"error_message,omitempty"`
}

// Sink consumes audit records. Implementations must be safe for concurrent
// use. Write failures are handled by the [asyncSink] wrapper: the evaluation
// path never blocks on, or fails because of, a sink error.
type Sink interface {
	Write(ctx context.Context, rec AuditRecord) error
}

// SinkFunc adapts a function to a [Sink].
type SinkFunc func(ctx context.Context, rec AuditRecord) error

// Write implements [Sink].
func (f SinkFunc) Write(ctx context.Context, rec AuditRecord) error {
	return f(ctx, rec)
}

// QueryableSink is implemented by sinks that support tenant-scoped retrieval.
type QueryableSink interface {
	Sink
	// Records returns a copy of the records stored for tenantID, newest last.
	Records(tenantID string) []AuditRecord
}

// asyncSink decouples the evaluation path from sink availability. Records go
// into a bounded per-manager buffer; a single drain goroutine forwards them
// in order to the wrapped sink. When the underlying sink fails, records are
// retried with backoff rather than dropped; when the buffer is full the
// record is retained in an overflow ring so it can be flushed later, and the
// evaluation still returns.
type asyncSink struct {
	inner    Sink
	buffer   chan AuditRecord
	overflow *ringBuffer
	stopCh   chan struct{}
	doneCh   chan struct{}

	retryBase time.Duration
	retryMax  time.Duration

	enqueued atomicCounter
	dropped  atomicCounter
}

type asyncSinkOpts struct {
	bufferSize int
	retryBase  time.Duration
	retryMax   time.Duration
}

func newAsyncSink(inner Sink, opts asyncSinkOpts) *asyncSink {
	if opts.bufferSize <= 0 {
		opts.bufferSize = 1024
	}
	if opts.retryBase <= 0 {
		opts.retryBase = 50 * time.Millisecond
	}
	if opts.retryMax <= 0 {
		opts.retryMax = 10 * time.Second
	}
	as := &asyncSink{
		inner:     inner,
		buffer:    make(chan AuditRecord, opts.bufferSize),
		overflow:  newRingBuffer(opts.bufferSize),
		stopCh:    make(chan struct{}),
		doneCh:    make(chan struct{}),
		retryBase: opts.retryBase,
		retryMax:  opts.retryMax,
	}
	go as.drain()
	return as
}

// Write never blocks the evaluation path: it either enqueues immediately or,
// when the buffer is full, parks the record in the overflow ring.
func (as *asyncSink) Write(_ context.Context, rec AuditRecord) error {
	select {
	case as.buffer <- rec:
		as.enqueued.inc()
	default:
		// Buffer full (sink down or slow): keep the record for later instead
		// of dropping it. Overflow evicts the oldest record only when its ring
		// is also full, and accounts for it in the dropped counter.
		if evicted := as.overflow.push(rec); evicted {
			as.dropped.inc()
		}
	}
	return nil
}

func (as *asyncSink) drain() {
	defer close(as.doneCh)
	for {
		select {
		case <-as.stopCh:
			as.flushOnShutdown()
			return
		case rec := <-as.buffer:
			if err := as.writeWithRetry(rec); err != nil {
				// Sink still failing after shutdown was requested while
				// retrying; stop.
				return
			}
			as.drainOverflow()
		}
	}
}

// flushOnShutdown makes a single best-effort pass over the buffered and
// overflow records, so a clean shutdown with a healthy sink loses nothing.
// Records that still cannot be written are left in the buffers; a durable
// sink implementation is expected to persist across restarts itself.
func (as *asyncSink) flushOnShutdown() {
	for {
		select {
		case rec := <-as.buffer:
			if err := as.inner.Write(context.Background(), rec); err != nil {
				// Put it back into the overflow ring for any later flush.
				as.overflow.push(rec)
			}
		default:
			goto overflow
		}
	}
overflow:
	for {
		rec, ok := as.overflow.pop()
		if !ok {
			return
		}
		if err := as.inner.Write(context.Background(), rec); err != nil {
			as.overflow.unpop(rec)
			return
		}
	}
}

// drainOverflow forwards any records parked during a sink outage, oldest
// first, so ordering is preserved.
func (as *asyncSink) drainOverflow() {
	for {
		rec, ok := as.overflow.pop()
		if !ok {
			return
		}
		if err := as.writeWithRetry(rec); err != nil {
			// Put it back at the head on shutdown.
			as.overflow.unpop(rec)
			return
		}
	}
}

func (as *asyncSink) writeWithRetry(rec AuditRecord) error {
	backoff := as.retryBase
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := as.inner.Write(ctx, rec)
		cancel()
		if err == nil {
			return nil
		}
		select {
		case <-as.stopCh:
			return err
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > as.retryMax {
			backoff = as.retryMax
		}
	}
}

func (as *asyncSink) close() {
	close(as.stopCh)
	<-as.doneCh
}

// stats returns total enqueued and dropped record counts (dropped > 0 only
// when both buffer and overflow ring were full during a sink outage).
func (as *asyncSink) stats() (enqueued, dropped int64) {
	return as.enqueued.get(), as.dropped.get()
}

// ringBuffer is a fixed-size FIFO with oldest-eviction.
type ringBuffer struct {
	mu   sync.Mutex
	recs []AuditRecord
	cap_ int
}

func newRingBuffer(capacity int) *ringBuffer {
	if capacity < 1 {
		capacity = 1
	}
	return &ringBuffer{cap_: capacity}
}

// push appends rec, evicting the oldest record when full. It reports whether
// an eviction happened.
func (r *ringBuffer) push(rec AuditRecord) (evicted bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.recs) >= r.cap_ {
		r.recs = r.recs[1:]
		evicted = true
	}
	r.recs = append(r.recs, rec)
	return evicted
}

func (r *ringBuffer) pop() (AuditRecord, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.recs) == 0 {
		return AuditRecord{}, false
	}
	rec := r.recs[0]
	r.recs = r.recs[1:]
	return rec, true
}

func (r *ringBuffer) unpop(rec AuditRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recs = append([]AuditRecord{rec}, r.recs...)
}

// memorySink stores records in memory, indexed by tenant. It is safe for
// concurrent use and implements [QueryableSink].
type memorySink struct {
	mu      sync.Mutex
	records map[string][]AuditRecord
}

// NewMemorySink returns a [QueryableSink] that keeps records in process
// memory. It is intended for tests and for deployments that plug in their own
// durable [Sink] for production.
func NewMemorySink() QueryableSink {
	return &memorySink{records: map[string][]AuditRecord{}}
}

func (m *memorySink) Write(_ context.Context, rec AuditRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records[rec.TenantID] = append(m.records[rec.TenantID], rec)
	return nil
}

func (m *memorySink) Records(tenantID string) []AuditRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	src := m.records[tenantID]
	out := make([]AuditRecord, len(src))
	copy(out, src)
	return out
}
