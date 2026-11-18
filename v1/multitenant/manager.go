// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package multitenant

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Config configures a [Manager]. The zero value is not valid; use
// [NewManager] which applies defaults and validation.
type Config struct {
	// Defaults is the instance-wide fallback quota. Every tenant quota field
	// left zero is filled from here. Required.
	Defaults Defaults

	// Provider optionally fetches tenant quotas from an external quota
	// service. Provider failures degrade to Defaults rather than opening the
	// gate: evaluations always stay bounded.
	Provider QuotaProvider

	// Sink receives audit records. When nil an in-memory [QueryableSink] is
	// used. Writes are always asynchronous and never block evaluation.
	Sink Sink

	// RequireRegisteredTenant, when true, makes evaluations for unknown
	// tenant IDs fail with ReasonUnknownTenant. When false (default), unknown
	// tenants are onboarded lazily and served with Defaults (and a Provider
	// quota when configured).
	RequireRegisteredTenant bool

	// MaxConcurrentEval, when > 0, bounds the total number of evaluations
	// running across all tenants. Admission is FIFO so no tenant can starve
	// the shared pool indefinitely. 0 means no global cap.
	MaxConcurrentEval int

	// AuditBufferSize is the async audit buffer. Default 1024.
	AuditBufferSize int

	// MemorySampleInterval is how often the memory watchdog samples heap
	// growth of in-flight evaluations. Default 20ms.
	MemorySampleInterval time.Duration

	// EnableProcessMemoryLimit calls [debug.SetMemoryLimit] on Manager
	// construction (and restores the previous setting on Close). The runtime
	// then forces GC aggressively before the process reaches the limit,
	// giving the per-evaluation memory guards time to fire. Off by default so
	// unmanaged deployments keep their exact current runtime behaviour.
	EnableProcessMemoryLimit bool

	// ProcessMemoryLimitBytes is the soft process heap limit applied when
	// EnableProcessMemoryLimit is true. Required when the flag is set.
	ProcessMemoryLimitBytes int64

	// IDFactory generates decision IDs. Defaults to uuid.NewString; override
	// in tests for deterministic records.
	IDFactory func() string
}

// EvalRequest is one tenant evaluation.
type EvalRequest struct {
	// Package locates the policy package / decision path for the audit
	// record. It never contains module source.
	Package string

	// RequestID is an optional caller correlation ID.
	RequestID string

	// Fn performs the actual engine work. It MUST honour the context passed
	// to it: the manager cancels that context on timeout or memory-quota
	// breach. Fn must not retain the context or its values after returning.
	Fn func(ctx context.Context) (any, error)
}

// EvalResult is the manager's evaluation outcome.
type EvalResult struct {
	// DecisionID identifies the evaluation in audit records.
	DecisionID string
	// Result is whatever Fn returned, passed through untouched.
	Result any
}

// Manager owns tenant quotas, admission scheduling, the memory watchdog and
// audit forwarding. Its zero value is unusable; construct it with
// [NewManager].
type Manager struct {
	cfg       Config
	registry  *quotaRegistry
	sink      *asyncSink
	queryable QueryableSink // non-nil when the default in-memory sink is used
	mem       *memSampler

	mu      sync.Mutex
	tenants map[string]*tenantState

	globalSem *fairSem

	// activeEvals is guarded by activeMu; the single watchdog goroutine reads
	// it every sample interval.
	activeMu sync.Mutex
	active   map[string]*activeEval

	stopCh chan struct{}
	doneCh chan struct{}

	stopped atomicCounter
}

type tenantState struct {
	id       string
	mu       sync.RWMutex
	quota    Quota
	sem      *fairSem
	degraded atomicCounter // 1 when last provider refresh failed and defaults apply

	// stats: independent atomic dimensions so concurrency/time/memory
	// accounting can never share state.
	started        atomicCounter
	completed      atomicCounter
	timeouts       atomicCounter
	memoryAborts   atomicCounter
	rejected       atomicCounter
	queueTimeouts  atomicCounter
	engineErrors   atomicCounter
	queueDelaySum  atomicCounter // nanoseconds
	evalDurationNs atomicCounter
}

// TenantStats is a point-in-time snapshot of one tenant's counters.
type TenantStats struct {
	InFlight      int64
	Queued        int
	Capacity      int
	Started       int64
	Completed     int64
	Timeouts      int64
	MemoryAborts  int64
	Rejected      int64
	QueueTimeouts int64
	EngineErrors  int64
	QueueDelayAvg time.Duration
	EvalDuration  time.Duration
	Degraded      bool
}

type activeEval struct {
	tenantID   string
	decisionID string
	cancel     context.CancelFunc
	guard      memGuard
	startedAt  time.Time

	mu         sync.Mutex
	memTripped bool
}

func (a *activeEval) markMemory() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.memTripped {
		return false
	}
	a.memTripped = true
	return true
}

func (a *activeEval) memoryTripped() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.memTripped
}

// NewManager validates cfg and starts the background sampler and watchdog.
func NewManager(cfg Config) (*Manager, error) {
	defaults, err := fillQuota(cfg.Defaults.Quota, cfg.Defaults.Quota)
	if err != nil {
		return nil, err
	}
	cfg.Defaults.Quota = defaults
	if cfg.MemorySampleInterval <= 0 {
		cfg.MemorySampleInterval = 20 * time.Millisecond
	}
	if cfg.IDFactory == nil {
		cfg.IDFactory = uuid.NewString
	}
	var queryable QueryableSink
	sink := cfg.Sink
	if sink == nil {
		queryable = NewMemorySink()
		sink = queryable
	}
	if cfg.EnableProcessMemoryLimit {
		if cfg.ProcessMemoryLimitBytes <= 0 {
			return nil, errors.New("EnableProcessMemoryLimit requires ProcessMemoryLimitBytes > 0")
		}
		debug.SetMemoryLimit(cfg.ProcessMemoryLimitBytes)
	}
	m := &Manager{
		cfg:       cfg,
		registry:  newQuotaRegistry(),
		tenants:   map[string]*tenantState{},
		active:    map[string]*activeEval{},
		stopCh:    make(chan struct{}),
		doneCh:    make(chan struct{}),
		queryable: queryable,
	}
	if cfg.MaxConcurrentEval > 0 {
		m.globalSem = newFairSem(cfg.MaxConcurrentEval)
	}
	m.sink = newAsyncSink(sink, asyncSinkOpts{bufferSize: cfg.AuditBufferSize})
	m.mem = newMemSampler(cfg.MemorySampleInterval / 2)
	go m.watchdog()
	return m, nil
}

// Close stops background work. In-flight evaluations are not killed by
// Close: callers should let them finish or cancel their parent contexts.
// Safe to call once.
func (m *Manager) Close() {
	if m.stopped.get() != 0 {
		return
	}
	m.stopped.inc()
	close(m.stopCh)
	<-m.doneCh
	m.mem.stopSampler()
	m.sink.close()
	if m.cfg.EnableProcessMemoryLimit {
		debug.SetMemoryLimit(-1) // restore Go default (no soft limit)
	}
}

// RegisterTenant creates or updates a tenant with an explicit quota. Zero
// fields of q are filled from the instance defaults.
func (m *Manager) RegisterTenant(_ context.Context, tenantID string, q Quota) error {
	if tenantID == "" {
		return errors.New("tenant id must not be empty")
	}
	filled, err := fillQuota(q, m.cfg.Defaults.Quota)
	if err != nil {
		return err
	}
	m.registry.put(tenantID, filled, true)
	m.getOrCreateTenant(tenantID, filled)
	return nil
}

// RemoveTenant removes a tenant. Its in-flight evaluations run to completion
// using the quota they started with; subsequent requests fail with
// ReasonUnknownTenant.
func (m *Manager) RemoveTenant(tenantID string) {
	m.registry.delete(tenantID)
	m.mu.Lock()
	delete(m.tenants, tenantID)
	m.mu.Unlock()
}

// TenantIDs returns the currently registered tenant IDs.
func (m *Manager) TenantIDs() []string {
	return m.registry.ids()
}

// SetQuota replaces a tenant's quota at runtime. The new concurrency limit
// applies to waiting and future requests immediately; running evaluations
// keep their original deadline and memory guard.
func (m *Manager) SetQuota(_ context.Context, tenantID string, q Quota) error {
	filled, err := fillQuota(q, m.cfg.Defaults.Quota)
	if err != nil {
		return err
	}
	m.registry.put(tenantID, filled, true)
	t, ok := m.lookupTenant(tenantID)
	if !ok {
		m.getOrCreateTenant(tenantID, filled)
		return nil
	}
	t.applyQuota(filled)
	return nil
}

// RefreshQuota re-fetches the tenant quota from the configured provider. On
// provider failure the tenant keeps serving with its previous quota (or the
// instance defaults on first failure): a quota-service outage never removes
// the bounds. Returns the provider error for observability, while the tenant
// remains usable.
func (m *Manager) RefreshQuota(ctx context.Context, tenantID string) error {
	if m.cfg.Provider == nil {
		return errors.New("no quota provider configured")
	}
	q, err := m.cfg.Provider.Quota(ctx, tenantID)
	if err != nil {
		if t, ok := m.lookupTenant(tenantID); ok {
			t.degraded.inc()
		}
		return fmt.Errorf("quota provider unavailable, retaining existing quota: %w", err)
	}
	filled, ferr := fillQuota(q, m.cfg.Defaults.Quota)
	if ferr != nil {
		return ferr
	}
	m.registry.put(tenantID, filled, true)
	t, ok := m.lookupTenant(tenantID)
	if !ok {
		t = m.getOrCreateTenant(tenantID, filled)
	} else {
		t.applyQuota(filled)
	}
	t.degraded.add(-t.degraded.get()) // clear degraded flag
	return nil
}

// Stats returns a snapshot of the tenant's counters.
func (m *Manager) Stats(tenantID string) (TenantStats, bool) {
	t, ok := m.lookupTenant(tenantID)
	if !ok {
		return TenantStats{}, false
	}
	started := t.started.get()
	completed := t.completed.get()
	avg := time.Duration(0)
	if completed > 0 {
		avg = time.Duration(t.queueDelaySum.get() / completed)
	}
	return TenantStats{
		InFlight:      started - completed,
		Queued:        t.sem.queued(),
		Capacity:      t.sem.capacity(),
		Started:       started,
		Completed:     completed,
		Timeouts:      t.timeouts.get(),
		MemoryAborts:  t.memoryAborts.get(),
		Rejected:      t.rejected.get(),
		QueueTimeouts: t.queueTimeouts.get(),
		EngineErrors:  t.engineErrors.get(),
		QueueDelayAvg: avg,
		EvalDuration:  time.Duration(t.evalDurationNs.get()),
		Degraded:      t.degraded.get() > 0,
	}, true
}

// AuditRecords returns audit records for a tenant. It works with the default
// in-memory sink; custom sinks implementing [QueryableSink] are supported too.
func (m *Manager) AuditRecords(tenantID string) ([]AuditRecord, error) {
	if m.queryable != nil {
		return m.queryable.Records(tenantID), nil
	}
	if qs, ok := m.cfg.Sink.(QueryableSink); ok {
		return qs.Records(tenantID), nil
	}
	return nil, errors.New("configured audit sink does not support retrieval")
}

// AuditEnqueued / AuditDropped expose async-sink health for operators.
func (m *Manager) AuditHealth() (enqueued, dropped int64) {
	return m.sink.stats()
}

func (m *Manager) lookupTenant(id string) (*tenantState, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tenants[id]
	return t, ok
}

func (m *Manager) getOrCreateTenant(id string, q Quota) *tenantState {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t, ok := m.tenants[id]; ok {
		return t
	}
	t := &tenantState{id: id, quota: q, sem: newFairSem(q.MaxConcurrent)}
	m.tenants[id] = t
	return t
}

// resolveTenant returns the tenant state, onboarding lazily according to
// configuration. Onboarding with a failing provider degrades to defaults.
func (m *Manager) resolveTenant(ctx context.Context, id string) (*tenantState, error) {
	if m.stopped.get() != 0 {
		return nil, &Error{TenantID: id, Reason: ReasonStopped, Message: "manager is stopped"}
	}
	if t, ok := m.lookupTenant(id); ok {
		return t, nil
	}
	entry, known := m.registry.get(id)
	var q Quota
	if known {
		q = entry.quota
	} else {
		if m.cfg.RequireRegisteredTenant {
			return nil, &Error{TenantID: id, Reason: ReasonUnknownTenant, Message: "tenant is not registered"}
		}
		q = m.cfg.Defaults.Quota
		if m.cfg.Provider != nil {
			if pq, perr := m.cfg.Provider.Quota(ctx, id); perr == nil {
				if filled, ferr := fillQuota(pq, m.cfg.Defaults.Quota); ferr == nil {
					q = filled
				}
			}
			// On any provider failure (or invalid provider payload) the
			// tenant is onboarded on the instance defaults and marked
			// degraded: bounded service continues instead of failing open.
		}
	}
	t := m.getOrCreateTenant(id, q)
	if !known && m.cfg.Provider != nil && q == m.cfg.Defaults.Quota {
		t.degraded.inc()
	}
	return t, nil
}

func (t *tenantState) applyQuota(q Quota) {
	t.mu.Lock()
	t.quota = q
	t.mu.Unlock()
	t.sem.resize(q.MaxConcurrent)
}

func (t *tenantState) currentQuota() Quota {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.quota
}

// Eval runs req under the tenant's quota. The returned error is either
//   - *[Error] for quota/admission failures,
//   - the engine error returned by req.Fn for evaluation failures.
//
// Every attempt, including admission rejections, produces an audit record.
func (m *Manager) Eval(ctx context.Context, tenantID string, req EvalRequest) (EvalResult, error) {
	t, err := m.resolveTenant(ctx, tenantID)
	if err != nil {
		// Unknown tenant / stopped manager: record what we can without a
		// runtime, then fail.
		m.audit(AuditRecord{
			TenantID:        tenantID,
			DecisionID:      m.cfg.IDFactory(),
			RequestID:       req.RequestID,
			Package:         req.Package,
			StartedAt:       time.Now(),
			EndedAt:         time.Now(),
			Outcome:         string(ReasonUnknownTenant),
			ErrorMessage:    err.Error(),
			HeapGrowthBytes: -1,
		})
		return EvalResult{}, err
	}
	q := t.currentQuota()
	decisionID := m.cfg.IDFactory()
	queueStart := time.Now()
	rec := AuditRecord{
		TenantID:        tenantID,
		DecisionID:      decisionID,
		RequestID:       req.RequestID,
		Package:         req.Package,
		StartedAt:       queueStart,
		HeapGrowthBytes: -1,
	}

	// ---- Admission: global FIFO gate first, then the tenant's own semaphore.
	var globalRelease func()
	if m.globalSem != nil {
		rel, gerr := m.globalSem.acquire(ctx, -1)
		if gerr != nil {
			t.queueTimeouts.inc()
			rec.EndedAt, rec.Outcome, rec.ErrorMessage = time.Now(), string(ReasonQueueTimeout), gerr.Error()
			m.audit(rec)
			return EvalResult{}, mapContextErr(tenantID, gerr, ReasonQueueTimeout)
		}
		globalRelease = rel
	}
	queueCtx := ctx
	var queueCancel context.CancelFunc
	if q.QueueTimeout > 0 {
		queueCtx, queueCancel = context.WithTimeout(ctx, q.QueueTimeout)
	}
	if queueCancel != nil {
		defer queueCancel()
	}
	release, aerr := t.sem.acquire(queueCtx, q.MaxQueued)
	queueDelay := time.Since(queueStart)
	rec.QueueDelay = queueDelay
	if aerr != nil {
		if globalRelease != nil {
			globalRelease()
		}
		if me, ok := errors.AsType[*Error](aerr); ok && me.Reason == ReasonConcurrency {
			me.TenantID = tenantID
			t.rejected.inc()
			rec.EndedAt, rec.Outcome, rec.ErrorMessage = time.Now(), string(ReasonConcurrency), me.Message
			m.audit(rec)
			return EvalResult{}, me
		}
		// Context expired while queued.
		t.queueTimeouts.inc()
		reason := ReasonQueueTimeout
		msg := "queued longer than QueueTimeout"
		if !errors.Is(aerr, context.DeadlineExceeded) {
			msg = aerr.Error()
		}
		rec.EndedAt, rec.Outcome, rec.ErrorMessage = time.Now(), string(reason), msg
		m.audit(rec)
		if errors.Is(aerr, context.DeadlineExceeded) {
			return EvalResult{}, &Error{TenantID: tenantID, Reason: reason, Message: msg}
		}
		return EvalResult{}, mapContextErr(tenantID, aerr, reason)
	}
	defer release()
	if globalRelease != nil {
		// Hand the global slot back together with the tenant slot on exit.
		defer globalRelease()
	}
	t.queueDelaySum.add(int64(queueDelay))
	t.started.inc()
	defer t.completed.inc()

	// ---- Bounded evaluation context.
	evalCtx, cancel := context.WithTimeout(ctx, q.EvalTimeout)
	defer cancel()
	ae := &activeEval{
		tenantID:   tenantID,
		decisionID: decisionID,
		cancel:     cancel,
		guard:      newMemGuard(q.MemoryLimitBytes, m.mem.current()),
		startedAt:  time.Now(),
	}
	m.registerActive(decisionID, ae)
	defer m.unregisterActive(decisionID)

	evalStart := time.Now()
	result, evalErr := req.Fn(evalCtx)
	duration := time.Since(evalStart)
	t.evalDurationNs.add(int64(duration))

	rec.EndedAt = time.Now()
	rec.Duration = duration
	rec.HeapGrowthBytes = m.observedGrowth(ae)

	classified := classify(evalCtx, ae, evalErr)
	rec.Outcome = classified.outcome
	rec.ErrorMessage = classified.message
	switch classified.reason {
	case ReasonTimeout:
		t.timeouts.inc()
	case ReasonMemory:
		t.memoryAborts.inc()
	case "":
		if evalErr != nil {
			t.engineErrors.inc()
		}
	}
	m.audit(rec)

	if classified.reason != "" {
		return EvalResult{DecisionID: decisionID}, &Error{
			TenantID: tenantID,
			Reason:   classified.reason,
			Message:  classified.message,
		}
	}
	if evalErr != nil {
		return EvalResult{DecisionID: decisionID}, evalErr
	}
	return EvalResult{DecisionID: decisionID, Result: result}, nil
}

// audit forwards a record to the async sink. The sink never returns an error
// to callers (its Write is non-blocking and keeps records on outage), so the
// evaluation path cannot be affected by audit failures.
func (m *Manager) audit(rec AuditRecord) {
	_ = m.sink.Write(context.Background(), rec)
}

type classification struct {
	reason  Reason // "" means not a quota failure
	outcome string
	message string
}

func classify(evalCtx context.Context, ae *activeEval, evalErr error) classification {
	if evalErr == nil {
		return classification{outcome: "ok"}
	}
	if ae.memoryTripped() {
		return classification{
			reason:  ReasonMemory,
			outcome: string(ReasonMemory),
			message: "evaluation exceeded tenant memory quota",
		}
	}
	if errors.Is(evalErr, context.DeadlineExceeded) || isEngineCancel(evalErr) || evalCtx.Err() == context.DeadlineExceeded {
		return classification{
			reason:  ReasonTimeout,
			outcome: string(ReasonTimeout),
			message: "evaluation exceeded tenant eval timeout",
		}
	}
	return classification{outcome: "engine_error", message: sanitizeErr(evalErr)}
}

func (m *Manager) registerActive(id string, ae *activeEval) {
	m.activeMu.Lock()
	m.active[id] = ae
	m.activeMu.Unlock()
}

func (m *Manager) unregisterActive(id string) {
	m.activeMu.Lock()
	delete(m.active, id)
	m.activeMu.Unlock()
}

func (m *Manager) observedGrowth(ae *activeEval) int64 {
	if ae.guard.limit <= 0 {
		return -1
	}
	s := m.mem.current()
	growth := s.heapIncr - ae.guard.startIncr
	if growth < 0 {
		growth = int64(s.heapAlloc) - int64(ae.guard.startAlloc)
	}
	return growth
}

// watchdog is the single memory watcher for all in-flight evaluations.
func (m *Manager) watchdog() {
	defer close(m.doneCh)
	t := time.NewTicker(m.cfg.MemorySampleInterval)
	defer t.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-t.C:
			snap := m.mem.current()
			m.activeMu.Lock()
			for _, ae := range m.active {
				if ae.guard.exceeded(snap) && ae.markMemory() {
					ae.cancel()
				}
			}
			m.activeMu.Unlock()
		}
	}
}

func mapContextErr(tenantID string, err error, fallback Reason) error {
	if errors.Is(err, context.Canceled) {
		return &Error{TenantID: tenantID, Reason: ReasonStopped, Message: "request cancelled"}
	}
	return &Error{TenantID: tenantID, Reason: fallback, Message: err.Error()}
}

// sanitizeErr reduces an engine error to non-sensitive text. Engine errors in
// OPA carry rule/location information but not input values; we keep the
// error string as-is while providing one place to tighten this if a custom
// builtin embeds input data in its errors.
func sanitizeErr(err error) string {
	return err.Error()
}
