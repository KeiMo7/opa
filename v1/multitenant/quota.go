// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package multitenant

import (
	"context"
	"sync"
	"time"
)

// Quota is the per-tenant evaluation quota. The zero value is not valid; use
// [Config.Defaults] and [Manager.SetQuota] which fill defaults. A zero field
// in a quota supplied to [Manager.SetQuota] is replaced by the instance
// default, so partial quota documents (e.g. only overriding concurrency) are
// supported.
type Quota struct {
	// MaxConcurrent is the maximum number of evaluations running at the same
	// time for one tenant. Must be >= 1.
	MaxConcurrent int

	// EvalTimeout is the upper bound on a single evaluation. When it elapses
	// the evaluation is cancelled and returns an [Error] with ReasonTimeout.
	EvalTimeout time.Duration

	// MemoryLimitBytes is the amount by which the process heap may grow while
	// one of the tenant's evaluations is running before that evaluation is
	// cancelled with ReasonMemory. 0 disables the per-evaluation memory guard
	// for the tenant (the process-wide soft limit, if enabled, still applies).
	// This is a cooperative guard, see the package documentation.
	MemoryLimitBytes int64

	// MaxQueued is the number of requests that may wait for a concurrency
	// slot per tenant. When the queue is full new requests fail immediately
	// with ReasonConcurrency. 0 means requests are rejected when no slot is
	// free.
	MaxQueued int

	// QueueTimeout bounds how long a request may wait in the tenant queue.
	// 0 means unbounded waiting (subject to the caller's context).
	QueueTimeout time.Duration
}

// Defaults is the instance-wide fallback quota. It applies to tenants that
// have no explicit quota, and fills zero-valued fields of explicit quotas.
type Defaults struct {
	Quota
}

// QuotaProvider supplies tenant quotas from an external quota service. The
// Manager calls [QuotaProvider.Quota] when a tenant is first seen and
// refreshes it on [Manager.RefreshQuota] / [Manager.RefreshAllQuotas].
//
// Contract: implementations MUST return the error without side effects on
// failure; the Manager then keeps serving the tenant with its last known
// quota, or the instance defaults if no quota was ever fetched. A provider
// failure therefore never causes an open fail: evaluations stay bounded by
// the instance defaults instead of running unconstrained.
type QuotaProvider interface {
	Quota(ctx context.Context, tenantID string) (Quota, error)
}

// QuotaProviderFunc adapts a function to a [QuotaProvider].
type QuotaProviderFunc func(ctx context.Context, tenantID string) (Quota, error)

// Quota implements [QuotaProvider].
func (f QuotaProviderFunc) Quota(ctx context.Context, tenantID string) (Quota, error) {
	return f(ctx, tenantID)
}

type quotaEntry struct {
	quota Quota
	// known reports whether an explicit quota has ever been set or fetched.
	known bool
}

// quotaRegistry stores tenant quotas with copy-on-write semantics: reads on
// the evaluation hot path take an RLock only.
type quotaRegistry struct {
	mu      sync.RWMutex
	tenants map[string]*quotaEntry
}

func newQuotaRegistry() *quotaRegistry {
	return &quotaRegistry{tenants: map[string]*quotaEntry{}}
}

func (r *quotaRegistry) get(tenantID string) (*quotaEntry, bool) {
	r.mu.RLock()
	e, ok := r.tenants[tenantID]
	r.mu.RUnlock()
	return e, ok
}

func (r *quotaRegistry) put(tenantID string, q Quota, known bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.tenants[tenantID]; ok {
		e.quota = q
		e.known = known || e.known
		return
	}
	r.tenants[tenantID] = &quotaEntry{quota: q, known: known}
}

func (r *quotaRegistry) delete(tenantID string) {
	r.mu.Lock()
	delete(r.tenants, tenantID)
	r.mu.Unlock()
}

func (r *quotaRegistry) ids() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.tenants))
	for id := range r.tenants {
		ids = append(ids, id)
	}
	return ids
}

// fillQuota validates q and fills only the fields whose zero value is not a
// meaningful explicit setting: MaxConcurrent and EvalTimeout have no valid
// zero semantics so they fall back to defaults. The other three fields keep
// their documented zero semantics (memory guard disabled, no queueing,
// unbounded queue wait), so an explicit 0 is never overwritten.
func fillQuota(q, d Quota) (Quota, error) {
	out := q
	if out.MaxConcurrent <= 0 {
		out.MaxConcurrent = d.MaxConcurrent
	}
	if out.EvalTimeout <= 0 {
		out.EvalTimeout = d.EvalTimeout
	}
	if out.MaxConcurrent < 1 {
		return Quota{}, &Error{Reason: ReasonStopped, Message: "quota must define MaxConcurrent >= 1 (check instance defaults)"}
	}
	if out.EvalTimeout <= 0 {
		return Quota{}, &Error{Reason: ReasonStopped, Message: "quota must define a positive EvalTimeout (check instance defaults)"}
	}
	return out, nil
}
