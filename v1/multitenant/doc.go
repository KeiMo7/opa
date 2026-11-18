// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

// Package multitenant provides per-tenant resource isolation and quotas for
// policy evaluation: bounded concurrency, evaluation deadlines, cooperative
// memory guards, fair scheduling under overload, and tenant-scoped audit
// records.
//
// The package is opt-in. Code paths that do not construct a [Manager] keep
// their original behaviour exactly; nothing in the rego, topdown or server
// packages is modified when the feature is unused.
//
// # Isolation model and its limits
//
// A single Go process cannot give goroutines hard, kernel-enforced CPU or
// memory boundaries: the Go scheduler decides which goroutine runs on which P,
// and the heap is one process-wide heap. This package therefore combines
// every isolation mechanism that IS available inside one process, and leaves
// a clean seam for the only mechanism that can provide a hard boundary:
//
//   - Concurrency: each tenant gets its own semaphore. A tenant that has
//     exhausted its slots blocks (or is rejected when its queue is full) and
//     cannot consume another tenant's slots.
//   - CPU/time: every evaluation runs under a per-evaluation context deadline.
//     The topdown engine checks cancellation between every expression, so an
//     infinite or pathological loop is unwound cooperatively and its goroutine
//     exits. Long-running custom (Go) builtins must honour the context passed
//     to them; a builtin that ignores its context cannot be interrupted by any
//     Go code.
//   - Memory: heap growth of the evaluating goroutine is sampled; once a
//     tenant's evaluation has grown past its memory quota the same cancellation
//     mechanism unwinds it and the allocations become garbage. [debug.SetMemoryLimit]
//     can additionally be enabled so the runtime forces GC before the process
//     itself is OOM-killed. Neither mechanism is a hard per-tenant limit: a
//     single unbounded allocation that crosses the quota in one step is only
//     observed after it has happened. For hard limits, run tenants (or groups
//     of tenants) in separate processes/containers (cgroups) and use this
//     package on top for the cooperative layer.
//   - Data/policies: every tenant owns an independent [storage.Store]; there
//     is no shared data path, so cross-tenant reads are impossible by
//     construction.
//   - Audit: every record carries the tenant ID, decision ID, package and
//     request ID. Sensitive policy and input content is never stored.
package multitenant

import (
	"errors"
)

// Reason explains why an evaluation was rejected or aborted.
type Reason string

const (
	// ReasonTimeout means the evaluation exceeded its per-evaluation deadline
	// and was cancelled.
	ReasonTimeout Reason = "timeout"

	// ReasonMemory means the evaluation grew past its memory quota and was
	// cancelled.
	ReasonMemory Reason = "memory"

	// ReasonConcurrency means the tenant had no free concurrency slot and its
	// bounded queue was full, so the request was rejected immediately.
	ReasonConcurrency Reason = "concurrency_limit"

	// ReasonQueueTimeout means the request waited in the tenant's fair queue
	// longer than the configured queue wait deadline without acquiring a slot.
	ReasonQueueTimeout Reason = "queue_timeout"

	// ReasonUnknownTenant means no tenant with the given ID is registered.
	ReasonUnknownTenant Reason = "unknown_tenant"

	// ReasonStopped means the manager has been shut down.
	ReasonStopped Reason = "manager_stopped"
)

// Error is returned for quota and isolation failures. Callers can use
// errors.AsType to distinguish them from evaluation errors returned by the
// engine itself.
type Error struct {
	// TenantID identifies the tenant the failure belongs to. It may be empty
	// for failures that happen before a tenant is resolved.
	TenantID string

	// Reason classifies the failure.
	Reason Reason

	// Message is a human-readable description. It never contains policy or
	// input content.
	Message string
}

func (e *Error) Error() string {
	if e.TenantID == "" {
		return "multitenant: " + string(e.Reason) + ": " + e.Message
	}
	return "multitenant: tenant " + e.TenantID + ": " + string(e.Reason) + ": " + e.Message
}

// AsError reports whether err is a [*Error] with the given reason.
func AsError(err error, reason Reason) bool {
	if me, ok := errors.AsType[*Error](err); ok {
		return me.Reason == reason
	}
	return false
}
