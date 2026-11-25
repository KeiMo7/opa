// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package decisioncache

import (
	"context"
	"time"
)

// Reason identifies why the cache was invalidated.
type Reason int

const (
	// ReasonPolicy is used when a transaction changed policies.
	ReasonPolicy Reason = iota
	// ReasonData is used when a transaction changed base data documents.
	ReasonData
)

// String returns a human readable representation of the reason.
func (r Reason) String() string {
	switch r {
	case ReasonPolicy:
		return "policy"
	case ReasonData:
		return "data"
	default:
		return "unknown"
	}
}

// State describes the operational state of the decision cache.
type State int

const (
	// StateDisabled is the default state: the cache is not enabled in
	// configuration, so no request is served from it.
	StateDisabled State = iota
	// StateEnabled means the cache is enabled and fences were read
	// successfully, so requests can be served from cached entries.
	StateEnabled
	// StateDegraded means the cache is enabled but a fence could not be read;
	// requests are evaluated directly until a fence read succeeds again.
	StateDegraded
)

// String returns a human readable representation of the state.
func (s State) String() string {
	switch s {
	case StateDisabled:
		return "disabled"
	case StateEnabled:
		return "enabled"
	case StateDegraded:
		return "degraded"
	default:
		return "unknown"
	}
}

// Key identifies a cached decision. Path is the (escaped) data API path,
// Input is the canonicalized request input and Fence is the fence digest the
// decision was evaluated against.
type Key struct {
	Path  string
	Input string
	Fence string
}

// Entry is a single cached decision. Entries are immutable once stored; a
// returned Entry must never be modified in place.
type Entry struct {
	// Value is the decision value. It is nil when Undefined is true.
	Value any
	// Undefined marks entries cached for an undefined decision; those are
	// governed by the negative TTL.
	Undefined bool
	// Fence is the full revision vector the decision was evaluated against.
	Fence Fence
	// StoredAt is when the entry was written.
	StoredAt time.Time
	// ExpiresAt is when the entry goes stale. The zero value means no expiry.
	ExpiresAt time.Time

	// noStore marks a decision that must be returned to its caller but never
	// retained, e.g. one carrying response metadata.
	noStore bool

	// size is the serialized size of Value in bytes, computed once at write.
	size int
}

// Stats holds counters describing cache behaviour.
type Stats struct {
	// Hits counts requests answered from a fresh entry.
	Hits uint64
	// Misses count requests that had to be evaluated because no fresh entry
	// existed.
	Misses uint64
	// Bypasses count requests that skipped the cache entirely.
	Bypasses uint64
	// Expired counts lookups that found an entry whose TTL had elapsed.
	Expired uint64
	// Evicted counts entries removed to stay within the configured limits.
	Evicted uint64
	// Dropped counts computed entries that were never stored because the
	// generation advanced while the evaluation was in flight.
	Dropped uint64
	// Entries is the number of currently stored entries.
	Entries int
	// Bytes is the serialized size of all currently stored decision values.
	Bytes int64
}

// Config configures the decision cache. A zero Config disables the cache.
type Config struct {
	// Enabled toggles the cache. It defaults to false.
	Enabled bool `json:"enabled"`
	// MaxNumEntries limits the number of stored entries. Zero means unlimited.
	MaxNumEntries int `json:"max_num_entries"`
	// MaxSizeBytes limits the total serialized size of stored decision
	// values. Zero means unlimited.
	MaxSizeBytes int64 `json:"max_size_bytes"`
	// TTL bounds how long a defined decision stays fresh.
	TTL time.Duration `json:"ttl_seconds"`
	// NegativeTTL bounds how long an undefined decision stays fresh.
	NegativeTTL time.Duration `json:"negative_ttl_seconds"`
	// DebugHeaders enables the OPA-Decision-Cache and OPA-Decision-Fence
	// response headers.
	DebugHeaders bool `json:"debug_headers"`
	// Now is the clock used for TTL evaluation; it defaults to time.Now and
	// is injectable for tests.
	Now func() time.Time `json:"-"`
}

// Ticket records the cache generation observed before a request's read
// transaction was opened. If the generation advances while the request is
// evaluated, the resulting decision must not be cached.
type Ticket struct {
	generation uint64
}

// Generation returns the generation the ticket was taken at.
func (t *Ticket) Generation() uint64 {
	return t.generation
}

// Cache is the decision cache used by the data API handlers.
type Cache interface {
	// Begin records the current generation. It must be called before the
	// request's read transaction is opened.
	Begin() *Ticket
	// Get returns a cached decision for key, or invokes load to evaluate it.
	// The boolean reports whether the returned Entry came from the cache.
	// Lookup, single-flight coordination, generation validation and writing
	// all happen inside Get. A context decorated with WithNoStore returns a
	// freshly evaluated decision without retaining it.
	Get(ctx context.Context, t *Ticket, key Key, load func(context.Context) (*Entry, error)) (*Entry, bool, error)
	// Invalidate drops every entry and advances the generation.
	Invalidate(Reason)
	// UpdateConfig applies a new configuration, shrinking the limits
	// immediately and only adjusting the bounds when they grow.
	UpdateConfig(*Config)
	// Stats returns a snapshot of the cache counters.
	Stats() Stats
	// Config returns a copy of the effective configuration.
	Config() Config
	// State returns the current operational state.
	State() State
	// SetState moves the cache into the given operational state.
	SetState(State)
	// Bypass records that a request skipped the cache.
	Bypass()
	// Close stops the cleanup goroutine. It is safe to call on a cache that
	// was never used and may be called more than once.
	Close() error
}
