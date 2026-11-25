// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

// Deprecated: This package is intended for older projects transitioning from OPA v0.x and will remain
// for the lifetime of OPA v1.x, but its use is not recommended.
// For newer features and behaviours, such as defaulting to the Rego v1 syntax, use the corresponding
// components in the [github.com/open-policy-agent/opa/v1] package instead.
// See https://www.open-policy-agent.org/docs/latest/v0-compatibility/ for more information.
package decisioncache

import (
	"context"

	v1 "github.com/open-policy-agent/opa/v1/decisioncache"
	"github.com/open-policy-agent/opa/v1/storage"
)

// Fence captures the revision vector of all activated bundles at the time a
// decision was evaluated.
type Fence = v1.Fence

// Key identifies a cached decision.
type Key = v1.Key

// Entry is a single cached decision.
type Entry = v1.Entry

// Stats holds counters describing cache behaviour.
type Stats = v1.Stats

// Config configures the decision cache.
type Config = v1.Config

// Reason identifies why the cache was invalidated.
type Reason = v1.Reason

const (
	// ReasonPolicy is used when a transaction changed policies.
	ReasonPolicy = v1.ReasonPolicy
	// ReasonData is used when a transaction changed base data documents.
	ReasonData = v1.ReasonData
)

// State describes the operational state of the decision cache.
type State = v1.State

const (
	// StateDisabled is the default state.
	StateDisabled = v1.StateDisabled
	// StateEnabled means the cache is serving cached entries.
	StateEnabled = v1.StateEnabled
	// StateDegraded means fence reads are failing and requests are evaluated directly.
	StateDegraded = v1.StateDegraded
)

// Ticket records the cache generation observed before a request's read
// transaction was opened.
type Ticket = v1.Ticket

// Cache is the decision cache used by the data API handlers.
type Cache = v1.Cache

// FenceReader reads the Fence for the current store state.
type FenceReader = v1.FenceReader

// NewFenceReader returns a FenceReader bound to the given store.
func NewFenceReader(store storage.Store) *FenceReader {
	return v1.NewFenceReader(store)
}

// New returns a decision cache configured by cfg.
func New(ctx context.Context, cfg *Config) Cache {
	return v1.New(ctx, cfg)
}

// CanonicalInput normalizes a raw request input document into a stable cache
// key string.
func CanonicalInput(raw []byte) (string, error) {
	return v1.CanonicalInput(raw)
}

// CanonicalValue normalizes an already-decoded input value.
func CanonicalValue(value any) (string, error) {
	return v1.CanonicalValue(value)
}

// WithNoStore decorates ctx so a freshly evaluated decision is returned
// without being retained in the cache.
func WithNoStore(ctx context.Context) context.Context {
	return v1.WithNoStore(ctx)
}

// NondeterminismChecker determines whether the policy reachable from a data
// API path invokes a nondeterministic built-in.
type NondeterminismChecker = v1.NondeterminismChecker

// NewNondeterminismChecker returns a checker. The current compiler is supplied
// to each lookup.
func NewNondeterminismChecker() *NondeterminismChecker {
	return v1.NewNondeterminismChecker()
}
