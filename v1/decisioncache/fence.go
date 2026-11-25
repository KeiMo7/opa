// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

// Package decisioncache implements a decision cache for the OPA server whose
// entries are bound to the revisions of the activated policy bundles. Every
// cached entry carries a Fence describing the policy/data generation it was
// evaluated against, so hot reloads of policies or data can never be answered
// with a decision computed for an older revision.
package decisioncache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"

	"github.com/open-policy-agent/opa/v1/bundle"
	"github.com/open-policy-agent/opa/v1/storage"
)

// defaultRoot is recorded as the roots for a bundle that either stores no
// roots or an empty roots array: an empty roots list means the bundle owns the
// whole namespace, which is represented by the wildcard root.
const defaultRoot = ""

// Fence captures the revision vector of all activated bundles at the time a
// decision was evaluated. It is immutable once constructed.
type Fence struct {
	// LegacyRevision is the revision of the legacy (unnamed) bundle, if any.
	LegacyRevision string

	// Bundles maps the name of every activated named bundle to its revision.
	Bundles map[string]string

	// Roots maps the name of every activated named bundle to the roots it
	// owns. A missing or empty roots list is recorded as the wildcard root.
	Roots map[string][]string

	// Digest is the deterministic SHA-256 hex digest of the revision vector
	// and roots. Entries are only reusable when the observed digest matches.
	Digest string
}

// Equal reports whether two fences describe the same policy generation.
func (f Fence) Equal(other Fence) bool {
	if f.LegacyRevision != other.LegacyRevision {
		return false
	}
	if len(f.Bundles) != len(other.Bundles) || len(f.Roots) != len(other.Roots) {
		return false
	}
	for name, rev := range f.Bundles {
		if other.Bundles[name] != rev {
			return false
		}
	}
	for name, roots := range f.Roots {
		otherRoots, ok := other.Roots[name]
		if !ok || len(roots) != len(otherRoots) {
			return false
		}
		for i := range roots {
			if roots[i] != otherRoots[i] {
				return false
			}
		}
	}
	return f.Digest == other.Digest
}

// computeDigest builds a deterministic SHA-256 hex digest over the sorted
// bundle names, their revisions and their roots together with the legacy
// revision. Map iteration order cannot influence the result.
func computeDigest(f Fence) string {
	names := make([]string, 0, len(f.Bundles))
	for name := range f.Bundles {
		names = append(names, name)
	}
	sort.Strings(names)

	h := sha256.New()
	h.Write([]byte("legacy:"))
	h.Write([]byte(f.LegacyRevision))
	h.Write([]byte{'\n'})

	for _, name := range names {
		h.Write([]byte("bundle:"))
		h.Write([]byte(name))
		h.Write([]byte{'\n'})
		h.Write([]byte("revision:"))
		h.Write([]byte(f.Bundles[name]))
		h.Write([]byte{'\n'})

		roots := append([]string(nil), f.Roots[name]...)
		sort.Strings(roots)
		for _, root := range roots {
			h.Write([]byte("root:"))
			h.Write([]byte(root))
			h.Write([]byte{'\n'})
		}
	}

	return hex.EncodeToString(h.Sum(nil))
}

// FenceReader reads the Fence for the current store state. It must be used
// inside the same read transaction as the decision evaluation so the fence
// cannot drift from the data the decision was computed against.
type FenceReader struct {
	store storage.Store
}

// NewFenceReader returns a FenceReader bound to the given store.
func NewFenceReader(store storage.Store) *FenceReader {
	return &FenceReader{store: store}
}

// Read builds the Fence describing all activated bundles as visible in the
// given transaction. A storage.NotFound error from any of the bundle metadata
// reads is treated as an empty vector; any other error is returned so the
// caller can degrade to an uncached evaluation.
func (r *FenceReader) Read(ctx context.Context, txn storage.Transaction) (Fence, error) {
	f := Fence{
		Bundles: map[string]string{},
		Roots:   map[string][]string{},
	}

	legacyRevision, err := bundle.LegacyReadRevisionFromStore(ctx, r.store, txn) //nolint:staticcheck
	if err != nil && !storage.IsNotFound(err) {
		return Fence{}, err
	}
	f.LegacyRevision = legacyRevision

	names, err := bundle.ReadBundleNamesFromStore(ctx, r.store, txn)
	if err != nil {
		if !storage.IsNotFound(err) {
			return Fence{}, err
		}
		names = nil
	}

	for _, name := range names {
		revision, err := bundle.ReadBundleRevisionFromStore(ctx, r.store, txn, name)
		if err != nil && !storage.IsNotFound(err) {
			return Fence{}, err
		}
		f.Bundles[name] = revision

		roots, err := bundle.ReadBundleRootsFromStore(ctx, r.store, txn, name)
		if err != nil {
			if !storage.IsNotFound(err) {
				return Fence{}, err
			}
			roots = nil
		}
		if len(roots) == 0 {
			roots = []string{defaultRoot}
		}
		f.Roots[name] = roots
	}

	f.Digest = computeDigest(f)
	return f, nil
}
