// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package decisioncache

import (
	"context"
	"testing"

	"github.com/open-policy-agent/opa/v1/bundle"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
)

func writeManifest(t *testing.T, ctx context.Context, store storage.Store, name string, manifest bundle.Manifest) {
	t.Helper()
	err := storage.Txn(ctx, store, storage.WriteParams, func(txn storage.Transaction) error {
		return bundle.WriteManifestToStore(ctx, store, txn, name, manifest)
	})
	if err != nil {
		t.Fatalf("WriteManifestToStore: %v", err)
	}
}

func writeLegacyManifest(t *testing.T, ctx context.Context, store storage.Store, manifest bundle.Manifest) {
	t.Helper()
	err := storage.Txn(ctx, store, storage.WriteParams, func(txn storage.Transaction) error {
		return bundle.LegacyWriteManifestToStore(ctx, store, txn, manifest) //nolint:staticcheck
	})
	if err != nil {
		t.Fatalf("LegacyWriteManifestToStore: %v", err)
	}
}

func readFence(t *testing.T, ctx context.Context, reader *FenceReader, store storage.Store) Fence {
	t.Helper()
	txn, err := store.NewTransaction(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Abort(ctx, txn)
	fence, err := reader.Read(ctx, txn)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return fence
}

func TestFenceReaderEmptyStore(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := inmem.New()
	reader := NewFenceReader(store)

	fence := readFence(t, ctx, reader, store)

	if fence.LegacyRevision != "" {
		t.Fatalf("expected empty legacy revision, got %q", fence.LegacyRevision)
	}
	if len(fence.Bundles) != 0 || len(fence.Roots) != 0 {
		t.Fatalf("expected empty vector, got %+v", fence)
	}
	if fence.Digest == "" {
		t.Fatal("expected non-empty digest for empty vector")
	}

	// An empty vector must be stable across reads.
	fence2 := readFence(t, ctx, reader, store)
	if fence.Digest != fence2.Digest {
		t.Fatalf("empty vector digest unstable: %q vs %q", fence.Digest, fence2.Digest)
	}
}

func TestFenceReaderNamedBundles(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := inmem.New()

	roots := []string{"example", "other"}
	writeManifest(t, ctx, store, "b1", bundle.Manifest{Revision: "r1", Roots: &roots})
	writeManifest(t, ctx, store, "b2", bundle.Manifest{Revision: "r2"})

	reader := NewFenceReader(store)
	fence := readFence(t, ctx, reader, store)

	if fence.Bundles["b1"] != "r1" || fence.Bundles["b2"] != "r2" {
		t.Fatalf("unexpected revisions: %+v", fence.Bundles)
	}
	if got := fence.Roots["b1"]; len(got) != 2 || got[0] != "example" || got[1] != "other" {
		t.Fatalf("unexpected roots for b1: %v", got)
	}
	// No roots stored: default wildcard root.
	if got := fence.Roots["b2"]; len(got) != 1 || got[0] != defaultRoot {
		t.Fatalf("expected wildcard default root for b2, got %v", got)
	}
}

func TestFenceDigestOrderIndependent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	build := func() Fence {
		store := inmem.New()
		writeManifest(t, ctx, store, "b1", bundle.Manifest{Revision: "r1"})
		writeManifest(t, ctx, store, "b2", bundle.Manifest{Revision: "r2"})
		reader := NewFenceReader(store)
		return readFence(t, ctx, reader, store)
	}

	first := build()
	second := build()
	if first.Digest != second.Digest {
		t.Fatalf("digest depends on map iteration order: %q vs %q", first.Digest, second.Digest)
	}
	if !first.Equal(second) {
		t.Fatal("Equal fences reported as different")
	}
}

func TestFenceDigestChanges(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := inmem.New()
	reader := NewFenceReader(store)

	read := func() Fence {
		return readFence(t, ctx, reader, store)
	}

	rootsV1 := []string{"a"}
	writeManifest(t, ctx, store, "b1", bundle.Manifest{Revision: "r1", Roots: &rootsV1})
	withRootsA := read()

	// A revision change changes the digest.
	writeManifest(t, ctx, store, "b1", bundle.Manifest{Revision: "r2", Roots: &rootsV1})
	withNewRevision := read()
	if withRootsA.Digest == withNewRevision.Digest {
		t.Fatal("revision change did not change digest")
	}

	// A roots change changes the digest even at the same revision.
	rootsV2 := []string{"a", "b"}
	writeManifest(t, ctx, store, "b1", bundle.Manifest{Revision: "r2", Roots: &rootsV2})
	withNewRoots := read()
	if withNewRevision.Digest == withNewRoots.Digest {
		t.Fatal("roots change did not change digest")
	}

	// Removing the bundle yields an empty vector again.
	err := storage.Txn(ctx, store, storage.WriteParams, func(txn storage.Transaction) error {
		return store.Write(ctx, txn, storage.RemoveOp, bundle.BundlesBasePath, nil)
	})
	if err != nil {
		t.Fatalf("remove bundles: %v", err)
	}
	empty := read()
	if len(empty.Bundles) != 0 {
		t.Fatalf("expected no bundles after removal, got %v", empty.Bundles)
	}
}

func TestFenceLegacyAndNamedAreSeparate(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	storeA := inmem.New()
	writeLegacyManifest(t, ctx, storeA, bundle.Manifest{Revision: "legacy-r"})
	fenceA := readFence(t, ctx, NewFenceReader(storeA), storeA)

	storeB := inmem.New()
	writeManifest(t, ctx, storeB, "b1", bundle.Manifest{Revision: "legacy-r"})
	fenceB := readFence(t, ctx, NewFenceReader(storeB), storeB)

	if fenceA.Digest == fenceB.Digest {
		t.Fatal("legacy and named bundle with same revision produced identical digest")
	}
	if fenceA.LegacyRevision != "legacy-r" || fenceB.LegacyRevision != "" {
		t.Fatalf("legacy/named revisions leaked across fences: %+v %+v", fenceA, fenceB)
	}
}

func TestFenceEqual(t *testing.T) {
	t.Parallel()

	base := Fence{
		LegacyRevision: "l1",
		Bundles:        map[string]string{"b1": "r1"},
		Roots:          map[string][]string{"b1": {"a"}},
		Digest:         "d",
	}

	cases := []struct {
		name  string
		other Fence
		want  bool
	}{
		{"identical", base, true},
		{"legacy changed", Fence{LegacyRevision: "l2", Bundles: map[string]string{"b1": "r1"}, Roots: map[string][]string{"b1": {"a"}}, Digest: "d"}, false},
		{"revision changed", Fence{LegacyRevision: "l1", Bundles: map[string]string{"b1": "r2"}, Roots: map[string][]string{"b1": {"a"}}, Digest: "d"}, false},
		{"bundle removed", Fence{LegacyRevision: "l1", Bundles: map[string]string{}, Roots: map[string][]string{}, Digest: "d"}, false},
		{"roots changed", Fence{LegacyRevision: "l1", Bundles: map[string]string{"b1": "r1"}, Roots: map[string][]string{"b1": {"b"}}, Digest: "d"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := base.Equal(tc.other); got != tc.want {
				t.Fatalf("Equal = %v, want %v", got, tc.want)
			}
		})
	}
}
