// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package decisioncache

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testConfig(now func() time.Time) *Config {
	return &Config{
		Enabled:       true,
		MaxNumEntries: 10,
		MaxSizeBytes:  0,
		TTL:           30 * time.Second,
		NegativeTTL:   5 * time.Second,
		Now:           now,
	}
}

func TestCacheDisabledByDefault(t *testing.T) {
	t.Parallel()

	cache := New(context.Background(), &Config{})
	if cache.State() != StateDisabled {
		t.Fatalf("expected disabled state, got %v", cache.State())
	}

	var loads atomic.Int32
	entry, hit, err := cache.Get(context.Background(), cache.Begin(), Key{}, func(context.Context) (*Entry, error) {
		loads.Add(1)
		return &Entry{Value: true}, nil
	})
	if err != nil || hit || entry == nil || entry.Value != true {
		t.Fatalf("unexpected disabled-cache result: %+v hit=%v err=%v", entry, hit, err)
	}
	if loads.Load() != 1 {
		t.Fatalf("disabled cache must still run load, got %d", loads.Load())
	}
	if err := cache.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCacheHitAndMiss(t *testing.T) {
	t.Parallel()

	now := time.Now()
	cache := New(context.Background(), testConfig(func() time.Time { return now }))
	t.Cleanup(func() { _ = cache.Close() })

	var loads atomic.Int32
	load := func(context.Context) (*Entry, error) {
		loads.Add(1)
		return &Entry{Value: true, Fence: Fence{Digest: "d1"}, StoredAt: now}, nil
	}
	key := Key{Path: "/example/allow", Input: "{}", Fence: "d1"}

	first, hit, err := cache.Get(context.Background(), cache.Begin(), key, load)
	if err != nil || hit {
		t.Fatalf("first Get: hit=%v err=%v", hit, err)
	}
	if first.Value != true {
		t.Fatalf("unexpected value %v", first.Value)
	}

	second, hit, err := cache.Get(context.Background(), cache.Begin(), key, load)
	if err != nil || !hit {
		t.Fatalf("second Get: hit=%v err=%v", hit, err)
	}
	if second.Value != true {
		t.Fatalf("cached value mismatch: %v", second.Value)
	}
	if loads.Load() != 1 {
		t.Fatalf("load ran %d times, want 1", loads.Load())
	}

	stats := cache.Stats()
	if stats.Hits != 1 || stats.Misses != 1 || stats.Entries != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func TestCacheTTLExpiry(t *testing.T) {
	t.Parallel()

	now := time.Now()
	cfg := testConfig(func() time.Time { return now })
	cache := New(context.Background(), cfg)
	t.Cleanup(func() { _ = cache.Close() })

	key := Key{Path: "/p", Input: noInputMarker, Fence: "d"}

	_, _, err := cache.Get(context.Background(), cache.Begin(), key, func(context.Context) (*Entry, error) {
		return &Entry{Value: "v", Fence: Fence{Digest: "d"}, StoredAt: now, ExpiresAt: now.Add(cfg.TTL)}, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, hit, _ := cache.Get(context.Background(), cache.Begin(), key, func(context.Context) (*Entry, error) {
		return &Entry{Value: "v2"}, nil
	}); !hit {
		t.Fatal("expected hit before TTL elapses")
	}

	now = now.Add(cfg.TTL + time.Second)
	if _, hit, _ := cache.Get(context.Background(), cache.Begin(), key, func(context.Context) (*Entry, error) {
		return &Entry{Value: "v3"}, nil
	}); hit {
		t.Fatal("expected miss after TTL elapses")
	}
	if stats := cache.Stats(); stats.Expired != 1 {
		t.Fatalf("expected 1 expired, got %+v", stats)
	}
}

func TestCacheNegativeTTLExpiry(t *testing.T) {
	t.Parallel()

	now := time.Now()
	cfg := testConfig(func() time.Time { return now })
	cache := New(context.Background(), cfg)
	t.Cleanup(func() { _ = cache.Close() })

	key := Key{Path: "/p", Input: noInputMarker, Fence: "d"}

	_, _, err := cache.Get(context.Background(), cache.Begin(), key, func(context.Context) (*Entry, error) {
		return &Entry{Undefined: true, Fence: Fence{Digest: "d"}, StoredAt: now, ExpiresAt: now.Add(cfg.NegativeTTL)}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, hit, _ := cache.Get(context.Background(), cache.Begin(), key, func(context.Context) (*Entry, error) {
		t.Fatal("undefined entry should have hit within negative TTL")
		return nil, nil
	}); !hit {
		t.Fatal("expected hit for undefined entry within negative TTL")
	}

	now = now.Add(cfg.NegativeTTL + time.Second)
	var reloaded atomic.Bool
	_, hit, _ := cache.Get(context.Background(), cache.Begin(), key, func(context.Context) (*Entry, error) {
		reloaded.Store(true)
		return &Entry{Undefined: true}, nil
	})
	if hit || !reloaded.Load() {
		t.Fatalf("expected undefined entry to expire: hit=%v reloaded=%v", hit, reloaded.Load())
	}
	if cache.Stats().Expired != 1 {
		t.Fatalf("expected 1 expired, got %+v", cache.Stats())
	}
}

func TestCacheMaxNumEntriesEviction(t *testing.T) {
	t.Parallel()

	cfg := testConfig(time.Now)
	cfg.MaxNumEntries = 2
	cache := New(context.Background(), cfg)
	t.Cleanup(func() { _ = cache.Close() })

	for i := range 3 {
		key := Key{Path: fmt.Sprintf("/p%d", i), Fence: "d"}
		_, _, err := cache.Get(context.Background(), cache.Begin(), key, func(context.Context) (*Entry, error) {
			return &Entry{Value: i, Fence: Fence{Digest: "d"}}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	stats := cache.Stats()
	if stats.Entries != 2 {
		t.Fatalf("expected 2 entries, got %d", stats.Entries)
	}
	if stats.Evicted != 1 {
		t.Fatalf("expected 1 eviction, got %d", stats.Evicted)
	}

	// The oldest entry must have been evicted.
	oldest := Key{Path: "/p0", Fence: "d"}
	if _, hit, _ := cache.Get(context.Background(), cache.Begin(), oldest, func(context.Context) (*Entry, error) {
		return &Entry{Value: "reloaded"}, nil
	}); hit {
		t.Fatal("oldest entry should have been evicted")
	}
}

func TestCacheMaxSizeBytesEviction(t *testing.T) {
	t.Parallel()

	cfg := testConfig(time.Now)
	cfg.MaxNumEntries = 0
	// Each boolean serializes to "true" (4 bytes); allow room for two.
	cfg.MaxSizeBytes = 9
	cache := New(context.Background(), cfg)
	t.Cleanup(func() { _ = cache.Close() })

	for i := range 3 {
		key := Key{Path: fmt.Sprintf("/p%d", i), Fence: "d"}
		_, _, err := cache.Get(context.Background(), cache.Begin(), key, func(context.Context) (*Entry, error) {
			return &Entry{Value: true, Fence: Fence{Digest: "d"}}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	stats := cache.Stats()
	if stats.Bytes > cfg.MaxSizeBytes {
		t.Fatalf("usage %d exceeds limit %d", stats.Bytes, cfg.MaxSizeBytes)
	}
	if stats.Evicted < 1 {
		t.Fatalf("expected byte-limit evictions, got %+v", stats)
	}
}

func TestCacheOversizedEntryDropped(t *testing.T) {
	t.Parallel()

	cfg := testConfig(time.Now)
	cfg.MaxSizeBytes = 2
	cache := New(context.Background(), cfg)
	t.Cleanup(func() { _ = cache.Close() })

	key := Key{Path: "/p", Fence: "d"}
	_, _, err := cache.Get(context.Background(), cache.Begin(), key, func(context.Context) (*Entry, error) {
		return &Entry{Value: "too-large"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats := cache.Stats(); stats.Entries != 0 {
		t.Fatalf("oversized entry must not be stored, got %+v", stats)
	}
}

func TestCacheSingleFlight(t *testing.T) {
	t.Parallel()

	cache := New(context.Background(), testConfig(time.Now))
	t.Cleanup(func() { _ = cache.Close() })

	var loads atomic.Int32
	load := func(context.Context) (*Entry, error) {
		loads.Add(1)
		time.Sleep(20 * time.Millisecond)
		return &Entry{Value: true, Fence: Fence{Digest: "d"}}, nil
	}
	key := Key{Path: "/p", Input: "{}", Fence: "d"}

	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := cache.Get(context.Background(), cache.Begin(), key, load)
			if err != nil {
				t.Errorf("Get: %v", err)
			}
		}()
	}
	wg.Wait()

	if loads.Load() != 1 {
		t.Fatalf("load ran %d times, want exactly 1", loads.Load())
	}
	stats := cache.Stats()
	if stats.Misses != 1 {
		t.Fatalf("expected exactly one miss (the leader), got %d", stats.Misses)
	}
	if stats.Hits != 99 {
		t.Fatalf("expected 99 hits for singleflight waiters, got %d", stats.Hits)
	}
}

func TestCacheGenerationDrop(t *testing.T) {
	t.Parallel()

	cache := New(context.Background(), testConfig(time.Now))
	t.Cleanup(func() { _ = cache.Close() })

	ticket := cache.Begin()

	// A commit lands while the evaluation is in flight.
	cache.Invalidate(ReasonData)

	var stored atomic.Bool
	entry, hit, err := cache.Get(context.Background(), ticket, Key{Path: "/p", Fence: "d"}, func(context.Context) (*Entry, error) {
		stored.Store(true)
		return &Entry{Value: true, Fence: Fence{Digest: "d"}}, nil
	})
	if err != nil || hit {
		t.Fatalf("unexpected Get result: hit=%v err=%v", hit, err)
	}
	if entry == nil || entry.Value != true {
		t.Fatal("the computed decision must still be returned to the caller")
	}
	if !stored.Load() {
		t.Fatal("load was not invoked")
	}
	stats := cache.Stats()
	if stats.Dropped != 1 {
		t.Fatalf("expected 1 dropped entry, got %+v", stats)
	}
	if stats.Entries != 0 {
		t.Fatalf("stale-generation entry was stored: %+v", stats)
	}
}

func TestCacheInvalidateClearsEntries(t *testing.T) {
	t.Parallel()

	cache := New(context.Background(), testConfig(time.Now))
	t.Cleanup(func() { _ = cache.Close() })

	key := Key{Path: "/p", Fence: "d"}
	_, _, _ = cache.Get(context.Background(), cache.Begin(), key, func(context.Context) (*Entry, error) {
		return &Entry{Value: true, Fence: Fence{Digest: "d"}}, nil
	})
	cache.Invalidate(ReasonPolicy)

	if _, hit, _ := cache.Get(context.Background(), cache.Begin(), key, func(context.Context) (*Entry, error) {
		return &Entry{Value: false}, nil
	}); hit {
		t.Fatal("entries must be cleared on invalidation")
	}
	if cache.Stats().Entries != 1 {
		t.Fatalf("expected one fresh entry after reload, got %+v", cache.Stats())
	}
}

func TestCacheUpdateConfigShrinksImmediately(t *testing.T) {
	t.Parallel()

	cfg := testConfig(time.Now)
	cache := New(context.Background(), cfg)
	t.Cleanup(func() { _ = cache.Close() })

	for i := range 4 {
		key := Key{Path: fmt.Sprintf("/p%d", i), Fence: "d"}
		_, _, _ = cache.Get(context.Background(), cache.Begin(), key, func(context.Context) (*Entry, error) {
			return &Entry{Value: true, Fence: Fence{Digest: "d"}}, nil
		})
	}

	shrunk := *cfg
	shrunk.MaxNumEntries = 2
	cache.UpdateConfig(&shrunk)

	if stats := cache.Stats(); stats.Entries != 2 {
		t.Fatalf("expected immediate shrink to 2, got %+v", stats)
	}

	// Growing the limit changes only the bound; surviving entries stay fresh.
	grown := shrunk
	grown.MaxNumEntries = 10
	cache.UpdateConfig(&grown)
	survivor := Key{Path: "/p3", Fence: "d"}
	if _, hit, _ := cache.Get(context.Background(), cache.Begin(), survivor, func(context.Context) (*Entry, error) {
		return &Entry{Value: "reloaded"}, nil
	}); !hit {
		t.Fatal("surviving entry should still hit after growing the limit")
	}
}

func TestCacheLoadErrorPropagates(t *testing.T) {
	t.Parallel()

	cache := New(context.Background(), testConfig(time.Now))
	t.Cleanup(func() { _ = cache.Close() })

	wantErr := errors.New("boom")
	_, _, err := cache.Get(context.Background(), cache.Begin(), Key{Path: "/p", Fence: "d"}, func(context.Context) (*Entry, error) {
		return nil, wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected %v, got %v", wantErr, err)
	}
	if cache.Stats().Entries != 0 {
		t.Fatal("failed loads must not be cached")
	}
}

func TestCacheCloseIdempotent(t *testing.T) {
	t.Parallel()

	cache := New(context.Background(), testConfig(time.Now))
	if err := cache.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cache.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestCanonicalInput(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		a    string
		b    string
		same bool
	}{
		{"whitespace", `{"a": 1}`, ` { "a":1 } `, true},
		{"key order", `{"a":1,"b":2}`, `{"b":2,"a":1}`, true},
		{"nested order", `{"o":{"a":1,"b":2}}`, `{"o":{"b":2,"a":1}}`, true},
		{"number precision", `1`, `1.0`, false},
		{"arrays stay ordered", `[1,2]`, `[2,1]`, false},
		{"string values", `"x"`, `"x"`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ka, err := CanonicalInput([]byte(tc.a))
			if err != nil {
				t.Fatal(err)
			}
			kb, err := CanonicalInput([]byte(tc.b))
			if err != nil {
				t.Fatal(err)
			}
			if (ka == kb) != tc.same {
				t.Fatalf("canonical(%q)=%q canonical(%q)=%q same=%v want %v", tc.a, ka, tc.b, kb, ka == kb, tc.same)
			}
		})
	}

	noInput, err := CanonicalInput(nil)
	if err != nil || noInput != noInputMarker {
		t.Fatalf("no-input marker wrong: %q err=%v", noInput, err)
	}

	if _, err := CanonicalInput([]byte("{not json")); err == nil {
		t.Fatal("malformed input must return an error")
	}
}

func TestEntryImmutability(t *testing.T) {
	t.Parallel()

	cache := New(context.Background(), testConfig(time.Now))
	t.Cleanup(func() { _ = cache.Close() })

	key := Key{Path: "/p", Fence: "d"}
	original := map[string]any{"nested": []any{1, 2}}
	_, _, _ = cache.Get(context.Background(), cache.Begin(), key, func(context.Context) (*Entry, error) {
		return &Entry{Value: original, Fence: Fence{Digest: "d"}}, nil
	})

	cached, hit, _ := cache.Get(context.Background(), cache.Begin(), key, func(context.Context) (*Entry, error) {
		t.Fatal("expected hit")
		return nil, nil
	})
	if !hit {
		t.Fatal("expected hit")
	}
	mutated := cached.Value.(map[string]any)
	mutated["nested"].([]any)[0] = 999

	again, hit, _ := cache.Get(context.Background(), cache.Begin(), key, func(context.Context) (*Entry, error) {
		t.Fatal("expected hit")
		return nil, nil
	})
	if !hit {
		t.Fatal("expected hit")
	}
	if again.Value.(map[string]any)["nested"].([]any)[0] != float64(1) {
		t.Fatalf("stored entry was mutated through a returned copy: %v", again.Value)
	}
}

func TestCacheDegradedBypassesStore(t *testing.T) {
	t.Parallel()

	cache := New(context.Background(), testConfig(time.Now))
	t.Cleanup(func() { _ = cache.Close() })
	cache.SetState(StateDegraded)

	var loads atomic.Int32
	key := Key{Path: "/p", Fence: "d"}
	for range 2 {
		_, hit, err := cache.Get(context.Background(), cache.Begin(), key, func(context.Context) (*Entry, error) {
			loads.Add(1)
			return &Entry{Value: true}, nil
		})
		if err != nil || hit {
			t.Fatalf("degraded cache must evaluate directly: hit=%v err=%v", hit, err)
		}
	}
	if loads.Load() != 2 || cache.Stats().Entries != 0 {
		t.Fatalf("degraded cache must not store entries: loads=%d stats=%+v", loads.Load(), cache.Stats())
	}
}

func TestCacheJanitorSweepsExpiredEntries(t *testing.T) {
	t.Parallel()

	now := time.Now()
	cache := New(context.Background(), testConfig(func() time.Time { return now })).(*decisionCache)
	t.Cleanup(func() { _ = cache.Close() })

	key := Key{Path: "/p", Fence: "d"}
	_, _, _ = cache.Get(context.Background(), cache.Begin(), key, func(context.Context) (*Entry, error) {
		return &Entry{Value: true, ExpiresAt: now.Add(time.Second)}, nil
	})

	// Advance time past expiry and invoke the same sweep the janitor runs.
	now = now.Add(2 * time.Second)
	cache.sweep()

	if cache.Stats().Expired != 1 || cache.Stats().Entries != 0 {
		t.Fatalf("janitor sweep did not remove the expired entry: %+v", cache.Stats())
	}
}

func TestCacheNoTriggerReliesOnFence(t *testing.T) {
	t.Parallel()

	// Even without Invalidate being called (store without triggers, or a
	// directly constructed cache), a changed fence digest makes the old entry
	// unhittable.
	cache := New(context.Background(), testConfig(time.Now))
	t.Cleanup(func() { _ = cache.Close() })

	load := func(v any) func(context.Context) (*Entry, error) {
		return func(context.Context) (*Entry, error) {
			return &Entry{Value: v, Fence: Fence{Digest: "d1"}}, nil
		}
	}
	oldKey := Key{Path: "/p", Fence: "d1"}
	if _, hit, _ := cache.Get(context.Background(), cache.Begin(), oldKey, load("old")); hit {
		t.Fatal("first request must miss")
	}
	if _, hit, _ := cache.Get(context.Background(), cache.Begin(), oldKey, load("old")); !hit {
		t.Fatal("same fence must hit")
	}

	newKey := Key{Path: "/p", Fence: "d2"}
	entry, hit, _ := cache.Get(context.Background(), cache.Begin(), newKey, load("new"))
	if hit || entry.Value != "new" {
		t.Fatalf("a changed fence must never match an old entry: hit=%v entry=%v", hit, entry)
	}
}

func TestCacheNoStoreContext(t *testing.T) {
	t.Parallel()

	cache := New(context.Background(), testConfig(time.Now))
	t.Cleanup(func() { _ = cache.Close() })

	key := Key{Path: "/p", Fence: "d"}
	ctx := WithNoStore(context.Background())
	entry, hit, err := cache.Get(ctx, cache.Begin(), key, func(context.Context) (*Entry, error) {
		return &Entry{Value: true}, nil
	})
	if err != nil || hit || entry == nil {
		t.Fatalf("no-store miss must still return the entry: hit=%v err=%v", hit, err)
	}
	if cache.Stats().Entries != 0 {
		t.Fatalf("no-store decision must not be retained: %+v", cache.Stats())
	}

	// An ordinary request on the same key still stores and subsequently hits.
	if _, hit, _ := cache.Get(context.Background(), cache.Begin(), key, func(context.Context) (*Entry, error) {
		return &Entry{Value: true}, nil
	}); hit {
		t.Fatal("first ordinary request must miss")
	}
	if _, hit, _ := cache.Get(context.Background(), cache.Begin(), key, func(context.Context) (*Entry, error) {
		t.Fatal("expected hit on the stored entry")
		return nil, nil
	}); !hit {
		t.Fatal("stored entry should hit")
	}
}
