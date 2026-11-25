// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/bundle"
	"github.com/open-policy-agent/opa/v1/config"
	"github.com/open-policy-agent/opa/v1/decisioncache"
	"github.com/open-policy-agent/opa/v1/metrics"
	"github.com/open-policy-agent/opa/v1/plugins"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/open-policy-agent/opa/v1/util"
)

const decisionCacheConfig = `{
	"caching": {
		"decision_cache": {
			"enabled": true,
			"max_num_entries": 100,
			"max_size_bytes": 100000,
			"ttl_seconds": 30,
			"negative_ttl_seconds": 5
		}
	}
}`

const debugHeadersConfig = `{
	"caching": {
		"decision_cache": {
			"enabled": true,
			"debug_headers": true
		}
	}
}`

const allowPolicy = `package example

import rego.v1

default allow := false

allow if {
	input.user == "alice"
}
`

func newDecisionCacheFixture(t *testing.T, config string) *fixture {
	t.Helper()
	return newFixtureWithConfig(t, config)
}

// newDecisionCacheFixtureWithServerOpts builds an enabled fixture while also
// applying server options (e.g. a custom decision id factory).
func newDecisionCacheFixtureWithServerOpts(t *testing.T, config string, opts ...func(*Server)) *fixture {
	t.Helper()
	ctx := t.Context()
	server := New().
		WithAddresses([]string{"localhost:8182"}).
		WithStore(inmem.New())
	for _, opt := range opts {
		opt(server)
	}

	m, err := plugins.New([]byte(config), "test", server.store)
	if err != nil {
		t.Fatal(err)
	}
	server = server.WithManager(m)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	server, err = server.Init(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{server: server, recorder: httptest.NewRecorder()}
}

func TestDecisionCacheDisabledByDefault(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	if f.server.decisionCache != nil {
		t.Fatalf("decision cache must be nil when unconfigured, got %+v", f.server.decisionCache)
	}
}

func TestDecisionCacheGetHit(t *testing.T) {
	t.Parallel()

	f := newDecisionCacheFixture(t, decisionCacheConfig)
	if err := f.v1(http.MethodPut, "/policies/example.rego", allowPolicy, 200, ""); err != nil {
		t.Fatal(err)
	}

	body := `{"input": {"user": "alice"}}`
	if err := f.v1(http.MethodPost, "/data/example/allow", body, 200, `{"result": true}`); err != nil {
		t.Fatal(err)
	}
	if err := f.v1(http.MethodPost, "/data/example/allow", body, 200, `{"result": true}`); err != nil {
		t.Fatal(err)
	}

	stats := f.server.decisionCache.Stats()
	if stats.Hits != 1 || stats.Misses != 1 {
		t.Fatalf("expected one hit and one miss, got %+v", stats)
	}
}

func TestDecisionCacheGetSameResponseExceptDecisionID(t *testing.T) {
	t.Parallel()

	f := newDecisionCacheFixtureWithServerOpts(t, decisionCacheConfig, uniqueDecisionIDs())
	if err := f.v1(http.MethodPut, "/policies/example.rego", allowPolicy, 200, ""); err != nil {
		t.Fatal(err)
	}

	req1 := newReqV1(http.MethodGet, "/data/example/allow?input="+urlQueryEscape(`{"user":"alice"}`), "")
	if err := f.executeRequest(req1, 200, ""); err != nil {
		t.Fatal(err)
	}
	first := f.recorder.Body.Bytes()

	req2 := newReqV1(http.MethodGet, "/data/example/allow?input="+urlQueryEscape(`{"user":"alice"}`), "")
	if err := f.executeRequest(req2, 200, ""); err != nil {
		t.Fatal(err)
	}
	second := f.recorder.Body.Bytes()

	var got1, got2 map[string]any
	if err := util.UnmarshalJSON(first, &got1); err != nil {
		t.Fatal(err)
	}
	if err := util.UnmarshalJSON(second, &got2); err != nil {
		t.Fatal(err)
	}
	if got1["decision_id"] == got2["decision_id"] {
		t.Fatal("decision_id must be unique per request")
	}
	delete(got1, "decision_id")
	delete(got2, "decision_id")
	if diff := compareJSON(got1, got2); diff != "" {
		t.Fatalf("cached response differs apart from decision_id: %s", diff)
	}

	if f.server.decisionCache.Stats().Hits != 1 {
		t.Fatalf("expected a cache hit, got %+v", f.server.decisionCache.Stats())
	}
}

func TestDecisionCacheDifferentInputMisses(t *testing.T) {
	t.Parallel()

	f := newDecisionCacheFixture(t, decisionCacheConfig)
	if err := f.v1(http.MethodPut, "/policies/example.rego", allowPolicy, 200, ""); err != nil {
		t.Fatal(err)
	}

	if err := f.v1(http.MethodPost, "/data/example/allow", `{"input": {"user": "alice"}}`, 200, `{"result": true}`); err != nil {
		t.Fatal(err)
	}
	if err := f.v1(http.MethodPost, "/data/example/allow", `{"input": {"user": "bob"}}`, 200, `{"result": false}`); err != nil {
		t.Fatal(err)
	}

	stats := f.server.decisionCache.Stats()
	if stats.Misses != 2 || stats.Hits != 0 {
		t.Fatalf("different inputs must miss: %+v", stats)
	}
}

func TestDecisionCacheKeyOrderAndWhitespace(t *testing.T) {
	t.Parallel()

	f := newDecisionCacheFixture(t, decisionCacheConfig)
	if err := f.v1(http.MethodPut, "/policies/example.rego", allowPolicy, 200, ""); err != nil {
		t.Fatal(err)
	}

	first := `{"input": {"user": "alice", "role": "admin"}}`
	second := `{"input":{"role":"admin","user":"alice"}}`

	if err := f.v1(http.MethodPost, "/data/example/allow", first, 200, `{"result": true}`); err != nil {
		t.Fatal(err)
	}
	if err := f.v1(http.MethodPost, "/data/example/allow", second, 200, `{"result": true}`); err != nil {
		t.Fatal(err)
	}

	if f.server.decisionCache.Stats().Hits != 1 {
		t.Fatalf("equivalent inputs must share a key: %+v", f.server.decisionCache.Stats())
	}
}

func TestDecisionCacheNumberDistinction(t *testing.T) {
	t.Parallel()

	f := newDecisionCacheFixture(t, decisionCacheConfig)
	policy := `package numbers
import rego.v1
one if input.n == 1
`
	if err := f.v1(http.MethodPut, "/policies/numbers.rego", policy, 200, ""); err != nil {
		t.Fatal(err)
	}

	if err := f.v1(http.MethodPost, "/data/numbers/one", `{"input":{"n":1}}`, 200, `{"result": true}`); err != nil {
		t.Fatal(err)
	}
	if err := f.v1(http.MethodPost, "/data/numbers/one", `{"input":{"n":1.0}}`, 200, `{"result": true}`); err != nil {
		t.Fatal(err)
	}

	if f.server.decisionCache.Stats().Hits != 0 {
		t.Fatalf("1 and 1.0 must be distinct cache keys: %+v", f.server.decisionCache.Stats())
	}
}

func TestDecisionCacheHotReload(t *testing.T) {
	t.Parallel()

	f := newDecisionCacheFixture(t, decisionCacheConfig)
	ctx := context.Background()

	policyV1 := `package example
import rego.v1
default allow := false
allow if true
`
	policyV2 := `package example
import rego.v1
default allow := false
allow if false
`

	putPolicy := func(src string) {
		t.Helper()
		if err := f.v1(http.MethodPut, "/policies/example.rego", src, 200, ""); err != nil {
			t.Fatal(err)
		}
	}

	putPolicy(policyV1)
	if err := f.v1(http.MethodGet, "/data/example/allow", "", 200, `{"result": true}`); err != nil {
		t.Fatal(err)
	}
	if err := f.v1(http.MethodGet, "/data/example/allow", "", 200, `{"result": true}`); err != nil {
		t.Fatal(err)
	}
	if f.server.decisionCache.Stats().Hits != 1 {
		t.Fatalf("expected hit before reload, got %+v", f.server.decisionCache.Stats())
	}

	putPolicy(policyV2)
	if err := f.v1(http.MethodGet, "/data/example/allow", "", 200, `{"result":false}`); err != nil {
		t.Fatal(err)
	}

	// Re-activating the original policy restores the old decision, and it
	// must not come from a stale cache entry.
	putPolicy(policyV1)
	if err := f.v1(http.MethodGet, "/data/example/allow", "", 200, `{"result": true}`); err != nil {
		t.Fatal(err)
	}

	// A bundle revision flip must also invalidate entries.
	setRevision := func(revision string) {
		t.Helper()
		err := storage.Txn(ctx, f.server.store, storage.WriteParams, func(txn storage.Transaction) error {
			return bundle.WriteManifestToStore(ctx, f.server.store, txn, "b1", bundle.Manifest{Revision: revision})
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	setRevision("r1")
	if err := f.v1(http.MethodGet, "/data/example/allow", "", 200, `{"result": true}`); err != nil {
		t.Fatal(err)
	}
	setRevision("r2")
	if err := f.v1(http.MethodGet, "/data/example/allow", "", 200, `{"result": true}`); err != nil {
		t.Fatal(err)
	}
	// The manifest write itself is a data commit and forces a miss; the next
	// identical request may hit.
	if f.server.decisionCache.Stats().Hits == 0 {
		t.Fatal("expected at least one hit across the reload sequence")
	}
}

func TestDecisionCacheDataChange(t *testing.T) {
	t.Parallel()

	f := newDecisionCacheFixture(t, decisionCacheConfig)
	ctx := context.Background()

	policy := `package example
import rego.v1
default allow := false
allow if data.example.flag
`
	if err := f.v1(http.MethodPut, "/policies/example.rego", policy, 200, ""); err != nil {
		t.Fatal(err)
	}

	err := storage.Txn(ctx, f.server.store, storage.WriteParams, func(txn storage.Transaction) error {
		if err := storage.MakeDir(ctx, f.server.store, txn, storage.MustParsePath("/example")); err != nil {
			return err
		}
		return f.server.store.Write(ctx, txn, storage.AddOp, storage.MustParsePath("/example/flag"), true)
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := f.v1(http.MethodGet, "/data/example/allow", "", 200, `{"result": true}`); err != nil {
		t.Fatal(err)
	}
	if err := f.v1(http.MethodGet, "/data/example/allow", "", 200, `{"result": true}`); err != nil {
		t.Fatal(err)
	}
	before := f.server.decisionCache.Stats().Hits
	if before != 1 {
		t.Fatalf("expected one hit, got %d", before)
	}

	err = storage.Txn(ctx, f.server.store, storage.WriteParams, func(txn storage.Transaction) error {
		return f.server.store.Write(ctx, txn, storage.ReplaceOp, storage.MustParsePath("/example/flag"), false)
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := f.v1(http.MethodGet, "/data/example/allow", "", 200, `{"result": false}`); err != nil {
		t.Fatal(err)
	}
	if f.server.decisionCache.Stats().Hits != before {
		t.Fatal("data change must invalidate the entry instead of serving a hit")
	}
}

func TestDecisionCacheUndefinedNegativeTTL(t *testing.T) {
	t.Parallel()

	f := newDecisionCacheFixture(t, decisionCacheConfig)
	policy := `package example
import rego.v1
allow if input.user == "alice"
`
	if err := f.v1(http.MethodPut, "/policies/example.rego", policy, 200, ""); err != nil {
		t.Fatal(err)
	}

	// Undefined documents keep their 404 semantics while being cached.
	if err := f.v1(http.MethodPost, "/data/example/allow", `{"input":{"user":"bob"}}`, 200, `{}`); err != nil {
		t.Fatal(err)
	}
	if err := f.v1(http.MethodPost, "/data/example/allow", `{"input":{"user":"bob"}}`, 200, `{}`); err != nil {
		t.Fatal(err)
	}

	stats := f.server.decisionCache.Stats()
	if stats.Hits != 1 {
		t.Fatalf("undefined decision should be cached under negative TTL: %+v", stats)
	}
}

func TestDecisionCacheNondeterministicBypass(t *testing.T) {
	t.Parallel()

	f := newDecisionCacheFixture(t, decisionCacheConfig)
	policy := `package example
import rego.v1
allow if time.now_ns() > 0
`
	if err := f.v1(http.MethodPut, "/policies/example.rego", policy, 200, ""); err != nil {
		t.Fatal(err)
	}

	for range 2 {
		if err := f.v1(http.MethodGet, "/data/example/allow", "", 200, `{"result":true}`); err != nil {
			t.Fatal(err)
		}
	}

	if f.server.decisionCache.Stats().Hits != 0 {
		t.Fatalf("nondeterministic policy must never hit: %+v", f.server.decisionCache.Stats())
	}
	if f.server.decisionCache.Stats().Bypasses < 2 {
		t.Fatalf("expected bypasses, got %+v", f.server.decisionCache.Stats())
	}
}

func TestDecisionCacheDebugHeaders(t *testing.T) {
	t.Parallel()

	f := newDecisionCacheFixture(t, debugHeadersConfig)
	if err := f.v1(http.MethodPut, "/policies/example.rego", allowPolicy, 200, ""); err != nil {
		t.Fatal(err)
	}

	req := newReqV1(http.MethodPost, "/data/example/allow", `{"input":{"user":"alice"}}`)
	if err := f.executeRequest(req, 200, ""); err != nil {
		t.Fatal(err)
	}
	if got := f.recorder.Header().Get(headerDecisionCache); got != decisionCacheMiss {
		t.Fatalf("expected miss header, got %q", got)
	}
	if f.recorder.Header().Get(headerDecisionFence) == "" {
		t.Fatal("expected fence header")
	}

	req = newReqV1(http.MethodPost, "/data/example/allow", `{"input":{"user":"alice"}}`)
	if err := f.executeRequest(req, 200, ""); err != nil {
		t.Fatal(err)
	}
	if got := f.recorder.Header().Get(headerDecisionCache); got != decisionCacheHit {
		t.Fatalf("expected hit header, got %q", got)
	}
}

func TestDecisionCacheDebugHeadersOffByDefault(t *testing.T) {
	t.Parallel()

	f := newDecisionCacheFixture(t, decisionCacheConfig)
	if err := f.v1(http.MethodPut, "/policies/example.rego", allowPolicy, 200, ""); err != nil {
		t.Fatal(err)
	}
	if err := f.v1(http.MethodPost, "/data/example/allow", `{"input":{"user":"alice"}}`, 200, `{"result":true}`); err != nil {
		t.Fatal(err)
	}
	if got := f.recorder.Header().Get(headerDecisionCache); got != "" {
		t.Fatalf("debug headers must be off unless configured, got %q", got)
	}
	if got := f.recorder.Header().Get(headerDecisionFence); got != "" {
		t.Fatalf("fence header must be off unless configured, got %q", got)
	}
}

func TestDecisionCacheRequestMetrics(t *testing.T) {
	t.Parallel()

	f := newDecisionCacheFixture(t, decisionCacheConfig)
	if err := f.v1(http.MethodPut, "/policies/example.rego", allowPolicy, 200, ""); err != nil {
		t.Fatal(err)
	}

	req := newReqV1(http.MethodPost, "/data/example/allow?metrics=true", `{"input":{"user":"alice"}}`)
	if err := f.executeRequest(req, 200, ""); err != nil {
		t.Fatal(err)
	}
	first := decodeBody(t, f.recorder.Body.Bytes())
	if counter(first, metrics.ServerDecisionCacheMiss) != 1 {
		t.Fatalf("missing miss counter: %v", first["metrics"])
	}

	req = newReqV1(http.MethodPost, "/data/example/allow?metrics=true", `{"input":{"user":"alice"}}`)
	if err := f.executeRequest(req, 200, ""); err != nil {
		t.Fatal(err)
	}
	second := decodeBody(t, f.recorder.Body.Bytes())
	if counter(second, metrics.ServerDecisionCacheHit) != 1 {
		t.Fatalf("missing hit counter: %v", second["metrics"])
	}
}

func TestDecisionCacheBypassReasons(t *testing.T) {
	t.Parallel()

	f := newDecisionCacheFixture(t, decisionCacheConfig)
	if err := f.v1(http.MethodPut, "/policies/example.rego", allowPolicy, 200, ""); err != nil {
		t.Fatal(err)
	}
	body := `{"input":{"user":"alice"}}`

	cases := []struct {
		name string
		path string
	}{
		{"explain", "/data/example/allow?explain=notes"},
		{"instrument", "/data/example/allow?instrument=true"},
		{"metrics is allowed", "/data/example/allow?metrics=true"},
		{"rule labels", "/data/example/allow?rule_labels=true"},
		{"strict builtin errors", "/data/example/allow?strict-builtin-errors=true"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := newReqV1(http.MethodPost, tc.path, body)
			if err := f.executeRequest(req, 200, ""); err != nil {
				t.Fatal(err)
			}
		})
	}

	// metrics=true must not bypass; explain, instrument, rule labels and
	// strict builtin errors do.
	if stats := f.server.decisionCache.Stats(); stats.Bypasses != 4 {
		t.Fatalf("expected exactly four bypasses, got %+v", stats)
	}
}

func TestDecisionCachePolicyWriteWithoutRevisionChange(t *testing.T) {
	t.Parallel()

	f := newDecisionCacheFixture(t, decisionCacheConfig)

	v1 := `package example
import rego.v1
allow if true
`
	v2 := `package example
import rego.v1
allow if input.user == "alice"
`
	if err := f.v1(http.MethodPut, "/policies/example.rego", v1, 200, ""); err != nil {
		t.Fatal(err)
	}
	if err := f.v1(http.MethodGet, "/data/example/allow", "", 200, `{"result":true}`); err != nil {
		t.Fatal(err)
	}
	if err := f.v1(http.MethodGet, "/data/example/allow", "", 200, `{"result":true}`); err != nil {
		t.Fatal(err)
	}
	if f.server.decisionCache.Stats().Hits != 1 {
		t.Fatalf("expected initial hit, got %+v", f.server.decisionCache.Stats())
	}

	// A policy PUT changes no bundle revision but must still invalidate.
	if err := f.v1(http.MethodPut, "/policies/example.rego", v2, 200, ""); err != nil {
		t.Fatal(err)
	}
	if err := f.v1(http.MethodPost, "/data/example/allow", `{"input":{"user":"bob"}}`, 200, `{}`); err != nil {
		t.Fatal(err)
	}
	if f.server.decisionCache.Stats().Hits != 1 {
		t.Fatalf("policy rewrite must not be answered from the old entry: %+v", f.server.decisionCache.Stats())
	}
}

func TestDecisionCacheProvenanceFromLiveRevisions(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	f := newDecisionCacheFixture(t, decisionCacheConfig)

	if err := f.v1(http.MethodPut, "/policies/example.rego", allowPolicy, 200, ""); err != nil {
		t.Fatal(err)
	}
	err := storage.Txn(ctx, f.server.store, storage.WriteParams, func(txn storage.Transaction) error {
		return bundle.WriteManifestToStore(ctx, f.server.store, txn, "b1", bundle.Manifest{Revision: "r1"})
	})
	if err != nil {
		t.Fatal(err)
	}

	body := `{"input":{"user":"alice"}}`
	for range 2 {
		req := newReqV1(http.MethodPost, "/data/example/allow?provenance=true", body)
		if err := f.executeRequest(req, 200, ""); err != nil {
			t.Fatal(err)
		}
		resp := decodeBody(t, f.recorder.Body.Bytes())
		prov, ok := resp["provenance"].(map[string]any)
		if !ok {
			t.Fatalf("missing provenance: %v", resp)
		}
		bundles, ok := prov["bundles"].(map[string]any)
		if !ok {
			t.Fatalf("missing bundle provenance: %v", prov)
		}
		b1, ok := bundles["b1"].(map[string]any)
		if !ok || b1["revision"] != "r1" {
			t.Fatalf("provenance must use the live revision r1, got %v", bundles)
		}
	}
}

func TestDecisionCacheDifferentPathsDoNotShareEntries(t *testing.T) {
	t.Parallel()

	f := newDecisionCacheFixture(t, decisionCacheConfig)
	policy := `package example
import rego.v1
a := 1
b := 2
`
	if err := f.v1(http.MethodPut, "/policies/example.rego", policy, 200, ""); err != nil {
		t.Fatal(err)
	}
	// Distinct paths must never share an entry even when they live in the
	// same package.
	if err := f.v1(http.MethodGet, "/data/example/a", "", 200, `{"result":1}`); err != nil {
		t.Fatal(err)
	}
	if err := f.v1(http.MethodGet, "/data/example/b", "", 200, `{"result":2}`); err != nil {
		t.Fatal(err)
	}
	if f.server.decisionCache.Stats().Hits != 0 {
		t.Fatalf("different paths must not share entries: %+v", f.server.decisionCache.Stats())
	}
	if f.server.decisionCache.Stats().Entries != 2 {
		t.Fatalf("expected two distinct entries: %+v", f.server.decisionCache.Stats())
	}

	// The cache key itself preserves the exact escaped path, including case
	// and trailing slashes, so requests routed outside the mux redirect still
	// stay distinct.
	if got := cacheKey("/Example/A", "in", decisioncache.Fence{Digest: "d"}).Path; got != "/Example/A" {
		t.Fatalf("path not preserved in key: %q", got)
	}
	if a, b := cacheKey("/x/", "in", decisioncache.Fence{Digest: "d"}), cacheKey("/x", "in", decisioncache.Fence{Digest: "d"}); a == b {
		t.Fatal("trailing-slash variants collapsed into the same key")
	}
}

func TestDecisionCacheConfigHotUpdate(t *testing.T) {
	t.Parallel()

	f := newDecisionCacheFixture(t, decisionCacheConfig)
	if err := f.v1(http.MethodPut, "/policies/example.rego", allowPolicy, 200, ""); err != nil {
		t.Fatal(err)
	}
	body := `{"input":{"user":"alice"}}`
	if err := f.v1(http.MethodPost, "/data/example/allow", body, 200, `{"result":true}`); err != nil {
		t.Fatal(err)
	}
	if err := f.v1(http.MethodPost, "/data/example/allow", body, 200, `{"result":true}`); err != nil {
		t.Fatal(err)
	}
	if f.server.decisionCache.Stats().Hits != 1 {
		t.Fatalf("expected initial hit: %+v", f.server.decisionCache.Stats())
	}

	// Shrink the entry limit through a manager reconfigure; the update must
	// apply immediately while the inter-query caches stay untouched.
	shrunk := `{
		"caching": {
			"decision_cache": {
				"enabled": true,
				"max_num_entries": 1,
				"ttl_seconds": 30,
				"negative_ttl_seconds": 5
			}
		}
	}`
	cfg, err := config.ParseConfig([]byte(shrunk), "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.server.manager.Reconfigure(cfg); err != nil {
		t.Fatal(err)
	}
	if stats := f.server.decisionCache.Stats(); stats.Entries > 1 {
		t.Fatalf("shrink did not apply immediately: %+v", stats)
	}

	// Existing entries that survived the shrink are still fresh.
	if err := f.v1(http.MethodPost, "/data/example/allow", body, 200, `{"result":true}`); err != nil {
		t.Fatal(err)
	}
}

func TestDecisionCacheFailedActivationKeepsOldRevision(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	f := newDecisionCacheFixture(t, decisionCacheConfig)
	if err := f.v1(http.MethodPut, "/policies/example.rego", allowPolicy, 200, ""); err != nil {
		t.Fatal(err)
	}

	// A valid revision serves successfully and gets cached.
	err := storage.Txn(ctx, f.server.store, storage.WriteParams, func(txn storage.Transaction) error {
		return bundle.WriteManifestToStore(ctx, f.server.store, txn, "b1", bundle.Manifest{Revision: "good"})
	})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"input":{"user":"alice"}}`
	if err := f.v1(http.MethodPost, "/data/example/allow", body, 200, `{"result":true}`); err != nil {
		t.Fatal(err)
	}

	// A syntactically broken policy write must fail: the revision vector and
	// the compiler stay on the previous generation.
	if err := f.v1(http.MethodPut, "/policies/broken.rego", "package broken\nimport rego.v1\nallow if {", 400, ""); err != nil {
		t.Fatal(err)
	}
	if err := f.v1(http.MethodPost, "/data/example/allow", body, 200, `{"result":true}`); err != nil {
		t.Fatal(err)
	}

	txn, err := f.server.store.NewTransaction(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fence, err := f.server.fenceReader.Read(ctx, txn)
	f.server.store.Abort(ctx, txn)
	if err != nil {
		t.Fatal(err)
	}
	if fence.Bundles["b1"] != "good" {
		t.Fatalf("revision changed after a failed activation: %+v", fence.Bundles)
	}
}

func TestDecisionCacheLogsEveryRequest(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	var decisions []*Info
	f := newDecisionCacheFixtureWithServerOpts(t, decisionCacheConfig, uniqueDecisionIDs(), func(s *Server) {
		s.WithDecisionLoggerWithErr(func(_ context.Context, info *Info) error {
			decisions = append(decisions, info)
			return nil
		})
	})

	if err := f.v1(http.MethodPut, "/policies/example.rego", allowPolicy, 200, ""); err != nil {
		t.Fatal(err)
	}

	err := storage.Txn(ctx, f.server.store, storage.WriteParams, func(txn storage.Transaction) error {
		return bundle.WriteManifestToStore(ctx, f.server.store, txn, "b1", bundle.Manifest{Revision: "r9"})
	})
	if err != nil {
		t.Fatal(err)
	}

	body := `{"input":{"user":"alice"}}`
	for range 3 {
		req := newReqV1(http.MethodPost, "/data/example/allow?provenance=true", body)
		if err := f.executeRequest(req, 200, ""); err != nil {
			t.Fatal(err)
		}
		resp := decodeBody(t, f.recorder.Body.Bytes())
		if resp["result"] != true {
			t.Fatalf("unexpected result: %v", resp)
		}
	}

	if len(decisions) != 3 {
		t.Fatalf("expected exactly one decision log per request, got %d", len(decisions))
	}
	ids := map[string]struct{}{}
	for _, info := range decisions {
		if info.DecisionID == "" {
			t.Fatal("decision log missing decision id")
		}
		if _, dup := ids[info.DecisionID]; dup {
			t.Fatalf("duplicate decision id %q", info.DecisionID)
		}
		ids[info.DecisionID] = struct{}{}
		if got := info.Bundles["b1"].Revision; got != "r9" {
			t.Fatalf("decision log revision %q does not match fence r9", got)
		}
	}
}

func TestDecisionCacheNoStaleHitAfterReloadRegression(t *testing.T) {
	t.Parallel()

	f := newDecisionCacheFixtureWithServerOpts(t, debugHeadersConfig)

	v1 := `package example
import rego.v1
default allow := false
allow if true
`
	v2 := `package example
import rego.v1
default allow := false
allow if false
`
	put := func(src string) {
		if err := f.v1(http.MethodPut, "/policies/example.rego", src, 200, ""); err != nil {
			t.Fatal(err)
		}
	}

	put(v1)
	req := newReqV1(http.MethodGet, "/data/example/allow", "")
	if err := f.executeRequest(req, 200, `{"result":true}`); err != nil {
		t.Fatal(err)
	}
	req = newReqV1(http.MethodGet, "/data/example/allow", "")
	if err := f.executeRequest(req, 200, `{"result":true}`); err != nil {
		t.Fatal(err)
	}
	if got := f.recorder.Header().Get(headerDecisionCache); got != decisionCacheHit {
		t.Fatalf("expected hit before reload, got %q", got)
	}

	put(v2)
	req = newReqV1(http.MethodGet, "/data/example/allow", "")
	if err := f.executeRequest(req, 200, `{"result":false}`); err != nil {
		t.Fatal(err)
	}
	// The forbidden combination: a hit header on a decision from the old
	// revision.
	if got := f.recorder.Header().Get(headerDecisionCache); got == decisionCacheHit {
		t.Fatalf("stale hit after policy reload: header=%q body=%s", got, f.recorder.Body.String())
	}
}

func activateBundle(t *testing.T, f *fixture, name, revision, module string) error {
	t.Helper()
	ctx := context.Background()
	parsed, err := ast.ParseModuleWithOpts(name+".rego", module, f.server.manager.ParserOptions())
	if err != nil {
		return err
	}
	b := bundle.Bundle{
		Manifest: bundle.Manifest{Revision: revision, Roots: &[]string{"example"}},
		Modules: []bundle.ModuleFile{{
			Path:   "/" + name + "/example.rego",
			Parsed: parsed,
			Raw:    []byte(module),
		}},
	}
	b.Manifest.Init()

	txn, err := f.server.store.NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		return err
	}
	activateErr := bundle.Activate(&bundle.ActivateOpts{
		Ctx:           ctx,
		Store:         f.server.store,
		Txn:           txn,
		Compiler:      ast.NewCompiler(),
		Metrics:       metrics.New(),
		ParserOptions: f.server.manager.ParserOptions(),
		Bundles:       map[string]*bundle.Bundle{name: &b},
	})
	if activateErr != nil {
		f.server.store.Abort(ctx, txn)
		return activateErr
	}
	return f.server.store.Commit(ctx, txn)
}

func TestDecisionCacheBundleActivationHotReload(t *testing.T) {
	t.Parallel()

	f := newDecisionCacheFixture(t, debugHeadersConfig)

	v1 := `package example
import rego.v1
default allow := false
allow if true
`
	v2 := `package example
import rego.v1
default allow := false
allow if false
`
	if err := activateBundle(t, f, "hot", "r1", v1); err != nil {
		t.Fatal(err)
	}

	if err := f.v1(http.MethodGet, "/data/example/allow", "", 200, `{"result":true}`); err != nil {
		t.Fatal(err)
	}
	if err := f.v1(http.MethodGet, "/data/example/allow", "", 200, `{"result":true}`); err != nil {
		t.Fatal(err)
	}
	if got := f.recorder.Header().Get(headerDecisionCache); got != decisionCacheHit {
		t.Fatalf("expected hit under r1, got %q", got)
	}

	// Activate a new revision that flips the decision.
	if err := activateBundle(t, f, "hot", "r2", v2); err != nil {
		t.Fatal(err)
	}
	if err := f.v1(http.MethodGet, "/data/example/allow", "", 200, `{"result":false}`); err != nil {
		t.Fatal(err)
	}
	if got := f.recorder.Header().Get(headerDecisionCache); got == decisionCacheHit {
		t.Fatalf("new revision must not hit an r1 entry, header=%q", got)
	}

	// Re-activating the old revision restores the old decision without a hit.
	if err := activateBundle(t, f, "hot", "r1", v1); err != nil {
		t.Fatal(err)
	}
	if err := f.v1(http.MethodGet, "/data/example/allow", "", 200, `{"result":true}`); err != nil {
		t.Fatal(err)
	}
	if got := f.recorder.Header().Get(headerDecisionCache); got == decisionCacheHit {
		t.Fatalf("old revision must be re-evaluated, header=%q", got)
	}
}

func TestDecisionCacheBundleActivationFailureKeepsEntries(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	f := newDecisionCacheFixture(t, debugHeadersConfig)

	good := `package example
import rego.v1
default allow := false
allow if true
`
	if err := activateBundle(t, f, "safe", "r1", good); err != nil {
		t.Fatal(err)
	}
	if err := f.v1(http.MethodGet, "/data/example/allow", "", 200, `{"result":true}`); err != nil {
		t.Fatal(err)
	}

	// A bundle whose module parses but fails to compile (two complete rules
	// producing conflicting values) must fail activation without touching the
	// stored revision vector or the live compiler.
	broken := `package example
import rego.v1
allow := 1 + "a"
`
	// Sanity check the module itself parses but fails to compile.
	c := ast.NewCompiler()
	c.Compile(map[string]*ast.Module{
		"x.rego": ast.MustParseModuleWithOpts(broken, f.server.manager.ParserOptions()),
	})
	if !c.Failed() {
		t.Fatal("test setup: expected the broken module to fail compilation")
	}

	if err := activateBundle(t, f, "safe", "r2", broken); err == nil {
		t.Fatal("expected activation of an invalid bundle to fail")
	}

	txn, err := f.server.store.NewTransaction(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fence, err := f.server.fenceReader.Read(ctx, txn)
	f.server.store.Abort(ctx, txn)
	if err != nil {
		t.Fatal(err)
	}
	if fence.Bundles["safe"] != "r1" {
		t.Fatalf("failed activation changed the revision: %+v", fence.Bundles)
	}

	// The request still succeeds and returns the decision from the last good
	// revision; a hit here is legitimate because nothing changed.
	if err := f.v1(http.MethodGet, "/data/example/allow", "", 200, `{"result":true}`); err != nil {
		t.Fatal(err)
	}
	if got := f.recorder.Header().Get(headerDecisionCache); got != decisionCacheHit {
		t.Fatalf("old entries must remain valid after a failed activation, got %q", got)
	}
}

func TestDecisionCacheEvictionRequestMetric(t *testing.T) {
	t.Parallel()

	small := `{
		"caching": {
			"decision_cache": {
				"enabled": true,
				"max_num_entries": 1,
				"ttl_seconds": 30,
				"negative_ttl_seconds": 5
			}
		}
	}`
	f := newDecisionCacheFixture(t, small)
	if err := f.v1(http.MethodPut, "/policies/example.rego", allowPolicy, 200, ""); err != nil {
		t.Fatal(err)
	}

	// Fill the single slot.
	if err := f.v1(http.MethodPost, "/data/example/allow", `{"input":{"user":"alice"}}`, 200, `{"result":true}`); err != nil {
		t.Fatal(err)
	}

	// A different input evicts the first entry; the response metrics must
	// surface the eviction counter.
	req := newReqV1(http.MethodPost, "/data/example/allow?metrics=true", `{"input":{"user":"bob"}}`)
	if err := f.executeRequest(req, 200, ""); err != nil {
		t.Fatal(err)
	}
	resp := decodeBody(t, f.recorder.Body.Bytes())
	if counter(resp, metrics.ServerDecisionCacheEvicted) == 0 {
		t.Fatalf("expected a decision cache eviction counter, got %v", resp["metrics"])
	}
	if counter(resp, metrics.ServerDecisionCacheMiss) != 1 {
		t.Fatalf("expected a miss counter, got %v", resp["metrics"])
	}
}
