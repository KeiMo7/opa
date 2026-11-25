// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package server

import (
	"context"
	"net/http"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/decisioncache"
	"github.com/open-policy-agent/opa/v1/metrics"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/server/types"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/topdown"
	"github.com/open-policy-agent/opa/v1/topdown/builtins"
	iCache "github.com/open-policy-agent/opa/v1/topdown/cache"
)

// Debug response headers returned when caching.decision_cache.debug_headers is
// enabled.
const (
	headerDecisionCache = "OPA-Decision-Cache"
	headerDecisionFence = "OPA-Decision-Fence"

	decisionCacheHit    = "hit"
	decisionCacheMiss   = "miss"
	decisionCacheBypass = "bypass"
)

// newDecisionCache builds the decision cache from the inter-query cache
// configuration. A disabled or absent decision_cache section leaves the
// server without a cache (nil), preserving the pre-feature behaviour byte for
// byte.
func (s *Server) newDecisionCache(ctx context.Context, cacheConfig *iCache.Config) decisioncache.Cache {
	dc := cacheConfig.DecisionCache
	if dc == nil || !dc.Enabled {
		return nil
	}

	cfg := &decisioncache.Config{
		Enabled:       dc.Enabled,
		MaxNumEntries: derefInt(dc.MaxNumEntries),
		MaxSizeBytes:  derefInt64(dc.MaxSizeBytes),
		TTL:           time.Duration(derefInt64(dc.TTLSeconds)) * time.Second,
		NegativeTTL:   time.Duration(derefInt64(dc.NegativeTTL)) * time.Second,
		DebugHeaders:  dc.DebugHeaders,
	}
	cache := decisioncache.New(ctx, cfg)
	return cache
}

func derefInt(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

func derefInt64(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

// updateDecisionCacheConfig maps a reconfigured caching config onto the
// decision cache. The inter-query builtin caches are updated separately and
// are never reset here.
func (s *Server) updateDecisionCacheConfig(cacheConfig *iCache.Config) {
	dc := cacheConfig.DecisionCache

	if s.decisionCache == nil {
		// A server booted without the cache can pick it up on the first
		// Reconfigure that enables it.
		if dc != nil && dc.Enabled {
			s.decisionCache = s.newDecisionCache(context.Background(), cacheConfig)
		}
		return
	}

	if dc == nil {
		s.decisionCache.UpdateConfig(&decisioncache.Config{Enabled: false, Now: time.Now})
		return
	}

	cfg := &decisioncache.Config{
		Enabled:       dc.Enabled,
		MaxNumEntries: derefInt(dc.MaxNumEntries),
		MaxSizeBytes:  derefInt64(dc.MaxSizeBytes),
		TTL:           time.Duration(derefInt64(dc.TTLSeconds)) * time.Second,
		NegativeTTL:   time.Duration(derefInt64(dc.NegativeTTL)) * time.Second,
		DebugHeaders:  dc.DebugHeaders,
	}
	s.decisionCache.UpdateConfig(cfg)
}

// decisionCacheEnabled reports whether a usable decision cache exists and is
// not in the disabled state.
func (s *Server) decisionCacheEnabled() bool {
	return s.decisionCache != nil && s.decisionCache.State() != decisioncache.StateDisabled
}

// readFence reads the fence inside the request's read transaction. A
// non-NotFound error degrades the cache and the request is evaluated
// directly; NotFound conditions are treated as an empty vector by the reader.
// It must only be called when a decision cache is present.
func (s *Server) readFence(ctx context.Context, txn storage.Transaction) (decisioncache.Fence, bool) {
	fence, err := s.fenceReader.Read(ctx, txn)
	if err != nil {
		s.decisionCache.SetState(decisioncache.StateDegraded)
		s.manager.Logger().Debug("decision cache fence read failed, degrading to direct evaluation: %v", err)
		return decisioncache.Fence{}, false
	}
	if s.decisionCache.State() == decisioncache.StateDegraded {
		s.decisionCache.SetState(decisioncache.StateEnabled)
	}
	return fence, true
}

// bypassDecisionCache decides whether a /v1/data request must skip the cache.
// Any of explain, instrumentation, rule labels or strict builtin errors forces
// a bypass; so does a reachable nondeterministic built-in or a wasm resolver.
func (s *Server) bypassDecisionCache(
	explainMode types.ExplainModeV1,
	includeInstrumentation, includeRuleLabels, strictBuiltinErrors bool,
	fence decisioncache.Fence,
	urlPath string,
) bool {
	if explainMode != types.ExplainOffV1 || includeInstrumentation || includeRuleLabels || strictBuiltinErrors {
		return true
	}

	if len(s.manager.GetWasmResolvers()) > 0 {
		return true
	}

	nondeterministic, err := s.ndChecker.HasNondeterministicBuiltin(s.getCompiler(), fence.Digest, urlPath)
	if err != nil {
		s.manager.Logger().Debug("decision cache nondeterminism check failed, bypassing: %v", err)
	}
	return nondeterministic
}

// policyMayProduceResponseMetadata reports whether the policy reachable from
// urlPath uses a custom (wrapping-project) built-in, the only mechanism that
// can populate response metadata. Such decisions must not be retained.
func (s *Server) policyMayProduceResponseMetadata(fence decisioncache.Fence, urlPath string) bool {
	custom, err := s.ndChecker.HasCustomBuiltin(s.getCompiler(), fence.Digest, urlPath)
	if err != nil {
		s.manager.Logger().Debug("decision cache custom-builtin check failed, skipping storage: %v", err)
		return true
	}
	return custom
}

// writeDebugHeaders adds the decision cache debug headers when enabled.
func (s *Server) writeDebugHeaders(w http.ResponseWriter, fence decisioncache.Fence, outcome string) {
	cfg := s.decisionCache.Config()
	if !cfg.DebugHeaders {
		return
	}
	w.Header().Set(headerDecisionCache, outcome)
	if fence.Digest != "" {
		summary := fence.Digest
		if len(summary) > 12 {
			summary = summary[:12]
		}
		w.Header().Set(headerDecisionFence, summary)
	}
}

// recordDecisionCacheMetric increments the request-scoped counter; the cache
// keeps its own aggregate Stats independently.
func recordDecisionCacheMetric(m metrics.Metrics, name string) {
	if m == nil {
		return
	}
	m.Counter(name).Incr()
}

// recordEvictionMetric surfaces evictions that happened while serving the
// request as the request-scoped ServerDecisionCacheEvicted counter. The cache
// tracks its cumulative count; this reports only the delta.
func (s *Server) recordEvictionMetric(m metrics.Metrics, before uint64) {
	if m == nil || s.decisionCache == nil {
		return
	}
	if delta := s.decisionCache.Stats().Evicted - before; delta > 0 {
		m.Counter(metrics.ServerDecisionCacheEvicted).Add(delta)
	}
}

// cacheKey builds the decision cache key for a path, canonical input and
// fence.
func cacheKey(urlPath, inputKey string, fence decisioncache.Fence) decisioncache.Key {
	return decisioncache.Key{Path: urlPath, Input: inputKey, Fence: fence.Digest}
}

// canonicalInputKey canonicalizes raw request input into the stable Input
// component of a cache key. The second return value is false when the input
// cannot be canonicalized, in which case the caller must bypass the cache.
func canonicalInputKey(raw []byte) (string, bool) {
	key, err := decisioncache.CanonicalInput(raw)
	if err != nil {
		return "", false
	}
	return key, true
}

// canonicalValueKey canonicalizes an already-decoded input value, used by the
// POST data handler whose body is parsed before the transaction opens.
func canonicalValueKey(value any) (string, bool) {
	key, err := decisioncache.CanonicalValue(value)
	if err != nil {
		return "", false
	}
	return key, true
}

// newDecisionEntry converts an evaluation result set into a cache entry bound
// to fence. An empty result set becomes an undefined entry governed by the
// negative TTL.
func (s *Server) newDecisionEntry(fence decisioncache.Fence, rs rego.ResultSet) *decisioncache.Entry {
	cfg := s.decisionCache.Config()
	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	entry := &decisioncache.Entry{
		Fence:    fence,
		StoredAt: now(),
	}

	if len(rs) == 0 {
		entry.Undefined = true
		if cfg.NegativeTTL > 0 {
			entry.ExpiresAt = entry.StoredAt.Add(cfg.NegativeTTL)
		}
		return entry
	}

	entry.Value = rs[0].Expressions[0].Value
	if cfg.TTL > 0 {
		entry.ExpiresAt = entry.StoredAt.Add(cfg.TTL)
	}
	return entry
}

// applyEntryToResult fills a DataResponseV1 from a cache entry. The entry's
// value is copied by the cache before it reaches here, so callers cannot
// mutate stored state. Undefined entries leave Result nil, mirroring an empty
// evaluation result set.
func applyEntryToResult(result *types.DataResponseV1, entry *decisioncache.Entry) {
	if entry.Undefined {
		return
	}
	value := entry.Value
	result.Result = &value
}

// decisionCacheStatus maps the cache outcome to a debug header value and the
// request metric that must be recorded.
func decisionCacheStatus(fromCache, bypassed bool) (header string, metric string) {
	switch {
	case bypassed:
		return decisionCacheBypass, metrics.ServerDecisionCacheBypass
	case fromCache:
		return decisionCacheHit, metrics.ServerDecisionCacheHit
	default:
		return decisionCacheMiss, metrics.ServerDecisionCacheMiss
	}
}

// evalDataGet runs the prepared-query preparation (using the existing
// preparedEvalQueries cache) and evaluation for a GET /v1/data request. It
// contains the exact code path the handler used before the decision cache was
// introduced, so bypassed and disabled requests behave identically.
func (s *Server) evalDataGet(
	ctx context.Context,
	txn storage.Transaction,
	input ast.Value,
	urlPath string,
	strictBuiltinErrors, includeInstrumentation bool,
	buf *topdown.BufferTracer,
	m metrics.Metrics,
	ndbCache builtins.NDBCache,
) (rego.ResultSet, *topdown.EvaluatedRuleTracker, error) {
	pqID := "v1DataGet::"
	if strictBuiltinErrors {
		pqID += "strict-builtin-errors::"
	}
	pqID += urlPath
	preparedQuery, ok := s.getCachedPreparedEvalQuery(pqID, m)
	if !ok {
		opts := []func(*rego.Rego){
			rego.Compiler(s.getCompiler()),
			rego.Store(s.store),
		}

		for _, r := range s.manager.GetWasmResolvers() {
			for _, entrypoint := range r.Entrypoints() {
				opts = append(opts, rego.Resolver(entrypoint, r))
			}
		}

		r, err := s.makeRego(ctx, strictBuiltinErrors, txn, input, urlPath, m, includeInstrumentation, buf, opts)
		if err != nil {
			return nil, nil, err
		}

		pq, err := r.PrepareForEval(ctx)
		if err != nil {
			return nil, nil, err
		}
		preparedQuery = &pq
		s.preparedEvalQueries.Insert(pqID, preparedQuery)
	}

	tracker := newEvaluatedRuleTracker()
	evalOpts := []rego.EvalOption{
		rego.EvalTransaction(txn),
		rego.EvalParsedInput(input),
		rego.EvalMetrics(m),
		rego.EvalQueryTracer(buf),
		rego.EvalInterQueryBuiltinCache(s.interQueryBuiltinCache),
		rego.EvalInterQueryBuiltinValueCache(s.interQueryBuiltinValueCache),
		rego.EvalInstrument(includeInstrumentation),
		rego.EvalNDBuiltinCache(ndbCache),
		rego.EvalEvaluatedRuleTracker(tracker),
	}

	rs, err := preparedQuery.Eval(ctx, evalOpts...)
	return rs, tracker, err
}

// evalDataPost runs the prepared-query preparation and evaluation for a POST
// /v1/data request. It mirrors the legacy handler code path exactly so
// bypassed and disabled requests behave unchanged.
func (s *Server) evalDataPost(
	ctx context.Context,
	txn storage.Transaction,
	input ast.Value,
	urlPath string,
	strictBuiltinErrors, includeInstrumentation bool,
	buf *topdown.BufferTracer,
	m metrics.Metrics,
	ndbCache builtins.NDBCache,
	respMetadata map[string]any,
	reqMetadata map[string]any,
) (rego.ResultSet, *topdown.EvaluatedRuleTracker, error) {
	pqID := "v1DataPost::"
	if strictBuiltinErrors {
		pqID = "v1DataPost::strict-builtin-errors::"
	}
	pqID += urlPath
	preparedQuery, ok := s.getCachedPreparedEvalQuery(pqID, m)
	if !ok {
		opts := []func(*rego.Rego){
			rego.Compiler(s.getCompiler()),
			rego.Store(s.store),
		}

		// Set resolvers on the base Rego object to avoid having them get
		// re-initialized, and to propagate them to the prepared query.
		for _, r := range s.manager.GetWasmResolvers() {
			for _, entrypoint := range r.Entrypoints() {
				opts = append(opts, rego.Resolver(entrypoint, r))
			}
		}

		r, err := s.makeRego(ctx, strictBuiltinErrors, txn, input, urlPath, m, includeInstrumentation, buf, opts)
		if err != nil {
			return nil, nil, err
		}

		pq, err := r.PrepareForEval(ctx)
		if err != nil {
			return nil, nil, err
		}
		preparedQuery = &pq
		s.preparedEvalQueries.Insert(pqID, preparedQuery)
	}

	tracker := newEvaluatedRuleTracker()
	evalOpts := []rego.EvalOption{
		rego.EvalTransaction(txn),
		rego.EvalParsedInput(input),
		rego.EvalMetrics(m),
		rego.EvalQueryTracer(buf),
		rego.EvalInterQueryBuiltinCache(s.interQueryBuiltinCache),
		rego.EvalInterQueryBuiltinValueCache(s.interQueryBuiltinValueCache),
		rego.EvalInstrument(includeInstrumentation),
		rego.EvalNDBuiltinCache(ndbCache),
		rego.EvalResponseMetadata(respMetadata),
		rego.EvalEvaluatedRuleTracker(tracker),
	}

	if reqMetadata != nil {
		evalOpts = append(evalOpts, rego.EvalRequestMetadata(reqMetadata))
	}

	rs, err := preparedQuery.Eval(ctx, evalOpts...)
	return rs, tracker, err
}
