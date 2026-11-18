// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package multitenant

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/bundle"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
)

// TenantRuntime bundles everything that belongs to exactly one tenant: an
// independent store, an independent compiler, and a cache of prepared queries.
// Tenants never share a store, so cross-tenant reads of data or policies are
// impossible by construction.
type TenantRuntime struct {
	id       string
	store    storage.Store
	compiler *ast.Compiler

	mu       sync.RWMutex
	closed   bool
	prepared map[string]*preparedEntry
}

type preparedEntry struct {
	query     rego.PreparedEvalQuery
	partial   rego.PreparedPartialQuery
	partialOK bool
	pkg       string
}

// NewTenantRuntime creates a runtime with an empty in-memory store and a
// fresh compiler.
func NewTenantRuntime(tenantID string) *TenantRuntime {
	return &TenantRuntime{
		id:       tenantID,
		store:    inmem.New(),
		compiler: ast.NewCompiler(),
		prepared: map[string]*preparedEntry{},
	}
}

// Store exposes the tenant's store for read/write operations. Callers must
// not pass it to other tenants' runtimes.
func (r *TenantRuntime) Store() storage.Store { return r.store }

// LoadBundle installs a policy bundle into this tenant's store and compiler.
// Previously prepared queries are invalidated; the next evaluation rebuilds
// them. Bundle loading happens outside of any evaluation so a failed load
// never leaves a half-evaluated query behind.
func (r *TenantRuntime) LoadBundle(ctx context.Context, b *bundle.Bundle) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errors.New("tenant runtime is closed")
	}
	txn, err := r.store.NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		return fmt.Errorf("open write transaction: %w", err)
	}
	activate := func() error {
		return bundle.Activate(&bundle.ActivateOpts{
			Ctx:      ctx,
			Store:    r.store,
			Txn:      txn,
			Compiler: r.compiler,
			Bundles:  map[string]*bundle.Bundle{r.id: b},
		})
	}
	if err := activate(); err != nil {
		r.store.Abort(ctx, txn)
		return fmt.Errorf("activate tenant bundle: %w", err)
	}
	if err := r.store.Commit(ctx, txn); err != nil {
		return fmt.Errorf("commit tenant bundle: %w", err)
	}
	// Invalidate every prepared query; their compiler state is stale now.
	for _, e := range r.prepared {
		e.query.Close()
	}
	r.prepared = map[string]*preparedEntry{}
	return nil
}

// LoadModule compiles and stores a single policy module for the tenant.
func (r *TenantRuntime) LoadModule(ctx context.Context, name, module string) error {
	parsed, err := ast.ParseModule(name, module)
	if err != nil {
		return fmt.Errorf("parse module: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errors.New("tenant runtime is closed")
	}
	txn, err := r.store.NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		return err
	}
	compiler := ast.NewCompiler()
	compiler.Compile(map[string]*ast.Module{name: parsed})
	if compiler.Failed() {
		r.store.Abort(ctx, txn)
		return compiler.Errors
	}
	if err := r.store.UpsertPolicy(ctx, txn, name, []byte(module)); err != nil {
		r.store.Abort(ctx, txn)
		return err
	}
	if err := r.store.Commit(ctx, txn); err != nil {
		return err
	}
	r.compiler = compiler
	for _, e := range r.prepared {
		e.query.Close()
	}
	r.prepared = map[string]*preparedEntry{}
	return nil
}

// preparedEval returns a cached prepared query for pkg, building one on first
// use. Prepared queries are safe for concurrent evaluations.
func (r *TenantRuntime) preparedEval(ctx context.Context, pkg string) (rego.PreparedEvalQuery, error) {
	r.mu.RLock()
	if r.closed {
		r.mu.RUnlock()
		return rego.PreparedEvalQuery{}, errors.New("tenant runtime is closed")
	}
	if e, ok := r.prepared[pkg]; ok {
		pq := e.query
		r.mu.RUnlock()
		return pq, nil
	}
	r.mu.RUnlock()

	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.prepared[pkg]; ok {
		return e.query, nil
	}
	rq := rego.New(
		rego.Query("data."+packageToRef(pkg)),
		rego.Store(r.store),
		rego.Compiler(r.compiler),
	)
	pq, err := rq.PrepareForEval(ctx)
	if err != nil {
		return rego.PreparedEvalQuery{}, err
	}
	r.prepared[pkg] = &preparedEntry{query: pq, pkg: pkg}
	return pq, nil
}

// preparedPartial returns a cached prepared partial query for pkg. Partial
// evaluation runs under exactly the same quota machinery as ordinary
// evaluation; the engine semantics are unchanged because only the outer
// context differs.
func (r *TenantRuntime) preparedPartial(ctx context.Context, pkg string) (rego.PreparedPartialQuery, error) {
	r.mu.RLock()
	if r.closed {
		r.mu.RUnlock()
		return rego.PreparedPartialQuery{}, errors.New("tenant runtime is closed")
	}
	if e, ok := r.prepared[pkg]; ok && e.partialOK {
		pq := e.partial
		r.mu.RUnlock()
		return pq, nil
	}
	r.mu.RUnlock()

	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.prepared[pkg]; ok && e.partialOK {
		return e.partial, nil
	}
	rq := rego.New(
		rego.Query("data."+packageToRef(pkg)),
		rego.Store(r.store),
		rego.Compiler(r.compiler),
	)
	pq, err := rq.PrepareForPartial(ctx)
	if err != nil {
		return rego.PreparedPartialQuery{}, err
	}
	e, ok := r.prepared[pkg]
	if !ok {
		e = &preparedEntry{pkg: pkg}
		r.prepared[pkg] = e
	}
	e.partial = pq
	e.partialOK = true
	return pq, nil
}

// Close releases prepared-query resources. In-flight evaluations are not
// interrupted (they hold their own eval context and topdown state).
func (r *TenantRuntime) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	for _, e := range r.prepared {
		e.query.Close()
	}
	r.prepared = nil
}

// packageToRef turns a decision path like "app/authz/allow" into the Rego
// reference form "app.authz.allow".
func packageToRef(pkg string) string {
	return strings.ReplaceAll(pkg, "/", ".")
}

// EvalInput is the policy-level evaluation request.
type EvalInput struct {
	// Package is the decision path under data., e.g. "app/authz/allow".
	Package string
	// Input is the Rego input document. It never leaves the tenant's
	// evaluation: audit records store none of it.
	Input any
	// RequestID is the optional correlation ID for audit.
	RequestID string
}

// EvalPolicy evaluates inp under the tenant's quota. It is the convenience
// entry point that wires [Manager] admission to the rego engine; callers
// needing a different engine use [Manager.Eval] directly with a custom Fn.
func (m *Manager) EvalPolicy(ctx context.Context, tenantID string, rt *TenantRuntime, inp EvalInput) (EvalResult, error) {
	if rt == nil || rt.id != tenantID {
		return EvalResult{}, &Error{TenantID: tenantID, Reason: ReasonUnknownTenant, Message: "tenant runtime does not belong to tenant"}
	}
	pq, err := rt.preparedEval(ctx, inp.Package)
	if err != nil {
		return EvalResult{}, err
	}
	return m.Eval(ctx, tenantID, EvalRequest{
		Package:   inp.Package,
		RequestID: inp.RequestID,
		Fn: func(evalCtx context.Context) (any, error) {
			// No external cancel: rego spawns its own watcher that cancels
			// the topdown Cancel when evalCtx (which carries the tenant
			// deadline) fires. The engine checks that cancel between every
			// expression, and every evaluation gets fresh per-query state, so
			// aborting one cannot pollute another.
			rs, err := pq.Eval(evalCtx, rego.EvalInput(inp.Input))
			if err != nil {
				return nil, err
			}
			if len(rs) == 0 {
				return nil, nil
			}
			return rs[0].Expressions, nil
		},
	})
}

// PartialPolicy runs partial evaluation under the same tenant quota and
// admission path as [EvalPolicy]. The returned value is the engine's native
// *rego.PartialQueries; partial-evaluation semantics are unchanged, only the
// surrounding resource bounds are new.
func (m *Manager) PartialPolicy(ctx context.Context, tenantID string, rt *TenantRuntime, inp EvalInput) (EvalResult, error) {
	if rt == nil || rt.id != tenantID {
		return EvalResult{}, &Error{TenantID: tenantID, Reason: ReasonUnknownTenant, Message: "tenant runtime does not belong to tenant"}
	}
	pq, err := rt.preparedPartial(ctx, inp.Package)
	if err != nil {
		return EvalResult{}, err
	}
	return m.Eval(ctx, tenantID, EvalRequest{
		Package:   inp.Package,
		RequestID: inp.RequestID,
		Fn: func(evalCtx context.Context) (any, error) {
			return pq.Partial(evalCtx, rego.EvalInput(inp.Input))
		},
	})
}
