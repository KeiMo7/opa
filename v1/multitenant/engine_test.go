// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package multitenant

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
)

func loadModule(t *testing.T, rt *TenantRuntime, name, module string) {
	t.Helper()
	if err := rt.LoadModule(t.Context(), name, module); err != nil {
		t.Fatalf("LoadModule %s: %v", name, err)
	}
}

// TestCPUBurningPolicyIsAbortedAndOtherTenantsUnaffected covers acceptance
// scenario 一(1/2/4) and 五(2): a pathological policy of one tenant is
// terminated within that tenant's timeout, while another tenant's
// evaluations keep succeeding and the timed-out tenant keeps serving.
func TestCPUBurningPolicyIsAbortedAndOtherTenantsUnaffected(t *testing.T) {
	m := newTestManager(t, Config{Defaults: Defaults{Quota: Quota{
		MaxConcurrent: 4, EvalTimeout: 250 * time.Millisecond, MaxQueued: 2,
	}}})
	ctx := t.Context()
	if err := m.RegisterTenant(ctx, "burn", Quota{MaxConcurrent: 2, EvalTimeout: 250 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	if err := m.RegisterTenant(ctx, "good", Quota{MaxConcurrent: 2, EvalTimeout: 5 * time.Second}); err != nil {
		t.Fatal(err)
	}
	burnRT := NewTenantRuntime("burn")
	goodRT := NewTenantRuntime("good")
	t.Cleanup(burnRT.Close)
	t.Cleanup(goodRT.Close)
	loadModule(t, burnRT, "burn.rego", infiniteLoopModule)
	loadModule(t, goodRT, "good.rego", simpleModule)

	// Concurrent burn attempts are both aborted within their quota.
	errs := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := m.EvalPolicy(ctx, "burn", burnRT, EvalInput{Package: "tenantloop", Input: map[string]any{}})
			errs <- err
		}()
	}
	for i := range 2 {
		select {
		case err := <-errs:
			if !AsError(err, ReasonTimeout) {
				t.Fatalf("burn eval %d: expected timeout abort, got %v", i, err)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("burn eval %d was not aborted in time", i)
		}
	}

	// The good tenant is unaffected while and after the burn happened.
	for i := range 3 {
		res, err := m.EvalPolicy(ctx, "good", goodRT, EvalInput{
			Package: "tenantgood",
			Input:   map[string]any{"user": "alice"},
		})
		if err != nil {
			t.Fatalf("good tenant eval %d failed: %v", i, err)
		}
		if res.Result == nil {
			t.Fatalf("good tenant eval %d returned no result", i)
		}
	}

	// The burn tenant itself is not blacklisted: a well-behaved policy loaded
	// into the same runtime evaluates normally after the abort.
	loadModule(t, burnRT, "fixed.rego", `
package tenantfixed

ok if { input.user == "bob" }
`)
	res, err := m.EvalPolicy(ctx, "burn", burnRT, EvalInput{
		Package: "tenantfixed",
		Input:   map[string]any{"user": "bob"},
	})
	if err != nil {
		t.Fatalf("burn tenant must recover after timeout: %v", err)
	}
	if res.Result == nil {
		t.Fatal("recovered tenant got no result")
	}

	stats, _ := m.Stats("burn")
	if stats.Timeouts != 2 || stats.Completed != 3 {
		t.Fatalf("burn tenant stats wrong: %+v", stats)
	}
}

// TestMemoryHoggingPolicyIsAborted covers 一(1/2): an evaluation that grows
// the heap past the tenant's memory quota is cancelled, and the instance
// stays healthy for other tenants.
func TestMemoryHoggingPolicyIsAborted(t *testing.T) {
	m := newTestManager(t, Config{
		Defaults: Defaults{Quota: Quota{
			MaxConcurrent: 2, EvalTimeout: 10 * time.Second, MemoryLimitBytes: 20 << 20,
		}},
		MemorySampleInterval: 10 * time.Millisecond,
		// Keep the runtime GC aggressive so the test process cannot be
		// OOM-killed before the cooperative guard fires.
		EnableProcessMemoryLimit: true,
		ProcessMemoryLimitBytes:  512 << 20,
	})
	ctx := t.Context()
	hogRT := NewTenantRuntime("hog")
	goodRT := NewTenantRuntime("good")
	t.Cleanup(hogRT.Close)
	t.Cleanup(goodRT.Close)
	loadModule(t, hogRT, "hog.rego", memoryHogModule)
	loadModule(t, goodRT, "good.rego", simpleModule)

	start := time.Now()
	_, err := m.EvalPolicy(ctx, "hog", hogRT, EvalInput{Package: "tenantmem", Input: map[string]any{}})
	if !AsError(err, ReasonMemory) {
		t.Fatalf("expected memory-quota abort, got %v (after %v)", err, time.Since(start))
	}

	// Audit shows the memory outcome and positive observed growth.
	waitUntil(t, func() bool {
		recs, _ := m.AuditRecords("hog")
		return len(recs) == 1
	}, "memory-abort audit record to be delivered")
	recs, err := m.AuditRecords("hog")
	if err != nil || len(recs) != 1 {
		t.Fatalf("audit records: %v (%v)", recs, err)
	}
	if recs[0].Outcome != string(ReasonMemory) || recs[0].HeapGrowthBytes <= 0 {
		t.Fatalf("memory abort not audited correctly: %+v", recs[0])
	}

	// Another tenant evaluates fine right after the abort.
	res, err := m.EvalPolicy(ctx, "good", goodRT, EvalInput{
		Package: "tenantgood",
		Input:   map[string]any{"user": "alice"},
	})
	if err != nil {
		t.Fatalf("good tenant failed after memory abort: %v", err)
	}
	if res.Result == nil {
		t.Fatal("good tenant returned no result after memory abort")
	}
	if st, _ := m.Stats("hog"); st.MemoryAborts != 1 {
		t.Fatalf("memory abort counter wrong: %+v", st)
	}
}

// TestTenantStoresAreFullyIsolated covers 二(4): policies and data of one
// tenant cannot be read through another tenant's runtime.
func TestTenantStoresAreFullyIsolated(t *testing.T) {
	m := newTestManager(t, Config{Defaults: testDefaults()})
	ctx := t.Context()
	rtA := NewTenantRuntime("A")
	rtB := NewTenantRuntime("B")
	t.Cleanup(rtA.Close)
	t.Cleanup(rtB.Close)
	loadModule(t, rtA, "secret.rego", `
package tenantsecret

token := "A-only-token"

allow if { input.ok }
`)
	// Tenant B has no policy for tenantsecret at all: evaluating it through
	// B's runtime yields no result and never touches A's store.
	res, err := m.EvalPolicy(ctx, "B", rtB, EvalInput{Package: "tenantsecret", Input: map[string]any{"ok": true}})
	if err != nil {
		t.Fatalf("undefined decision must be a nil result, not an error: %v", err)
	}
	if res.Result != nil {
		t.Fatalf("tenant B saw tenant A's package content: %v", res.Result)
	}

	// A's data writes stay inside A's store. Policies and data live in
	// separate parts of the inmem store, so write under a data root.
	secretPath := mustPath(t, "/tenant_a_only/secret")
	txn, err := rtA.Store().NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		t.Fatal(err)
	}
	// Add the parent document first; inmem AddOp requires it to exist.
	if err := rtA.Store().Write(ctx, txn, storage.AddOp, mustPath(t, "/tenant_a_only"), map[string]any{}); err != nil {
		t.Fatalf("create parent: %v", err)
	}
	if err := rtA.Store().Write(ctx, txn, storage.AddOp, secretPath, map[string]any{"only": "A"}); err != nil {
		t.Fatalf("write tenant data: %v", err)
	}
	if err := rtA.Store().Commit(ctx, txn); err != nil {
		t.Fatal(err)
	}
	txnB, err := rtB.Store().NewTransaction(ctx)
	if err != nil {
		t.Fatal(err)
	}
	val, rerr := rtB.Store().Read(ctx, txnB, secretPath)
	rtB.Store().Abort(ctx, txnB)
	if rerr == nil {
		t.Fatalf("tenant B read tenant A's data: %v", val)
	}
	if !storage.IsNotFound(rerr) {
		t.Fatalf("expected storage NotFoundErr on cross-tenant read, got %v", rerr)
	}
}

// TestPolicyReloadInvalidatesPreparedQueries ensures a bundle/module update
// is observed by subsequent evaluations without restarting the runtime.
func TestPolicyReloadInvalidatesPreparedQueries(t *testing.T) {
	m := newTestManager(t, Config{Defaults: testDefaults()})
	ctx := t.Context()
	rt := NewTenantRuntime("T")
	t.Cleanup(rt.Close)
	loadModule(t, rt, "p.rego", `
package tenantver

allow := "v1"
`)
	inp := EvalInput{Package: "tenantver", Input: map[string]any{}}
	res, err := m.EvalPolicy(ctx, "T", rt, inp)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(toString(res.Result), "v1") {
		t.Fatalf("expected v1 result, got %v", res.Result)
	}

	loadModule(t, rt, "p.rego", `
package tenantver

allow := "v2"
`)
	res, err = m.EvalPolicy(ctx, "T", rt, inp)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(toString(res.Result), "v2") {
		t.Fatalf("prepared query was not invalidated after reload, got %v", res.Result)
	}
}

// TestDataChangeIsObservedOnNextEvaluation covers 四(2): data changes between
// two evaluations of the same prepared query are observed (incremental
// evaluation behaviour), with both evaluations going through the quota path.
func TestDataChangeIsObservedOnNextEvaluation(t *testing.T) {
	m := newTestManager(t, Config{Defaults: testDefaults()})
	ctx := t.Context()
	rt := NewTenantRuntime("T")
	t.Cleanup(rt.Close)
	loadModule(t, rt, "d.rego", `
package tenantdata

allow if {
	data.tenant_state.flag == "on"
}
`)
	writeFlag := func(v string) {
		t.Helper()
		txn, err := rt.Store().NewTransaction(ctx, storage.WriteParams)
		if err != nil {
			t.Fatal(err)
		}
		if err := rt.Store().Write(ctx, txn, storage.AddOp, mustPath(t, "/tenant_state"),
			map[string]any{"flag": v}); err != nil {
			rt.Store().Abort(ctx, txn)
			t.Fatal(err)
		}
		if err := rt.Store().Commit(ctx, txn); err != nil {
			t.Fatal(err)
		}
	}

	inp := EvalInput{Package: "tenantdata/allow", Input: map[string]any{}}
	writeFlag("off")
	res, err := m.EvalPolicy(ctx, "T", rt, inp)
	if err != nil {
		t.Fatal(err)
	}
	if res.Result != nil {
		t.Fatalf("expected undefined with flag off, got %v", res.Result)
	}
	writeFlag("on")
	res, err = m.EvalPolicy(ctx, "T", rt, inp)
	if err != nil {
		t.Fatal(err)
	}
	if res.Result == nil {
		t.Fatal("second evaluation did not observe the data change")
	}
}

// TestInvalidPolicyIsRejectedCleanly checks that compilation failures never
// reach evaluation and leave the previous good policy in place.
func TestInvalidPolicyIsRejectedCleanly(t *testing.T) {
	rt := NewTenantRuntime("T")
	t.Cleanup(rt.Close)
	loadModule(t, rt, "good.rego", simpleModule)
	err := rt.LoadModule(t.Context(), "bad.rego", "package broken\nallow if {")
	if err == nil {
		t.Fatal("expected parse/compile error for malformed module")
	}
	if _, ok := errors.AsType[ast.Errors](err); !ok {
		t.Fatalf("expected ast.Errors, got %T: %v", err, err)
	}
	m := newTestManager(t, Config{Defaults: testDefaults()})
	res, err := m.EvalPolicy(t.Context(), "T", rt, EvalInput{
		Package: "tenantgood", Input: map[string]any{"user": "alice"},
	})
	if err != nil || res.Result == nil {
		t.Fatalf("previous good policy must remain usable after failed load: %v", err)
	}
}

// TestPartialEvaluationSharesQuotaAndKeepsSemantics covers 四(2): partial
// evaluation keeps its engine semantics while running under the same tenant
// quota (deadline applies, aborts are clean).
func TestPartialEvaluationSharesQuotaAndKeepsSemantics(t *testing.T) {
	m := newTestManager(t, Config{Defaults: Defaults{Quota: Quota{
		MaxConcurrent: 2, EvalTimeout: 2 * time.Second,
	}}})
	ctx := t.Context()
	rt := NewTenantRuntime("P")
	t.Cleanup(rt.Close)
	loadModule(t, rt, "p.rego", `
package tenantpartial

allow if {
	input.user == "alice"
	input.role == "admin"
}
`)
	res, err := m.PartialPolicy(ctx, "P", rt, EvalInput{Package: "tenantpartial"})
	if err != nil {
		t.Fatalf("partial evaluation: %v", err)
	}
	pq, ok := res.Result.(*rego.PartialQueries)
	if !ok {
		t.Fatalf("expected *rego.PartialQueries, got %T", res.Result)
	}
	if len(pq.Queries) == 0 {
		t.Fatal("partial evaluation produced no queries")
	}

	// A partial evaluation under a shorter tenant deadline is still bounded.
	if err := m.SetQuota(ctx, "P", Quota{MaxConcurrent: 1, EvalTimeout: 40 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	gate := make(chan struct{})
	_, perr := m.Eval(ctx, "P", EvalRequest{Package: "tenantpartial", Fn: func(c context.Context) (any, error) {
		return blockFn(gate)(c)
	}})
	if !AsError(perr, ReasonTimeout) {
		t.Fatalf("quota must bound any Fn, got %v", perr)
	}
	// Subsequent partial evaluation still works: no half-state leaked.
	res2, err := m.PartialPolicy(ctx, "P", rt, EvalInput{Package: "tenantpartial"})
	if err != nil {
		t.Fatalf("partial evaluation after abort: %v", err)
	}
	if _, ok := res2.Result.(*rego.PartialQueries); !ok {
		t.Fatalf("partial result type changed after abort: %T", res2.Result)
	}
}

func toString(v any) string {
	return fmt.Sprintf("%v", v)
}

func mustPath(t *testing.T, str string) storage.Path {
	t.Helper()
	p, ok := storage.ParsePath(str)
	if !ok {
		t.Fatalf("invalid storage path %q", str)
	}
	return p
}
