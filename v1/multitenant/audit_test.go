// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package multitenant

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestAuditRecordsAreTenantScopedAndRetrievable(t *testing.T) {
	m := newTestManager(t, Config{Defaults: testDefaults()})
	ctx := t.Context()
	for _, id := range []string{"A", "B"} {
		if err := m.RegisterTenant(ctx, id, Quota{MaxConcurrent: 2, EvalTimeout: time.Second}); err != nil {
			t.Fatal(err)
		}
	}
	const secret = "super-secret-input-value"

	run := func(tenant, pkg string) {
		t.Helper()
		_, err := m.Eval(ctx, tenant, EvalRequest{
			Package:   pkg,
			RequestID: "req-" + tenant,
			Fn: func(context.Context) (any, error) {
				// The input lives only inside the closure; it must not appear
				// in any audit field.
				_ = map[string]any{"password": secret}
				return "decision", nil
			},
		})
		if err != nil {
			t.Fatalf("eval %s: %v", tenant, err)
		}
	}
	run("A", "a/policy/allow")
	run("A", "a/policy/deny")
	run("B", "b/policy/allow")

	waitUntil(t, func() bool {
		recsA, _ := m.AuditRecords("A")
		recsB, _ := m.AuditRecords("B")
		return len(recsA) == 2 && len(recsB) == 1
	}, "audit records to be delivered asynchronously")
	recsA, err := m.AuditRecords("A")
	if err != nil {
		t.Fatal(err)
	}
	recsB, err := m.AuditRecords("B")
	if err != nil {
		t.Fatal(err)
	}
	if len(recsA) != 2 || len(recsB) != 1 {
		t.Fatalf("audit records leaked across tenants: A=%d B=%d", len(recsA), len(recsB))
	}
	for _, r := range recsA {
		if r.TenantID != "A" {
			t.Fatalf("record with wrong tenant id in A's records: %+v", r)
		}
		if !strings.HasPrefix(r.Package, "a/") {
			t.Fatalf("record locator wrong: %q", r.Package)
		}
		if r.DecisionID == "" || r.RequestID != "req-A" || r.Outcome != "ok" {
			t.Fatalf("record missing locator fields: %+v", r)
		}
		if strings.Contains(r.ErrorMessage, secret) || strings.Contains(r.Package, secret) {
			t.Fatalf("sensitive data found in audit record: %+v", r)
		}
	}
	if recsB[0].Package != "b/policy/allow" {
		t.Fatalf("B record locator wrong: %+v", recsB[0])
	}
	if _, err := m.AuditRecords("unknown"); err != nil {
		t.Fatalf("unknown tenant should return an empty slice, not an error: %v", err)
	}
}

func TestAuditSinkFailureDoesNotBlockEvaluationAndIsRetried(t *testing.T) {
	sink := &flakySink{failing: true}
	m := newTestManager(t, Config{
		Defaults:        testDefaults(),
		Sink:            sink,
		AuditBufferSize: 8,
	})
	ctx := t.Context()

	// Sink is down: evaluations still succeed, and the async layer keeps the
	// records for later delivery.
	for range 5 {
		if _, err := m.Eval(ctx, "A", EvalRequest{Package: "p", Fn: quickFn}); err != nil {
			t.Fatalf("evaluation must not fail when the audit sink is down: %v", err)
		}
	}
	if got := len(sink.snapshot()); got != 0 {
		t.Fatalf("failing sink should have accepted nothing yet, got %d", got)
	}

	// Recover the sink: buffered records are flushed, none lost.
	sink.setFailing(false)
	waitUntil(t, func() bool { return len(sink.snapshot()) == 5 }, "buffered records to be flushed")

	enqueued, dropped := m.AuditHealth()
	if enqueued != 5 || dropped != 0 {
		t.Fatalf("audit health wrong: enqueued=%d dropped=%d", enqueued, dropped)
	}
}

func TestAuditRecordsQuotasAndAdmissionFailures(t *testing.T) {
	m := newTestManager(t, Config{Defaults: testDefaults()})
	ctx := t.Context()
	if err := m.RegisterTenant(ctx, "A", Quota{
		MaxConcurrent: 1, MaxQueued: 0, EvalTimeout: 50 * time.Millisecond,
	}); err != nil {
		t.Fatal(err)
	}
	gate := make(chan struct{})
	started := make(chan struct{})
	go func() {
		_, _ = m.Eval(ctx, "A", EvalRequest{Package: "p/head", Fn: func(c context.Context) (any, error) {
			close(started)
			return blockFn(gate)(c)
		}})
	}()
	<-started
	waitUntil(t, func() bool {
		st, _ := m.Stats("A")
		return st.InFlight == 1
	}, "head evaluation to start")
	_, rejectErr := m.Eval(ctx, "A", EvalRequest{Package: "p/rejected", Fn: quickFn})
	if !AsError(rejectErr, ReasonConcurrency) {
		t.Fatalf("expected rejection, got %v", rejectErr)
	}
	waitUntil(t, func() bool {
		recs, _ := m.AuditRecords("A")
		return len(recs) == 2
	}, "both attempts to be audited")

	recs, _ := m.AuditRecords("A")
	var sawReject bool
	for _, r := range recs {
		if r.Outcome == string(ReasonConcurrency) && r.Package == "p/rejected" {
			sawReject = true
			if r.DecisionID == "" {
				t.Fatal("rejected request has no decision id")
			}
		}
	}
	if !sawReject {
		t.Fatalf("admission rejection was not audited: %+v", recs)
	}
}
