// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package ledgerplugin

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/v1/plugins/logs"
	"github.com/open-policy-agent/opa/v1/plugins/logs/ledger"
)

func TestFactoryValidateDefaults(t *testing.T) {
	t.Parallel()
	f := &Factory{}
	// A directory is required unless persistence defaults are wired through a
	// manager; here the explicit directory path is the supported mode.
	raw := []byte(`{"directory":"` + t.TempDir() + `"}`)
	cfgAny, err := f.Validate(nil, raw)
	if err != nil {
		t.Fatal(err)
	}
	cfg := cfgAny.(Config)
	if cfg.Algorithm != ledger.AlgHS256 {
		t.Fatalf("default algorithm = %q", cfg.Algorithm)
	}
	if cfg.MaxRecordsPerSegment != 10_000 || cfg.DiskLimitMB != 1024 {
		t.Fatalf("defaults not injected: %+v", cfg)
	}
}

func TestFactoryValidateRejectsBadConfig(t *testing.T) {
	t.Parallel()
	f := &Factory{}
	if _, err := f.Validate(nil, []byte(`{"algorithm":"nope"}`)); err == nil {
		t.Fatal("expected unknown algorithm rejection")
	}
	if _, err := f.Validate(nil, []byte(`{}`)); err == nil {
		t.Fatal("expected missing directory rejection when no manager")
	}
}

func TestPluginRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgAny, err := (&Factory{}).Validate(nil, []byte(`{"directory":"`+dir+`","max_records_per_segment":3}`))
	if err != nil {
		t.Fatal(err)
	}
	p := (&Factory{}).New(nil, cfgAny).(*Plugin)
	if err := p.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Stop(t.Context()) })

	ctx := t.Context()
	for i := range 7 {
		var input any = map[string]any{"user": "alice", "secret": "do-not-leak"}
		var result any = map[string]any{"allow": i%2 == 0}
		event := logs.EventV1{
			DecisionID: string(rune('a'+i)) + "-decision",
			Timestamp:  time.Now().UTC(),
			Path:       "/example/allow",
			Revision:   "rev-42",
			Input:      &input,
			Result:     &result,
			Masked:     []string{"/input/secret"},
			Metrics:    map[string]any{"timer_rego_query_eval_ns": float64(1234 + i)},
		}
		if err := p.Log(ctx, event); err != nil {
			t.Fatalf("log %d: %v", i, err)
		}
	}
	p.Stop(ctx)

	// The raw sensitive input must never be written.
	paths, err := filepath.Glob(filepath.Join(dir, "segment-*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) < 2 {
		t.Fatalf("expected rotation, got %d segments", len(paths))
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if contains(raw, "do-not-leak") {
			t.Fatalf("sensitive input leaked into %s", path)
		}
	}

	// The ledger verifies offline.
	key, err := os.ReadFile(filepath.Join(dir, "ledger.key"))
	if err != nil {
		t.Fatal(err)
	}
	report, err := ledger.VerifyDirectories([]string{dir}, ledger.VerifyOptions{HMACKey: key})
	if err != nil {
		t.Fatal(err)
	}
	if !report.OK {
		t.Fatalf("verification failed: %+v", report.FirstError)
	}
	if report.ConfirmedRecords != 7 {
		t.Fatalf("confirmed = %d, want 7", report.ConfirmedRecords)
	}

	// A record carries the required fields: decision id, time, revision,
	// input digest, result, and evaluation latency.
	first := paths[0]
	lines, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	var header, rec struct {
		Payload json.RawMessage `json:"payload"`
	}
	rest := splitLines(lines)
	if err := json.Unmarshal(rest[1], &rec); err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(rec.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"decision_id", "timestamp", "revision", "input_digest", "result", "latency_ns"} {
		if _, ok := payload[field]; !ok {
			t.Fatalf("record missing %q: %s", field, rec.Payload)
		}
	}
	if payload["input_digest"] == "sha256:input" {
		t.Fatal("input digest not computed")
	}
	_ = header
}

func TestPluginRedactResult(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgAny, err := (&Factory{}).Validate(nil, []byte(`{"directory":"`+dir+`","redact_result":true}`))
	if err != nil {
		t.Fatal(err)
	}
	p := (&Factory{}).New(nil, cfgAny).(*Plugin)
	if err := p.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	var result any = map[string]any{"allow": true, "internal": "secret-result"}
	event := logs.EventV1{
		DecisionID: "redact-1",
		Timestamp:  time.Now().UTC(),
		Result:     &result,
	}
	if err := p.Log(t.Context(), event); err != nil {
		t.Fatal(err)
	}
	p.Stop(t.Context())
	paths, _ := filepath.Glob(filepath.Join(dir, "segment-*.jsonl"))
	raw, _ := os.ReadFile(paths[0])
	if contains(raw, "secret-result") {
		t.Fatal("redact_result did not suppress the result value")
	}
	if !contains(raw, "result_digest") {
		t.Fatal("redacted record should still carry a result digest")
	}
}

func TestPluginLogBeforeStartErrors(t *testing.T) {
	t.Parallel()
	cfgAny, _ := (&Factory{}).Validate(nil, []byte(`{"directory":"`+t.TempDir()+`"}`))
	p := (&Factory{}).New(nil, cfgAny).(*Plugin)
	err := p.Log(t.Context(), logs.EventV1{DecisionID: "x"})
	if err == nil || !errors.Is(err, errLedgerNotStarted) {
		t.Fatalf("expected not-started error, got %v", err)
	}
}

func contains(haystack []byte, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if string(haystack[i:i+len(needle)]) == needle {
				return true
			}
		}
		return false
	})()
}

func splitLines(raw []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, b := range raw {
		if b == '\n' {
			out = append(out, raw[start:i])
			start = i + 1
		}
	}
	if start < len(raw) {
		out = append(out, raw[start:])
	}
	return out
}
