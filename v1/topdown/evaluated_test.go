// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package topdown_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/storage"
	inmem "github.com/open-policy-agent/opa/v1/storage/inmem/test"
	"github.com/open-policy-agent/opa/v1/topdown"
)

func TestEvaluatedRuleTracker(t *testing.T) {
	t.Run("nil tracker is safe", func(*testing.T) {
		var tracker *topdown.EvaluatedRuleTracker
		tracker.Record(&ast.Rule{})
	})

	t.Run("no annotation set is a no-op", func(t *testing.T) {
		tracker := &topdown.EvaluatedRuleTracker{}
		tracker.Record(&ast.Rule{})
		if len(tracker.Labels) != 0 {
			t.Fatalf("expected 0 label sets, got %d", len(tracker.Labels))
		}
	})
}

func TestEvaluatedRuleLabelsScopes(t *testing.T) {
	tests := []struct {
		note    string
		module  string
		modules map[string]string
		query   string
		input   string
		exp     []map[string]any
	}{
		{
			note: "rule scope labels",
			module: `package test

# METADATA
# labels:
#   severity: high
#   team: security
allow if input.role == "admin"
`,
			query: "data.test.allow",
			exp: []map[string]any{
				{"severity": "high", "team": "security"},
			},
		},
		{
			note: "document scope labels apply to all rules in document",
			module: `package test

# METADATA
# scope: document
# labels:
#   component: authz
allow if input.role == "admin"

allow if input.role == "superuser"
`,
			query: "data.test.allow",
			exp: []map[string]any{
				{"component": "authz"},
			},
		},
		{
			note: "rule and document scope combine",
			module: `package test

# METADATA
# scope: document
# labels:
#   component: authz

# METADATA
# labels:
#   severity: high
allow if input.role == "admin"

# METADATA
# labels:
#   severity: low
allow if input.role == "viewer"
`,
			query: "data.test.allow",
			exp: []map[string]any{
				{"component": "authz", "severity": "high"},
			},
		},
		{
			note: "no labels when rule not satisfied",
			module: `package test

# METADATA
# labels:
#   severity: high
allow if input.role == "admin"
`,
			query: "data.test.allow",
			input: `{"role": "guest"}`,
			exp:   nil,
		},
		{
			note: "multiple rules each contribute labels",
			module: `package test

# METADATA
# labels:
#   id: allow-admin
allow if input.role == "admin"

# METADATA
# labels:
#   id: allow-viewer
allow if input.role == "viewer"
`,
			query: "data.test.allow",
			exp: []map[string]any{
				{"id": "allow-admin"},
			},
		},
		{
			note: "package scope labels inherited by rules",
			module: `# METADATA
# scope: package
# labels:
#   service: auth
package test

# METADATA
# labels:
#   severity: high
allow if input.role == "admin"
`,
			query: "data.test.allow",
			exp: []map[string]any{
				{"service": "auth", "severity": "high"},
			},
		},
		{
			note: "package and document and rule scope all combine",
			module: `# METADATA
# scope: package
# labels:
#   service: auth
package test

# METADATA
# scope: document
# labels:
#   component: authz

# METADATA
# labels:
#   severity: high
allow if input.role == "admin"
`,
			query: "data.test.allow",
			exp: []map[string]any{
				{"service": "auth", "component": "authz", "severity": "high"},
			},
		},
		{
			note: "inner scope wins on conflicting keys",
			module: `# METADATA
# scope: package
# labels:
#   severity: low
#   service: auth
package test

# METADATA
# scope: document
# labels:
#   severity: medium

# METADATA
# labels:
#   severity: high
allow if input.role == "admin"
`,
			query: "data.test.allow",
			exp: []map[string]any{
				{"service": "auth", "severity": "high"},
			},
		},
		{
			note: "both rules fire, both severities collected",
			module: `package test

# METADATA
# labels:
#   severity: high
reasons contains "admin" if "admin" in input.roles

# METADATA
# labels:
#   severity: low
reasons contains "viewer" if "viewer" in input.roles
`,
			query: "data.test.reasons",
			input: `{"roles": ["admin", "viewer"]}`,
			exp: []map[string]any{
				{"severity": "high"},
				{"severity": "low"},
			},
		},
		{
			note: "identical merged labels across rules are deduplicated",
			module: `# METADATA
# scope: package
# labels:
#   service: auth
package test

# METADATA
# labels:
#   severity: low
reasons contains "admin" if "admin" in input.roles

# METADATA
# labels:
#   severity: low
reasons contains "editor" if "editor" in input.roles
`,
			query: "data.test.reasons",
			input: `{"roles": ["admin", "editor"]}`,
			exp: []map[string]any{
				{"service": "auth", "severity": "low"},
			},
		},
		{
			note: "labels kept when a later annotation has none",
			module: `# METADATA
# scope: package
# labels:
#   service: auth
package test

# METADATA
# title: allow admins
allow if input.role == "admin"
`,
			query: "data.test.allow",
			input: `{"role": "admin"}`,
			exp: []map[string]any{
				{"service": "auth"},
			},
		},
		{
			note: "subpackages scope labels inherited by rules in child packages",
			modules: map[string]string{
				"parent": `# METADATA
# scope: subpackages
# labels:
#   org: acme
package test
`,
				"child": `package test.authz

# METADATA
# labels:
#   severity: high
allow if input.role == "admin"
`,
			},
			query: "data.test.authz.allow",
			exp: []map[string]any{
				{"org": "acme", "severity": "high"},
			},
		},
		{
			note: "inner subpackages scope overrides outer subpackages scope",
			modules: map[string]string{
				"root": `# METADATA
# scope: subpackages
# labels:
#   org: acme
#   tier: free
package test
`,
				"mid": `# METADATA
# scope: subpackages
# labels:
#   tier: enterprise
package test.authz
`,
				"leaf": `package test.authz.users

# METADATA
# labels:
#   severity: high
allow if input.role == "admin"
`,
			},
			query: "data.test.authz.users.allow",
			exp: []map[string]any{
				{"org": "acme", "tier": "enterprise", "severity": "high"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.note, func(t *testing.T) {
			modules := make(map[string]*ast.Module)
			if tc.modules != nil {
				for name, src := range tc.modules {
					modules[name] = ast.MustParseModuleWithOpts(src, ast.ParserOptions{ProcessAnnotation: true})
				}
			} else {
				modules["test"] = ast.MustParseModuleWithOpts(tc.module, ast.ParserOptions{ProcessAnnotation: true})
			}
			c := ast.NewCompiler()
			c.Compile(modules)
			if c.Failed() {
				t.Fatal(c.Errors)
			}

			inputStr := tc.input
			if inputStr == "" {
				inputStr = `{"role": "admin"}`
			}
			input := ast.MustParseTerm(inputStr)
			store := inmem.New()
			ctx := t.Context()
			txn := storage.NewTransactionOrDie(ctx, store)
			defer store.Abort(ctx, txn)

			tracker := &topdown.EvaluatedRuleTracker{}
			query := topdown.NewQuery(ast.MustParseBody(tc.query)).
				WithCompiler(c).
				WithStore(store).
				WithTransaction(txn).
				WithInput(input).
				WithEvaluatedRuleTracker(tracker)

			_, err := query.Run(ctx)
			if err != nil {
				t.Fatal(err)
			}

			if diff := cmp.Diff(tc.exp, tracker.Labels, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("unexpected labels (-want, +got):\n%s", diff)
			}
		})
	}
}

func TestEvaluatedRuleProvenance(t *testing.T) {
	module := `package test

allow if input.role == "admin"

deny if input.role == "banned"
`
	m := ast.MustParseModuleWithOpts(module, ast.ParserOptions{ProcessAnnotation: true})
	c := ast.NewCompiler()
	c.Compile(map[string]*ast.Module{"test.rego": m})
	if c.Failed() {
		t.Fatal(c.Errors)
	}

	input := ast.MustParseTerm(`{"role": "admin"}`)
	store := inmem.New()
	ctx := t.Context()
	txn := storage.NewTransactionOrDie(ctx, store)
	defer store.Abort(ctx, txn)

	tracker := &topdown.EvaluatedRuleTracker{}
	query := topdown.NewQuery(ast.MustParseBody("data.test.allow")).
		WithCompiler(c).
		WithStore(store).
		WithTransaction(txn).
		WithInput(input).
		WithEvaluatedRuleTracker(tracker)

	if _, err := query.Run(ctx); err != nil {
		t.Fatal(err)
	}

	rule := tracker.PrimaryFallback("/test/allow")
	if exp, act := "data.test.allow", rule.ID; exp != act {
		t.Errorf("expected rule id %q, got %q", exp, act)
	}
	if exp, act := "data.test", rule.Package; exp != act {
		t.Errorf("expected package %q, got %q", exp, act)
	}
	if rule.Version == "" || rule.Version == topdown.UnversionedPolicyVersion {
		t.Errorf("expected a per-rule version, got %q", rule.Version)
	}

	// Changing the rule's source must change the version, without touching the
	// package or rule id.
	m2 := ast.MustParseModuleWithOpts(strings.Replace(module, `input.role == "admin"`, `input.role == "administrator"`, 1),
		ast.ParserOptions{ProcessAnnotation: true})
	c2 := ast.NewCompiler()
	c2.Compile(map[string]*ast.Module{"test.rego": m2})
	if c2.Failed() {
		t.Fatal(c2.Errors)
	}
	txn2 := storage.NewTransactionOrDie(ctx, store)
	defer store.Abort(ctx, txn2)
	tracker2 := &topdown.EvaluatedRuleTracker{}
	query2 := topdown.NewQuery(ast.MustParseBody("data.test.allow")).
		WithCompiler(c2).
		WithStore(store).
		WithTransaction(txn2).
		WithInput(ast.MustParseTerm(`{"role": "administrator"}`)).
		WithEvaluatedRuleTracker(tracker2)
	if _, err := query2.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if rule := tracker2.PrimaryFallback("/test/allow"); rule.Version == tracker.PrimaryFallback("/test/allow").Version {
		t.Error("expected a changed rule to have a different version")
	}
}

func TestEvaluatedRuleFallbacks(t *testing.T) {
	t.Run("no tracked rules", func(t *testing.T) {
		var tracker *topdown.EvaluatedRuleTracker
		rule := tracker.PrimaryFallback("/http/authz/allow")
		if rule.ID != "data.http.authz.allow" {
			t.Errorf("expected path-derived rule id, got %q", rule.ID)
		}
		if rule.Package != "data.http.authz" {
			t.Errorf("expected path-derived package, got %q", rule.Package)
		}
		if rule.Version != topdown.UnversionedPolicyVersion {
			t.Errorf("expected %q, got %q", topdown.UnversionedPolicyVersion, rule.Version)
		}
	})

	t.Run("no path", func(t *testing.T) {
		rule := (&topdown.EvaluatedRuleTracker{}).PrimaryFallback("")
		if rule.ID != topdown.UnknownRuleID || rule.Package != topdown.UnknownRulePackage {
			t.Errorf("expected placeholders, got %+v", rule)
		}
		if rule.Version != topdown.UnversionedPolicyVersion {
			t.Errorf("expected %q, got %q", topdown.UnversionedPolicyVersion, rule.Version)
		}
	})
}
