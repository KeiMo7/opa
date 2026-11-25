// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package decisioncache

import (
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
)

func compileModules(t *testing.T, modules map[string]string) *ast.Compiler {
	t.Helper()
	parsed := make(map[string]*ast.Module, len(modules))
	for name, src := range modules {
		module, err := ast.ParseModuleWithOpts(name, src, ast.ParserOptions{RegoVersion: ast.RegoV1})
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		parsed[name] = module
	}
	compiler := ast.NewCompiler()
	if compiler.Compile(parsed); compiler.Failed() {
		t.Fatalf("compile: %v", compiler.Errors)
	}
	return compiler
}

func TestNondeterminismDirectBuiltin(t *testing.T) {
	t.Parallel()

	compiler := compileModules(t, map[string]string{
		"example.rego": `package example

import rego.v1

allow if time.now_ns() > 0
`,
	})

	checker := NewNondeterminismChecker()
	nondeterministic, err := checker.HasNondeterministicBuiltin(compiler, "digest", "example/allow")
	if err != nil {
		t.Fatal(err)
	}
	if !nondeterministic {
		t.Fatal("time.now_ns must force a bypass")
	}
}

func TestNondeterminismTransitiveRule(t *testing.T) {
	t.Parallel()

	compiler := compileModules(t, map[string]string{
		"example.rego": `package example

import rego.v1

allow if fresh

fresh if time.now_ns() > 0
`,
	})

	checker := NewNondeterminismChecker()
	nondeterministic, err := checker.HasNondeterministicBuiltin(compiler, "digest", "example/allow")
	if err != nil {
		t.Fatal(err)
	}
	if !nondeterministic {
		t.Fatal("a nondeterministic builtin in a referenced rule must force a bypass")
	}
}

func TestNondeterminismDeterministicPolicy(t *testing.T) {
	t.Parallel()

	compiler := compileModules(t, map[string]string{
		"example.rego": `package example

import rego.v1

allow if input.user == "alice"
deny contains x if x := input.blocked[_]
`,
	})

	checker := NewNondeterminismChecker()
	for _, path := range []string{"example/allow", "example/deny"} {
		nondeterministic, err := checker.HasNondeterministicBuiltin(compiler, "digest", path)
		if err != nil {
			t.Fatal(err)
		}
		if nondeterministic {
			t.Fatalf("%s is deterministic but was flagged", path)
		}
	}
}

func TestNondeterminismAllRequiredBuiltins(t *testing.T) {
	t.Parallel()

	modules := map[string]string{
		"timenow.rego": "package timenow\nimport rego.v1\np if time.now_ns() > 0\n",
		"rand.rego":    "package randpkg\nimport rego.v1\np if rand.intn(\"x\", 5) >= 0\n",
		"http.rego":    "package httppkg\nimport rego.v1\np if http.send({\"url\": \"http://example.com\", \"method\": \"GET\"}).status == 200\n",
		"uuid.rego":    "package uuidpkg\nimport rego.v1\np if uuid.rfc4122(\"x\") != \"\"\n",
	}

	compiler := compileModules(t, modules)
	checker := NewNondeterminismChecker()

	for path, want := range map[string]bool{
		"timenow/p": true,
		"randpkg/p": true,
		"httppkg/p": true,
		"uuidpkg/p": true,
		"example/x": false,
	} {
		got, err := checker.HasNondeterministicBuiltin(compiler, "digest", path)
		if err != nil {
			// The deterministic/non-existent path must not error either.
			if want {
				t.Fatalf("%s: %v", path, err)
			}
			continue
		}
		if got != want {
			t.Fatalf("%s: got %v want %v", path, got, want)
		}
	}
}

func TestNondeterminismMemoizedPerDigest(t *testing.T) {
	t.Parallel()

	compiler := compileModules(t, map[string]string{
		"example.rego": "package example\nimport rego.v1\nallow if time.now_ns() > 0\n",
	})
	checker := NewNondeterminismChecker()

	first, err := checker.HasNondeterministicBuiltin(compiler, "d1", "example/allow")
	if err != nil {
		t.Fatal(err)
	}
	second, err := checker.HasNondeterministicBuiltin(compiler, "d1", "example/allow")
	if err != nil {
		t.Fatal(err)
	}
	if !first || !second {
		t.Fatal("expected both lookups to report nondeterministic")
	}

	// A different digest gets its own cache entry.
	other, err := checker.HasNondeterministicBuiltin(compiler, "d2", "example/allow")
	if err != nil {
		t.Fatal(err)
	}
	if !other {
		t.Fatal("expected independent lookup for a new digest")
	}
}
