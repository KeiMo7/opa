// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package decisioncache

import (
	"sync"

	"github.com/open-policy-agent/opa/v1/ast"
)

// NondeterminismChecker determines whether the policy reachable from a data
// API path invokes a nondeterministic built-in. Such paths must bypass the
// decision cache because repeated evaluations are allowed to return different
// decisions for the same input and fence.
type NondeterminismChecker struct {
	mtx          sync.RWMutex
	cached       map[cacheKey]bool
	customCached map[customKey]bool
}

type cacheKey struct {
	digest string
	path   string
}

type customKey struct {
	digest string
	path   string
}

// NewNondeterminismChecker returns a checker. The current compiler is supplied
// to each lookup because the plugin manager replaces the compiler on policy
// writes, and holding onto an Init-time compiler would inspect stale rules.
func NewNondeterminismChecker() *NondeterminismChecker {
	return &NondeterminismChecker{
		cached:       map[cacheKey]bool{},
		customCached: map[customKey]bool{},
	}
}

// HasNondeterministicBuiltin reports whether any rule reachable from the
// virtual document at dataPath calls a nondeterministic built-in. The result
// is memoized per (digest, path); the digest changes whenever the policy
// generation changes, invalidating stale decisions. A nil compiler fails safe
// to nondeterministic so the cache is bypassed.
func (n *NondeterminismChecker) HasNondeterministicBuiltin(compiler *ast.Compiler, digest, dataPath string) (bool, error) {
	if n == nil || compiler == nil {
		return true, nil
	}

	key := cacheKey{digest: digest, path: dataPath}

	n.mtx.RLock()
	result, ok := n.cached[key]
	n.mtx.RUnlock()
	if ok {
		return result, nil
	}

	ref, err := stringPathToDataRef(dataPath)
	if err != nil {
		return true, err
	}

	// Collect the closure of rules reachable from the requested document:
	// rules it references, rules those reference, and so on.
	rules := n.reachableRules(compiler, ref)

	nondeterministic := false
	for _, rule := range rules {
		if ruleContainsNondeterministicBuiltin(rule) {
			nondeterministic = true
			break
		}
	}

	n.mtx.Lock()
	n.cached[key] = nondeterministic
	n.mtx.Unlock()

	return nondeterministic, nil
}

// reachableRules returns every rule the evaluation of ref may invoke,
// following virtual-document references transitively.
func (n *NondeterminismChecker) reachableRules(compiler *ast.Compiler, ref ast.Ref) []*ast.Rule {
	seen := map[*ast.Rule]struct{}{}
	queue := append([]*ast.Rule{}, compiler.GetRulesForVirtualDocument(ref)...)

	for len(queue) > 0 {
		rule := queue[0]
		queue = queue[1:]
		if rule == nil {
			continue
		}
		if _, ok := seen[rule]; ok {
			continue
		}
		seen[rule] = struct{}{}

		// Walk the whole rule (head, body and else chain) and follow any
		// reference to another virtual document.
		ast.WalkRefs(rule, func(r ast.Ref) bool {
			for _, next := range compiler.GetRulesForVirtualDocument(r) {
				if _, ok := seen[next]; !ok {
					queue = append(queue, next)
				}
			}
			return false
		})
	}

	rules := make([]*ast.Rule, 0, len(seen))
	for rule := range seen {
		rules = append(rules, rule)
	}
	return rules
}

// ruleContainsNondeterministicBuiltin walks every expression of the rule,
// including its else chain, and reports the first call to a built-in flagged
// as nondeterministic.
func ruleContainsNondeterministicBuiltin(rule *ast.Rule) bool {
	found := false
	ast.WalkExprs(rule, func(expr *ast.Expr) bool {
		if found || !expr.IsCall() {
			return false
		}
		operator := expr.Operator()
		if operator == nil {
			return false
		}
		builtin, ok := ast.BuiltinMap[operator.String()]
		if ok && builtin.IsNondeterministic() {
			found = true
			return true
		}
		return false
	})
	return found
}

// HasCustomBuiltin reports whether any rule reachable from dataPath invokes a
// call that is not a known built-in and not a virtual document. Such calls are
// custom built-ins supplied by wrapping projects, which may populate response
// metadata and therefore cannot have their decisions cached. The result is
// memoized per (digest, path).
func (n *NondeterminismChecker) HasCustomBuiltin(compiler *ast.Compiler, digest, dataPath string) (bool, error) {
	if n == nil || compiler == nil {
		// Fail safe: an unknown policy surface must not be cached.
		return true, nil
	}

	key := customKey{digest: digest, path: dataPath}
	n.mtx.RLock()
	result, ok := n.customCached[key]
	n.mtx.RUnlock()
	if ok {
		return result, nil
	}

	ref, err := stringPathToDataRef(dataPath)
	if err != nil {
		return true, err
	}

	custom := false
	for _, rule := range n.reachableRules(compiler, ref) {
		if ruleContainsCustomCall(compiler, rule) {
			custom = true
			break
		}
	}

	n.mtx.Lock()
	n.customCached[key] = custom
	n.mtx.Unlock()
	return custom, nil
}

// ruleContainsCustomCall reports whether rule calls a function that is
// neither a registered built-in nor a rule managed by the compiler (i.e. a
// wrapping-project custom built-in).
func ruleContainsCustomCall(compiler *ast.Compiler, rule *ast.Rule) bool {
	found := false
	ast.WalkExprs(rule, func(expr *ast.Expr) bool {
		if found || !expr.IsCall() {
			return false
		}
		operator := expr.Operator()
		if operator == nil {
			return false
		}
		name := operator.String()
		if _, isBuiltin := ast.BuiltinMap[name]; isBuiltin {
			return false
		}
		// A reference to another virtual document is handled by the reachable
		// rule closure rather than treated as a custom built-in.
		if len(compiler.GetRulesForVirtualDocument(operator)) > 0 {
			return false
		}
		found = true
		return true
	})
	return found
}

// stringPathToDataRef mirrors the server's path parsing without importing the
// server package (which would create an import cycle).
func stringPathToDataRef(s string) (ast.Ref, error) {
	path, ok := parseEscapedPath(s)
	if !ok {
		return nil, &ast.Error{Code: ast.ParseErr, Message: "invalid data path"}
	}

	ref := make(ast.Ref, 1, 1+len(path))
	ref[0] = ast.DefaultRootDocument
	for _, segment := range path {
		ref = append(ref, ast.InternedTerm(segment))
	}
	return ref, nil
}

func parseEscapedPath(s string) ([]string, bool) {
	if s == "" {
		return nil, true
	}
	var path []string
	current := make([]rune, 0, len(s))
	flush := func() {
		if len(current) > 0 {
			path = append(path, string(current))
			current = current[:0]
		}
	}
	for _, r := range s {
		switch r {
		case '/':
			flush()
		default:
			current = append(current, r)
		}
	}
	flush()
	return path, true
}
