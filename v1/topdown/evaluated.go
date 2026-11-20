// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package topdown

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/open-policy-agent/opa/v1/ast"
)

// UnversionedPolicyVersion is recorded as the policy version of an evaluated
// rule whose source key cannot be determined (for example, because the policy
// was not parsed with source locations). It is deliberately non-empty so that
// decision log consumers can always group events by policy version.
const UnversionedPolicyVersion = "unversioned"

// UnknownRuleID and UnknownRulePackage are the placeholders recorded when a
// decision cannot be attributed to an evaluated rule (for example, because the
// policy was not packaged). They must stay stable so that events remain
// searchable.
const (
	UnknownRuleID      = "unknown"
	UnknownRulePackage = "unknown"
)

// EvaluatedRule identifies a rule that contributed to a decision, together with
// the package it belongs to and a version specific to that rule's source.
type EvaluatedRule struct {
	// ID is the fully qualified reference of the rule, e.g. "data.example.allow".
	ID string `json:"id"`
	// Package is the fully qualified package of the rule, e.g. "data.example".
	Package string `json:"package"`
	// Version is a stable digest of the rule's source (annotations included).
	// It changes whenever that specific rule changes, unlike a global bundle
	// revision, and is never empty.
	Version string `json:"version"`
}

// EvaluatedRuleTracker records labels and provenance of rules evaluated during
// a query.
//
// An AnnotationSet must be set via WithAnnotationSet for the tracker to
// resolve label chains; without it, labels are not collected, but rule
// provenance still is.
type EvaluatedRuleTracker struct {
	Labels []map[string]any
	seen   map[string]struct{}
	rules  map[*ast.Rule]struct{}
	// ordered keeps the first-seen order of evaluated rules so that rule
	// selection for decision logs is deterministic.
	ordered []*ast.Rule
	as      *ast.AnnotationSet
}

// WithAnnotationSet configures the AnnotationSet used to resolve each
// evaluated rule's annotation chain. Typically wired from the compiler.
func (t *EvaluatedRuleTracker) WithAnnotationSet(as *ast.AnnotationSet) *EvaluatedRuleTracker {
	if t != nil {
		t.as = as
	}
	return t
}

// Record records an evaluated rule.
func (t *EvaluatedRuleTracker) Record(rule *ast.Rule) {
	if t == nil || rule == nil {
		return
	}

	if t.rules == nil {
		t.rules = make(map[*ast.Rule]struct{})
	}
	if _, ok := t.rules[rule]; ok {
		return
	}
	t.rules[rule] = struct{}{}
	t.ordered = append(t.ordered, rule)

	if t.as == nil {
		return
	}

	labels, key := t.as.MergedLabels(rule)
	if len(labels) == 0 {
		return
	}
	if t.seen == nil {
		t.seen = make(map[string]struct{})
	}
	if _, dup := t.seen[key]; dup {
		return
	}
	t.seen[key] = struct{}{}
	t.Labels = append(t.Labels, labels)
}

// Primary picks the evaluated rule that best matches the decision path. When
// path is empty or none match, the first evaluated rule is returned. It returns
// nil when no rules were recorded.
func (t *EvaluatedRuleTracker) Primary(path string) *EvaluatedRule {
	if t == nil || len(t.ordered) == 0 {
		return nil
	}

	ref := decisionPathRef(path)

	var fallback *ast.Rule
	for _, rule := range t.ordered {
		if fallback == nil {
			fallback = rule
		}
		if ref == "" || rule.Module == nil || rule.Module.Package == nil {
			continue
		}
		if ruleRef(rule) == ref {
			return evaluatedRule(rule)
		}
	}

	if ref != "" {
		// Secondary match: the first rule in the decision's package. This
		// covers virtual documents produced by several rules and package
		// level queries where no single rule ref matches.
		pkgRef := ref
		if i := lastDot(ref); i >= 0 {
			pkgRef = ref[:i]
		}
		for _, rule := range t.ordered {
			if rule.Module == nil || rule.Module.Package == nil {
				continue
			}
			if rule.Module.Package.Path.String() == pkgRef {
				return evaluatedRule(rule)
			}
		}
	}

	return evaluatedRule(fallback)
}

// PrimaryFallback returns the primary evaluated rule, or a deterministic
// placeholder carrying the decision path when nothing was tracked.
func (t *EvaluatedRuleTracker) PrimaryFallback(path string) EvaluatedRule {
	if r := t.Primary(path); r != nil {
		return *r
	}

	id := UnknownRuleID
	if path != "" {
		id = decisionPathRef(path)
	}

	pkg := UnknownRulePackage
	if i := lastDot(id); i >= 0 {
		pkg = id[:i]
	}

	return EvaluatedRule{ID: id, Package: pkg, Version: UnversionedPolicyVersion}
}

func evaluatedRule(rule *ast.Rule) *EvaluatedRule {
	if rule == nil || rule.Module == nil || rule.Module.Package == nil {
		return &EvaluatedRule{ID: UnknownRuleID, Package: UnknownRulePackage, Version: UnversionedPolicyVersion}
	}

	pkg := rule.Module.Package.Path.String()
	id := ruleRef(rule)

	version := UnversionedPolicyVersion
	if key, ok := rule.SourceKey(); ok {
		version = hex.EncodeToString(key[:])
	} else {
		// The source key is only available for modules parsed with
		// annotations and locations. Hash the rule's textual form as a
		// per-rule fallback; it is scoped to this rule rather than the
		// whole bundle snapshot.
		sum := sha256.Sum256([]byte(rule.String()))
		version = hex.EncodeToString(sum[:8])
	}

	return &EvaluatedRule{ID: id, Package: pkg, Version: version}
}

func ruleRef(rule *ast.Rule) string {
	if rule == nil || rule.Module == nil || rule.Module.Package == nil {
		return UnknownRuleID
	}
	if ref := rule.Ref(); ref != nil {
		return ref.String()
	}
	return UnknownRuleID
}

// decisionPathRef normalizes a decision path (as used in decision logs) into a
// fully qualified rule reference, e.g. "/http/authz/allow" or "kafka/allow"
// become "data.http.authz.allow" and "data.kafka.allow" respectively.
func decisionPathRef(path string) string {
	if path == "" {
		return ""
	}
	p := path
	for len(p) > 0 && p[0] == '/' {
		p = p[1:]
	}
	if len(p) >= 5 && p[:5] == "data." {
		return p
	}
	p = "data." + replaceSlashes(p)
	return p
}

func replaceSlashes(s string) string {
	out := []byte(s)
	for i := range out {
		if out[i] == '/' {
			out[i] = '.'
		}
	}
	return string(out)
}

func lastDot(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '.' {
			return i
		}
	}
	return -1
}

// String returns a compact representation for logging and debugging.
func (r EvaluatedRule) String() string {
	return fmt.Sprintf("%s (package %s, version %s)", r.ID, r.Package, r.Version)
}
