// Copyright 2020 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package logs

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/open-policy-agent/opa/internal/deepcopy"
)

type maskOP string

const (
	maskOPRemove maskOP = "remove"
	maskOPUpsert maskOP = "upsert"

	partInput    = "input"
	partResult   = "result"
	partNDBCache = "nd_builtin_cache"
	// Additional parts that can carry original values and are therefore
	// maskable. They mirror the corresponding EventV1 fields.
	partIntermediateResults = "intermediate_results"
	partMappedResult        = "mapped_result"
	partRequestContext      = "request_context"
	partError               = "error"
	partCustom              = "custom"

	// maskUndefinedDrop drops events when a mask rule targets a path that
	// cannot be applied. maskUndefinedClear instead replaces the targeted part
	// with an empty conservative value.
	maskUndefinedDrop  = "drop"
	maskUndefinedClear = "clear"

	defaultMaskUndefinedPolicy = maskUndefinedDrop
)

var errMaskInvalidObject = errors.New("mask upsert invalid object")

// maskRule is a single erase/upsert operation targeting one event part.
type maskRule struct {
	OP                maskOP `json:"op"`
	Path              string `json:"path"`
	Value             any    `json:"value"`
	escapedParts      []string
	modifyFullObj     bool
	failUndefinedPath bool
}

// part returns the top-level event part this rule applies to.
func (r maskRule) part() string {
	return r.escapedParts[0]
}

type maskRuleSet struct {
	OnRuleError  func(*maskRule, error)
	Rules        []*maskRule
	resultCopied bool
	// otherCopied tracks which non-result parts have been deep copied so a
	// mask never mutates data still referenced by the evaluation result.
	copied map[string]bool
	// UndefinedPolicy selects what happens when a rule cannot be applied.
	UndefinedPolicy string
	// MaskVersion is the effective version of the mask rule set, recorded on
	// the events it masked.
	MaskVersion string
}

func (r maskRule) String() string {
	return "/" + strings.Join(r.escapedParts, "/")
}

type maskRuleOption func(*maskRule) error

func newMaskRule(path string, opts ...maskRuleOption) (*maskRule, error) {
	const (
		defaultOP                = maskOPRemove
		defaultFailUndefinedPath = false
	)

	if len(path) == 0 {
		return nil, errors.New("mask must be non-empty")
	} else if !strings.HasPrefix(path, "/") {
		return nil, errors.New("mask must be slash-prefixed")
	}

	parts := strings.Split(path[1:], "/")

	switch parts[0] {
	case partInput, partResult, partNDBCache,
		partIntermediateResults, partMappedResult,
		partRequestContext, partError, partCustom: // OK
	default:
		return nil, fmt.Errorf("mask prefix not allowed: %v", parts[0])
	}

	escapedParts := make([]string, len(parts))
	for i := range parts {
		_, err := url.PathUnescape(parts[i])
		if err != nil {
			return nil, err
		}

		escapedParts[i] = url.PathEscape(parts[i])
	}

	var modifyFullObj bool
	if len(escapedParts) == 1 {
		modifyFullObj = true
	}

	r := &maskRule{
		OP:                defaultOP,
		Path:              path,
		escapedParts:      escapedParts,
		failUndefinedPath: defaultFailUndefinedPath,
		modifyFullObj:     modifyFullObj,
	}

	for _, opt := range opts {
		if err := opt(r); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func withOP(op maskOP) maskRuleOption {
	return func(r *maskRule) error {
		switch op {
		case maskOPRemove, maskOPUpsert:
			r.OP = op
			return nil
		}
		return fmt.Errorf("mask op is not supported: %s", op)
	}
}

func withValue(val any) maskRuleOption {
	return func(r *maskRule) error {
		r.Value = val
		return nil
	}
}

func withFailUndefinedPath() maskRuleOption {
	return func(r *maskRule) error {
		r.failUndefinedPath = true
		return nil
	}
}

// Mask applies the rule to event. An error is returned when the rule requests
// failures on undefined paths. Undefined targets are otherwise ignored, which
// preserves the historical behavior for callers that apply a single rule.
func (r maskRule) Mask(event *EventV1) error {
	_, err := r.Apply(event)
	return err
}

// Apply applies the rule to event. An error is only returned for structurally
// invalid rules.
func (r maskRule) Apply(event *EventV1) (undefined bool, err error) {
	var maskObj *any     // pointer to event Input|Result|NDBCache object
	var maskObjPtr **any // pointer to the event Input|Result|NDBCache pointer itself

	switch r.part() {
	case partInput:
		if event.Input == nil {
			return r.undefinedOnMissing()
		}
		maskObj = event.Input
		maskObjPtr = &event.Input
	case partResult:
		if event.Result == nil {
			return r.undefinedOnMissing()
		}
		maskObj = event.Result
		maskObjPtr = &event.Result
	case partNDBCache:
		if event.NDBuiltinCache == nil {
			return r.undefinedOnMissing()
		}
		maskObj = event.NDBuiltinCache
		maskObjPtr = &event.NDBuiltinCache
	case partIntermediateResults:
		if event.IntermediateResults == nil {
			return r.undefinedOnMissing()
		}
		var obj any = event.IntermediateResults
		maskObj = &obj
		maskObjPtr = nil
	case partMappedResult:
		if event.MappedResult == nil {
			return r.undefinedOnMissing()
		}
		maskObj = event.MappedResult
		maskObjPtr = &event.MappedResult
	case partCustom:
		if event.Custom == nil {
			return r.undefinedOnMissing()
		}
		// Custom is a map, which is assignable to any without a copy.
		var obj any = event.Custom
		maskObj = &obj
		maskObjPtr = nil
	case partRequestContext:
		return r.maskRequestContext(event)
	case partError:
		return r.maskError(event)
	default:
		return false, fmt.Errorf("illegal path value: %s", r.part())
	}

	switch r.OP {
	case maskOPRemove:
		if r.modifyFullObj {
			switch r.part() {
			case partIntermediateResults:
				event.IntermediateResults = nil
			case partCustom:
				event.Custom = nil
			default:
				*maskObjPtr = nil
			}
		} else {
			if err := r.removeValue(r.escapedParts[1:], maskObj); err != nil {
				if err == errMaskInvalidObject {
					return r.undefinedOnMissing()
				}
				return false, nil
			}
		}

		event.Erased = append(event.Erased, r.String())
	case maskOPUpsert:
		if r.modifyFullObj {
			switch r.part() {
			case partIntermediateResults:
				if m, ok := r.Value.(map[string]any); ok {
					event.IntermediateResults = m
				} else {
					return r.undefinedOnMissing()
				}
			case partCustom:
				if m, ok := r.Value.(map[string]any); ok {
					event.Custom = m
				} else {
					return r.undefinedOnMissing()
				}
			default:
				*maskObjPtr = &r.Value
			}
		} else {
			// A document rooted at an array is addressable too, so dispatch on both
			// container kinds. mkdirp already handles each.
			switch obj := (*maskObj).(type) {
			case map[string]any, []any:
				if err := r.mkdirp(obj, r.escapedParts[1:len(r.escapedParts)], r.Value); err != nil {
					return r.undefinedOnMissing()
				}
			default:
				return r.undefinedOnMissing()
			}
		}

		event.Masked = append(event.Masked, r.String())
	default:
		return false, fmt.Errorf("illegal mask op value: %s", r.OP)
	}

	return false, nil
}

// undefinedOnMissing reports the outcome of a rule that could not be applied.
// When the rule set explicitly requested failures for undefined paths, the
// legacy error is returned so that callers can surface it. Otherwise the miss
// is reported as undefined and the rule set's policy decides what to do.
func (r maskRule) undefinedOnMissing() (bool, error) {
	if r.failUndefinedPath {
		return false, errMaskInvalidObject
	}
	return true, nil
}

// maskRequestContext supports paths under /request_context. The only
// maskable subtree is the selected HTTP request headers object.
func (r maskRule) maskRequestContext(event *EventV1) (bool, error) {
	if event.RequestContext == nil || event.RequestContext.HTTPRequest == nil {
		return r.undefinedOnMissing()
	}

	headers := event.RequestContext.HTTPRequest.Headers
	if headers == nil {
		return r.undefinedOnMissing()
	}

	// Paths are /request_context/http/headers[/<name>...]
	rest := r.escapedParts[1:]
	if len(rest) == 0 {
		switch r.OP {
		case maskOPRemove:
			event.RequestContext = nil
			event.Erased = append(event.Erased, r.String())
		case maskOPUpsert:
			return false, fmt.Errorf("mask upsert not supported at %s", r.String())
		}
		return false, nil
	}

	if len(rest) < 2 || rest[0] != "http" || rest[1] != "headers" {
		return r.undefinedOnMissing()
	}

	// Normalize the headers map to the addressable shape used by the mask
	// engine. HTTP header names are case-insensitive, so resolve the target
	// name against the stored casing before stripping it to a single key.
	var node any = map[string]any{}
	nodeMap := node.(map[string]any)
	for name, values := range headers {
		vals := make([]any, len(values))
		for i := range values {
			vals[i] = values[i]
		}
		nodeMap[name] = vals
	}

	// Rewrite the part that addresses the header name to the stored casing, so
	// that a mask rule using a different casing still matches. Header names
	// are matched by http.CanonicalHeaderKey semantics.
	target := r.escapedParts[3:]
	if len(target) > 0 {
		if stored, ok := resolveHeaderName(nodeMap, target[0]); ok {
			target = append([]string{stored}, target[1:]...)
		}
	}
	switch r.OP {
	case maskOPRemove:
		if len(target) == 0 {
			event.RequestContext.HTTPRequest.Headers = nil
			event.Erased = append(event.Erased, r.String())
			return false, nil
		}
		if err := r.removeValue(target, &node); err != nil {
			if err == errMaskInvalidObject {
				return r.undefinedOnMissing()
			}
			return false, nil
		}
		event.Erased = append(event.Erased, r.String())
	case maskOPUpsert:
		if len(target) == 0 {
			return false, fmt.Errorf("mask upsert not supported at %s", r.String())
		}
		if err := r.mkdirp(node, target, r.Value); err != nil {
			return r.undefinedOnMissing()
		}
		event.Masked = append(event.Masked, r.String())
	default:
		return false, fmt.Errorf("illegal mask op value: %s", r.OP)
	}

	if nodeMap, ok := node.(map[string]any); ok {
		event.RequestContext.HTTPRequest.Headers = headersFromMask(nodeMap)
	}

	return false, nil
}

func headersFromMask(node map[string]any) map[string][]string {
	out := make(map[string][]string, len(node))
	for name, v := range node {
		switch vals := v.(type) {
		case []any:
			ss := make([]string, 0, len(vals))
			for _, s := range vals {
				if str, ok := s.(string); ok {
					ss = append(ss, str)
				}
			}
			out[name] = ss
		case string:
			out[name] = []string{vals}
		}
	}
	return out
}

// resolveHeaderName returns the stored key matching name case-insensitively.
func resolveHeaderName(node map[string]any, name string) (string, bool) {
	if _, ok := node[name]; ok {
		return name, true
	}
	for stored := range node {
		if strings.EqualFold(stored, name) {
			return stored, true
		}
	}
	return "", false
}

func (r maskRule) maskError(event *EventV1) (bool, error) {
	if event.Error == nil {
		return r.undefinedOnMissing()
	}

	// Only whole-error operations are supported: error text is opaque and
	// not addressable by JSON Pointer.
	if !r.modifyFullObj {
		return r.undefinedOnMissing()
	}

	switch r.OP {
	case maskOPRemove:
		event.Error = nil
		event.Erased = append(event.Erased, r.String())
	case maskOPUpsert:
		event.Error = fmt.Errorf("%v", r.Value)
		event.Masked = append(event.Masked, r.String())
	default:
		return false, fmt.Errorf("illegal mask op value: %s", r.OP)
	}

	return false, nil
}

func (maskRule) removeValue(p []string, nodePtr *any) error {
	if len(p) == 0 {
		return nil
	}

	node := *nodePtr

	// the key or index to be removed
	targetKey := p[len(p)-1]

	// nodeParent stores the parent of the node to be modified during the
	// removal, this is only needed when the node is a slice
	var nodeParent any
	// nodeKey stores the key of the node to be modified relative to the parent
	var nodeKey string

	// Walk to the parent of the target to be removed, the nodeParent is cached
	// support removing of slice values
	for i := range len(p) - 1 {
		switch v := node.(type) {
		case map[string]any:
			child, ok := v[p[i]]
			if !ok {
				return errMaskInvalidObject
			}
			nodeParent = v
			nodeKey = p[i]
			node = child

		case []any:
			index, err := strconv.Atoi(p[i])
			if err != nil || index < 0 || index >= len(v) {
				return errMaskInvalidObject
			}
			nodeParent = v
			nodeKey = p[i]
			node = v[index]

		default:
			return errMaskInvalidObject
		}
	}

	switch v := node.(type) {
	case map[string]any:
		if _, ok := v[targetKey]; !ok {
			return errMaskInvalidObject
		}

		delete(v, targetKey)

	case []any:
		// first, check the targetKey is a valid index
		targetIndex, err := strconv.Atoi(targetKey)
		if err != nil || targetIndex < 0 || targetIndex >= len(v) {
			return errMaskInvalidObject
		}

		switch nodeParent := nodeParent.(type) {
		case []any:
			// update the target's grandparent slice with a new slice
			index, err := strconv.Atoi(nodeKey)
			if err != nil {
				return errMaskInvalidObject
			}

			nodeParent[index] = slices.Delete(v, targetIndex, targetIndex+1)

		case map[string]any:
			nodeParent[nodeKey] = slices.Delete(v, targetIndex, targetIndex+1)

		case nil:
			// The target slice is the root document itself, so there is no parent to
			// write the shortened slice back into. Write through the root pointer.
			*nodePtr = slices.Delete(v, targetIndex, targetIndex+1)

		default:
			return errMaskInvalidObject
		}

	default:
		return errMaskInvalidObject
	}

	return nil
}

func (maskRule) mkdirp(node any, path []string, value any) error {
	if len(path) == 0 {
		return nil
	}

	for i := range len(path) - 1 {
		switch v := node.(type) {
		case map[string]any:
			child, ok := v[path[i]]
			if !ok {
				child = map[string]any{}
				v[path[i]] = child
			}

			node = child

		case []any:
			idx, err := strconv.Atoi(path[i])
			if err != nil || idx < 0 {
				return errMaskInvalidObject
			}

			for len(v) <= idx {
				v = append(v, nil)
			}

			node = v[idx]

		default:
			return errMaskInvalidObject
		}
	}

	switch v := node.(type) {
	case map[string]any:
		v[path[len(path)-1]] = value

	case []any:
		idx, err := strconv.Atoi(path[len(path)-1])
		if err != nil || idx < 0 || idx >= len(v) {
			return errMaskInvalidObject
		}
		v[idx] = value

	default:
		return errMaskInvalidObject
	}

	return nil
}

func newMaskRuleSet(rv any, onRuleError func(*maskRule, error)) (*maskRuleSet, error) {
	mRuleSet := &maskRuleSet{
		OnRuleError:     onRuleError,
		UndefinedPolicy: defaultMaskUndefinedPolicy,
	}
	rawRules, ok := rv.([]any)
	if !ok {
		return nil, fmt.Errorf("unexpected rule format %v (%[1]T)", rv)
	}

	for _, iface := range rawRules {
		switch v := iface.(type) {

		case string:
			// preserve default behavior of remove when
			// structured mask format is not provided
			rule, err := newMaskRule(v)
			if err != nil {
				return nil, err
			}

			mRuleSet.Rules = append(mRuleSet.Rules, rule)

		case map[string]any:
			rule := &maskRule{}
			op, set := getString(v, "op")
			if set && op == "" {
				return nil, fmt.Errorf("invalid \"op\" value: %v %[1]T", v["op"])
			}
			rule.OP = maskOP(op)

			path, set := getString(v, "path")
			if set && path == "" {
				return nil, fmt.Errorf("invalid \"path\" value: %v %[1]T", v["path"])
			}
			rule.Path = path

			rule.Value = v["value"]

			// use unmarshalled values to create new Mask Rule
			rule, err := newMaskRule(rule.Path, withOP(rule.OP), withValue(rule.Value))
			// TODO add withFailUndefinedPath() option based on
			//   A) new syntax in user defined mask rule
			//   B) passed in/global configuration option
			//   rule precedence A>B
			if err != nil {
				return nil, err
			}

			mRuleSet.Rules = append(mRuleSet.Rules, rule)

		default:
			return nil, fmt.Errorf("invalid mask rule format encountered: %T", v)
		}
	}

	return mRuleSet, nil
}

// Mask applies all rules to event and returns whether the event must be
// dropped because a rule could not be applied while the drop policy is in
// effect. When clear policy is selected, the affected part is cleared instead.
func (rs *maskRuleSet) Mask(event *EventV1) (drop bool) {
	for _, mRule := range rs.Rules {
		// result must be deep copied if there are any mask rules
		// targeting it, to avoid modifying the result sent
		// to the consumer
		if mRule.part() == partResult && event.Result != nil && !rs.resultCopied {
			resultCopy := deepcopy.DeepCopy(*event.Result)
			event.Result = &resultCopy
			rs.resultCopied = true
		}
		if err := rs.copyOnWrite(mRule.part(), event); err != nil {
			if rs.OnRuleError != nil {
				rs.OnRuleError(mRule, err)
			}
			continue
		}

		undefined, err := mRule.Apply(event)
		if err != nil {
			if rs.OnRuleError != nil {
				rs.OnRuleError(mRule, err)
			}
			continue
		}

		if undefined {
			switch rs.UndefinedPolicy {
			case maskUndefinedClear:
				rs.clearPart(mRule.part(), event)
				// Clearing removes values from the event, so leave the same
				// audit trace as an explicit erase.
				event.Erased = append(event.Erased, mRule.String())
			case maskUndefinedDrop:
				return true
			}
		}
	}

	return false
}

// Digest returns a stable digest of the effective mask rules. It is used to
// record which masking semantics were applied to an event.
func (rs *maskRuleSet) Digest() string {
	h := sha256.New()
	for _, r := range rs.Rules {
		h.Write([]byte(r.OP))
		h.Write([]byte{0})
		h.Write([]byte(r.String()))
		h.Write([]byte{0})
		fmt.Fprintf(h, "%v", r.Value)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// copyOnWrite ensures a mask rule never mutates a part still referenced by the
// evaluation result. Input, result and the ND cache are owned by the decision
// log path, so they are not copied here; intermediate and mapped results may
// alias user data.
func (rs *maskRuleSet) copyOnWrite(root string, event *EventV1) error {
	switch root {
	case partIntermediateResults:
		if event.IntermediateResults != nil {
			if rs.copied == nil {
				rs.copied = map[string]bool{}
			}
			if !rs.copied[root] {
				if m, ok := deepcopy.DeepCopy(event.IntermediateResults).(map[string]any); ok {
					event.IntermediateResults = m
				}
				rs.copied[root] = true
			}
		}
	case partMappedResult:
		if event.MappedResult != nil {
			if rs.copied == nil {
				rs.copied = map[string]bool{}
			}
			if !rs.copied[root] {
				v := deepcopy.DeepCopy(*event.MappedResult)
				event.MappedResult = &v
				rs.copied[root] = true
			}
		}
	}
	return nil
}

// clearPart conservatively empties the part a mask rule named when the rule
// could not be applied and the clear policy is selected.
func (rs *maskRuleSet) clearPart(root string, event *EventV1) {
	switch root {
	case partInput:
		if event.Input != nil {
			v := any(map[string]any{})
			event.Input = &v
		}
	case partResult:
		if event.Result != nil {
			v := any(map[string]any{})
			event.Result = &v
		}
	case partNDBCache:
		if event.NDBuiltinCache != nil {
			v := any(map[string]any{})
			event.NDBuiltinCache = &v
		}
	case partIntermediateResults:
		event.IntermediateResults = map[string]any{}
	case partMappedResult:
		if event.MappedResult != nil {
			v := any(map[string]any{})
			event.MappedResult = &v
		}
	case partRequestContext:
		if event.RequestContext != nil && event.RequestContext.HTTPRequest != nil {
			event.RequestContext.HTTPRequest.Headers = nil
		}
	case partError:
		event.Error = nil
	case partCustom:
		event.Custom = nil
	}
}

// bool return means the field was set, if the string is still "", the
// value was invalid
func getString(x map[string]any, key string) (string, bool) {
	y, ok := x[key]
	if !ok {
		return "", false
	}
	s, ok := y.(string)
	if !ok {
		return "", true
	}
	return s, true
}
