// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package server

import (
	"encoding/json"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/open-policy-agent/opa/v1/util"
)

func urlQueryEscape(s string) string {
	return url.QueryEscape(s)
}

// uniqueDecisionIDs gives every decision on the fixture a unique id so cached
// responses can be compared apart from their decision_id field.
func uniqueDecisionIDs() func(*Server) {
	var counter atomic.Uint64
	return func(s *Server) {
		s.WithDecisionIDFactory(func() string {
			counter.Add(1)
			return "decision-" + strconv.FormatUint(counter.Load(), 10)
		})
	}
}

func decodeBody(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var decoded map[string]any
	if err := util.UnmarshalJSON(body, &decoded); err != nil {
		t.Fatalf("decode response %q: %v", string(body), err)
	}
	return decoded
}

func compareJSON(a, b any) string {
	return cmp.Diff(a, b)
}

// counter extracts an integer counter from an include_metrics response body.
// util.UnmarshalJSON preserves numbers as json.Number.
func counter(resp map[string]any, name string) uint64 {
	metricsMap, ok := resp["metrics"].(map[string]any)
	if !ok {
		return 0
	}
	value, ok := metricsMap["counter_"+name]
	if !ok {
		return 0
	}
	switch v := value.(type) {
	case float64:
		return uint64(v)
	case uint64:
		return v
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return 0
		}
		return uint64(n)
	default:
		return 0
	}
}
