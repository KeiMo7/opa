// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package decisioncache

import (
	"encoding/json"

	"github.com/open-policy-agent/opa/v1/util"
)

// noInputMarker is used as the Input component of a Key when the request
// carried no input. It cannot collide with a canonicalized JSON document,
// which always starts with one of '{', '[' or a quote/number/keyword.
const noInputMarker = "\x00no-input\x00"

// CanonicalInput normalizes a raw request input document into a stable string
// suitable for cache keys. The document is decoded with json.Number preserved
// so 1 and 1.0 stay distinct, then re-marshalled with object keys sorted so
// whitespace and key ordering cannot split equivalent inputs.
//
// raw may be nil or empty, in which case the fixed no-input marker is
// returned. A malformed document returns an error so the caller can bypass the
// cache rather than cache against an unusable key.
func CanonicalInput(raw []byte) (string, error) {
	if len(raw) == 0 {
		return noInputMarker, nil
	}

	var value any
	if err := util.UnmarshalJSON(raw, &value); err != nil {
		return "", err
	}

	canonical, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(canonical), nil
}

// CanonicalValue normalizes an already-decoded input value (such as the value
// parsed by the POST data handler). It applies the same json.Number and
// key-ordering rules as CanonicalInput; a nil value yields the no-input
// marker.
func CanonicalValue(value any) (string, error) {
	if value == nil {
		return noInputMarker, nil
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(canonical), nil
}
