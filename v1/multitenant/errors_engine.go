// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package multitenant

import (
	"context"
	"errors"

	"github.com/open-policy-agent/opa/v1/topdown"
)

// isEngineCancel reports whether err is the topdown engine's cancellation
// error, which is what rego/topdown return once a query has been aborted via
// its Cancel handle or a cancelled context.
func isEngineCancel(err error) bool {
	if errors.Is(err, context.Canceled) {
		return true
	}
	return topdown.IsCancel(err)
}
