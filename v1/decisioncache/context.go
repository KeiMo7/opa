// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package decisioncache

import "context"

type noStoreKeyType struct{}

var noStoreKey noStoreKeyType

// WithNoStore decorates ctx so that a decision evaluated for the request is
// returned to the caller but never retained in the cache. Existing entries may
// still be returned. It is used when an evaluation produces data that cannot
// be represented by a cache entry, such as response metadata.
//
// The flag travels per request through the context, so requests coordinated by
// a singleflight load cannot change each other's storage behaviour.
func WithNoStore(ctx context.Context) context.Context {
	return context.WithValue(ctx, noStoreKey, true)
}

func noStoreFromContext(ctx context.Context) bool {
	v, _ := ctx.Value(noStoreKey).(bool)
	return v
}
