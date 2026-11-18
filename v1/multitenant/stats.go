// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package multitenant

import "sync/atomic"

// atomicCounter is a named int64 counter so hot-path statistics stay
// contention-free and independent of one another.
type atomicCounter struct {
	n atomic.Int64
}

func (c *atomicCounter) inc()        { c.n.Add(1) }
func (c *atomicCounter) add(n int64) { c.n.Add(n) }
func (c *atomicCounter) get() int64  { return c.n.Load() }
