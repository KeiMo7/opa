// Copyright 2018 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package logs

import (
	"container/list"
)

// logBuffer implements a circular FIFO buffer for the plugin that caps memory
// usage at the configured limit. If the buffer size is exceeded, events from
// the front of the buffer are dropped.
type logBuffer struct {
	usage int64
	limit int64
	l     *list.List
}

type logBufferElem struct {
	bs []byte
	// ev optionally identifies the events contained in bs, so that a dropped
	// chunk can be recorded against the decisions it carried.
	ev *EventV1
}

func newLogBuffer(limit int64) *logBuffer {
	return &logBuffer{
		limit: limit,
		usage: 0,
		l:     list.New(),
	}
}

func (lb *logBuffer) Push(bs []byte) (dropped int) {
	return len(lb.PushEvent(bs, nil))
}

// PushEvent pushes bs and, when the buffer is full, reports the events that
// were evicted. ev is optional and gives the events contained in bs.
func (lb *logBuffer) PushEvent(bs []byte, ev *EventV1) (dropped []*EventV1) {
	size := int64(len(bs))

	if lb.limit > 0 {
		if size > lb.limit {
			return []*EventV1{ev}
		}

		for lb.usage+size > lb.limit {
			elem := lb.l.Front()
			if elem == nil {
				break
			}
			drop := elem.Value.(logBufferElem)
			lb.l.Remove(elem)
			lb.usage -= int64(len(drop.bs))
			dropped = append(dropped, drop.ev)
		}
	}

	elem := logBufferElem{bs: bs, ev: ev}

	lb.l.PushBack(elem)
	lb.usage += size
	return dropped
}

func (lb *logBuffer) Pop() []byte {
	elem := lb.l.Front()
	if elem != nil {
		e := elem.Value.(logBufferElem)
		lb.usage -= int64(len(e.bs))
		lb.l.Remove(elem)
		return e.bs
	}
	return nil
}

func (lb *logBuffer) Len() int {
	return lb.l.Len()
}
