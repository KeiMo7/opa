// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package logs

import (
	"sync"
	"time"

	"github.com/open-policy-agent/opa/v1/logging"
)

// Drop reasons recorded alongside dropped decision events. They never contain
// any value from the event itself.
const (
	dropReasonRateLimit     = "rate_limit_exceeded"
	dropReasonBufferSize    = "buffer_size_limit_exceeded"
	dropReasonBufferBytes   = "buffer_size_limit_bytes_exceeded"
	dropReasonEncoding      = "encoding_failure"
	dropReasonMaskFailure   = "masking_failure"
	dropReasonMaskUndefined = "masking_undefined_path"
	dropReasonMaskParse     = "masking_parse_failure"
)

const defaultDropRecordLimit = 1024

// DropRecord is a searchable record of a decision event that was dropped
// before reaching the remote service. It carries only identifiers and the
// reason, never event values, so it is safe to retain and search.
type DropRecord struct {
	DecisionID    string    `json:"decision_id"`
	Reason        string    `json:"reason"`
	Time          time.Time `json:"timestamp"`
	RuleID        string    `json:"rule_id,omitempty"`
	PolicyVersion string    `json:"policy_version,omitempty"`
}

// dropRecorder keeps a bounded, concurrency safe ring of drop records.
type dropRecorder struct {
	mtx     sync.Mutex
	records []DropRecord
	limit   int
	logger  logging.Logger
}

func newDropRecorder(limit int, logger logging.Logger) *dropRecorder {
	if limit <= 0 {
		limit = defaultDropRecordLimit
	}
	return &dropRecorder{limit: limit, logger: logger}
}

func (r *dropRecorder) WithLogger(l logging.Logger) *dropRecorder {
	r.mtx.Lock()
	r.logger = l
	r.mtx.Unlock()
	return r
}

// record appends a drop record. Empty decision IDs are still recorded so that
// drops are never invisible; consumers group them under the empty key.
func (r *dropRecorder) record(rec DropRecord) {
	if r == nil {
		return
	}
	if rec.Time.IsZero() {
		rec.Time = time.Now().UTC()
	}

	r.mtx.Lock()
	if len(r.records) == r.limit {
		copy(r.records, r.records[1:])
		r.records[len(r.records)-1] = rec
	} else {
		r.records = append(r.records, rec)
	}
	logger := r.logger
	r.mtx.Unlock()

	if logger != nil {
		logger.Error("Decision log event dropped: decision_id=%q reason=%q", rec.DecisionID, rec.Reason)
	}
}

// Records returns a copy of the retained drop records, oldest first.
func (r *dropRecorder) Records() []DropRecord {
	if r == nil {
		return nil
	}
	r.mtx.Lock()
	defer r.mtx.Unlock()
	out := make([]DropRecord, len(r.records))
	copy(out, r.records)
	return out
}

// RecordsForDecision returns the drop records matching decisionID.
func (r *dropRecorder) RecordsForDecision(decisionID string) []DropRecord {
	if r == nil {
		return nil
	}
	r.mtx.Lock()
	defer r.mtx.Unlock()
	var out []DropRecord
	for _, rec := range r.records {
		if rec.DecisionID == decisionID {
			out = append(out, rec)
		}
	}
	return out
}

// DropRecords returns the retained drop records, oldest first. Records survive
// upload retries without being duplicated: they are only appended when an
// event is actually discarded.
func (p *Plugin) DropRecords() []DropRecord {
	return p.drops.Records()
}

// DropRecordsForDecision returns the drop records for a given decision ID.
func (p *Plugin) DropRecordsForDecision(decisionID string) []DropRecord {
	return p.drops.RecordsForDecision(decisionID)
}
