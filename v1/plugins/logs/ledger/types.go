// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

// Package ledger implements a tamper-evident, append-only on-disk ledger of
// decision records.
//
// Every record is linked to its predecessor by a keyed digest, so any
// truncation, deletion, reordering or in-place modification is detected at the
// first record that no longer matches the chain. Records are fsynced before an
// append is acknowledged, which makes them durable across process crashes and
// power loss. The ledger is split into independently named segment files while
// the digest chain continues across segment boundaries, so replacing a whole
// segment and recomputing its digests is detected as well.
package ledger

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// Algorithm names for record digests and signatures.
const (
	// AlgHS256 authenticates each record with an HMAC-SHA-256 key. The key
	// never leaves the host and cannot be recovered from the ledger.
	AlgHS256 = "HS256"
	// AlgEdDSA signs each record with an Ed25519 private key. The matching
	// public key can be distributed independently and used by verifiers that
	// must not be trusted with write credentials.
	AlgEdDSA = "EdDSA"
	// AlgSHA256 links records with plain SHA-256 digests. This detects
	// accidental corruption and tampering by parties without the ledger
	// directory's write access, but an attacker able to rewrite the ledger can
	// recompute the chain; prefer a keyed algorithm.
	AlgSHA256 = "SHA256"
)

// Default configuration values.
const (
	defaultAlgorithm    = AlgHS256
	defaultMaxRecords   = 10_000
	defaultMaxSegmentMB = 32
	defaultDiskLimitMB  = 1024
	defaultQueueSize    = 1024

	// maxLineBounds caps the size of a single encoded line while reading, so a
	// corrupted length field cannot make the verifier allocate unbounded
	// memory. It mirrors the maximum segment size plus generous headroom.
	maxLineBytes = 64 << 20 // 64 MiB
)

// Well-known file names inside a ledger directory.
const (
	stateFileName = "ledger-state.json"
	keyFileName   = "ledger.key"
	// lockFileName serializes access to a ledger directory between processes.
	lockFileName = ".lock"
	// segmentNamePrefix names segment files: segment-000001.jsonl ...
	segmentNamePrefix = "segment-"
	segmentNameSuffix = ".jsonl"
)

// Errors that callers can test with errors.Is.
var (
	// ErrClosed is returned after Close or a fatal write failure.
	ErrClosed = errors.New("ledger is closed")
	// ErrUnwritable is returned when the ledger directory cannot be written
	// to or the disk limit has been reached. Records must be counted as
	// rejected; the ledger never silently drops them.
	ErrUnwritable = errors.New("ledger is not writable")
	// ErrQueueFull is returned when the append backpressure queue is full and
	// the caller did not wait for acknowledgement.
	ErrQueueFull = errors.New("ledger append queue is full")
	// ErrCorrupt marks a ledger whose on-disk chain cannot be recovered.
	ErrCorrupt = errors.New("ledger is corrupt")
)

// Entry is the caller-supplied content of one decision record. It never
// contains raw sensitive input: callers pass a precomputed input digest.
type Entry struct {
	DecisionID   string         `json:"decision_id"`
	Timestamp    time.Time      `json:"timestamp"`
	PolicyID     string         `json:"policy_id,omitempty"`
	Revision     string         `json:"revision,omitempty"`
	Bundles      map[string]any `json:"bundles,omitempty"`
	Path         string         `json:"path,omitempty"`
	InputDigest  string         `json:"input_digest"`
	Result       any            `json:"result,omitempty"`
	ResultDigest string         `json:"result_digest,omitempty"`
	LatencyNS    int64          `json:"latency_ns,omitempty"`
	DecisionErr  string         `json:"error,omitempty"`
	// Masked and Erased carry the field paths the mask policy touched. They
	// are paths, not values, and so do not leak sensitive content.
	Masked []string `json:"masked,omitempty"`
	Erased []string `json:"erased,omitempty"`
}

// Record is the full, on-disk envelope of one entry.
type Record struct {
	Payload json.RawMessage `json:"payload"`
	// Digest is the hex-encoded digest of the exact Payload bytes, keyed
	// according to the segment header's algorithm.
	Digest string `json:"digest"`
	// Sig is the Ed25519 signature over Digest (hex). Empty for HS256 and
	// SHA256.
	Sig string `json:"sig,omitempty"`
}

// payload is the canonical, signed content of a record. It is encoded once
// and its exact bytes are hashed, so verification never re-canonicalizes
// caller data.
type payload struct {
	Seq          uint64         `json:"seq"`
	PrevDigest   string         `json:"prev_digest"`
	InstanceID   string         `json:"instance_id"`
	DecisionID   string         `json:"decision_id"`
	Timestamp    time.Time      `json:"timestamp"`
	PolicyID     string         `json:"policy_id,omitempty"`
	Revision     string         `json:"revision,omitempty"`
	Bundles      map[string]any `json:"bundles,omitempty"`
	Path         string         `json:"path,omitempty"`
	InputDigest  string         `json:"input_digest"`
	Result       any            `json:"result,omitempty"`
	ResultDigest string         `json:"result_digest,omitempty"`
	LatencyNS    int64          `json:"latency_ns,omitempty"`
	DecisionErr  string         `json:"error,omitempty"`
	Masked       []string       `json:"masked,omitempty"`
	Erased       []string       `json:"erased,omitempty"`
}

// HeaderPayload is the signed content of a segment header line.
type HeaderPayload struct {
	SegmentIndex      uint64    `json:"segment_index"`
	InstanceID        string    `json:"instance_id"`
	Algorithm         string    `json:"algorithm"`
	KeyID             string    `json:"key_id,omitempty"`
	SaltB64           string    `json:"salt_b64"`
	FirstSeq          uint64    `json:"first_seq"`
	PrevSegmentDigest string    `json:"prev_segment_digest,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
}

// Header is the on-disk segment header envelope.
type Header struct {
	Payload json.RawMessage `json:"payload"`
	Digest  string          `json:"digest"`
	Sig     string          `json:"sig,omitempty"`
}

func decodeHeader(raw []byte) (*Header, *HeaderPayload, error) {
	var h Header
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, nil, err
	}
	var hp HeaderPayload
	if err := json.Unmarshal(h.Payload, &hp); err != nil {
		return nil, nil, err
	}
	return &h, &hp, nil
}

func mustB64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func b64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

func hexEncode(b []byte) string {
	return hex.EncodeToString(b)
}

// digestLen is the hex length of a SHA-256 digest.
const digestLen = 64
