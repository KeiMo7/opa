// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package ledger

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// VerifyOptions supplies the key material an offline verifier needs. HMACKey
// is required for HS256 ledgers; PublicKey for EdDSA ledgers. SHA256
// ledgers need neither.
type VerifyOptions struct {
	HMACKey   []byte
	PublicKey ed25519.PublicKey
}

// ErrorLocation pinpoints the first record that failed verification.
type ErrorLocation struct {
	Directory string `json:"directory"`
	Segment   string `json:"segment"`
	Line      int    `json:"line"`
	Seq       uint64 `json:"seq,omitempty"`
	Reason    string `json:"reason"`
}

func (e ErrorLocation) String() string {
	s := fmt.Sprintf("%s/%s", e.Directory, e.Segment)
	if e.Line > 0 {
		s += fmt.Sprintf(":%d", e.Line)
	}
	if e.Seq > 0 {
		s += fmt.Sprintf(" (seq %d)", e.Seq)
	}
	return s + ": " + e.Reason
}

// SegmentReport summarizes verification of one segment file.
type SegmentReport struct {
	Directory        string `json:"directory"`
	File             string `json:"file"`
	SegmentIndex     uint64 `json:"segment_index"`
	InstanceID       string `json:"instance_id"`
	Algorithm        string `json:"algorithm"`
	KeyID            string `json:"key_id,omitempty"`
	FirstSeq         uint64 `json:"first_seq"`
	LastSeq          uint64 `json:"last_seq"`
	Records          int    `json:"records"`
	SegmentHash      string `json:"segment_hash,omitempty"`
	PrevSegmentHash  string `json:"prev_segment_digest,omitempty"`
	ChainFromPriorOK bool   `json:"chain_from_prior_ok"`
	// ChainBroken means the segment's own records authenticate correctly, but
	// the running digest chain from the predecessor does not connect. This is
	// the signature of a deleted/evicted preceding segment, not of forgery:
	// every surviving record's HMAC/signature still verifies.
	ChainBroken bool   `json:"chain_broken,omitempty"`
	OK          bool   `json:"ok"`
	FirstError  string `json:"first_error,omitempty"`
	ErrorLine   int    `json:"error_line,omitempty"`
}

// Gap is a missing sequence range for one instance: every seq in
// (After, Before) is absent.
type Gap struct {
	After  uint64 `json:"after"`
	Before uint64 `json:"before"`
}

// InstanceReport reconciles one writer's records across all verified
// directories. Gaps are listed individually and never merged into a total.
type InstanceReport struct {
	InstanceID        string   `json:"instance_id"`
	Segments          []string `json:"segments"`
	EarliestAvailable uint64   `json:"earliest_available_seq"`
	LastSeq           uint64   `json:"last_seq"`
	RecordsVerified   int      `json:"records_verified"`
	Gaps              []Gap    `json:"gaps"`
	EvictedPrefix     bool     `json:"evicted_prefix"`
	Directories       []string `json:"directories"`
}

// Report is the machine-parseable verification result.
type Report struct {
	OK               bool             `json:"ok"`
	GeneratedAt      time.Time        `json:"generated_at"`
	Directories      []string         `json:"directories"`
	Segments         []SegmentReport  `json:"segments"`
	Instances        []InstanceReport `json:"instances"`
	FirstError       *ErrorLocation   `json:"first_error,omitempty"`
	ConfirmedRecords int              `json:"confirmed_records"`
	TotalRecords     int              `json:"total_records_seen"`
}

// WriteJSON writes the report as indented JSON.
func (r *Report) WriteJSON(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return err
	}
	return f.Sync()
}

// Text renders a human-readable summary.
func (r *Report) Text() string {
	var b strings.Builder
	if r.OK {
		b.WriteString("LEDGER VERIFICATION: OK\n")
	} else {
		b.WriteString("LEDGER VERIFICATION: FAILED\n")
	}
	fmt.Fprintf(&b, "directories: %s\n", strings.Join(r.Directories, ", "))
	fmt.Fprintf(&b, "segments: %d, records verified: %d, total record lines seen: %d\n",
		len(r.Segments), r.ConfirmedRecords, r.TotalRecords)
	if r.FirstError != nil {
		fmt.Fprintf(&b, "first anomaly: %s\n", r.FirstError.String())
	}
	for i := range r.Segments {
		s := &r.Segments[i]
		status := "ok"
		if !s.OK {
			status = "FAIL: " + s.FirstError
		}
		fmt.Fprintf(&b, "- %s/%s index=%d instance=%s alg=%s seq=[%d..%d] records=%d %s\n",
			s.Directory, s.File, s.SegmentIndex, s.InstanceID, s.Algorithm,
			s.FirstSeq, s.LastSeq, s.Records, status)
	}
	for _, in := range r.Instances {
		fmt.Fprintf(&b, "instance %s: verified=%d seq window=[%d..%d] dirs=%s\n",
			in.InstanceID, in.RecordsVerified, in.EarliestAvailable, in.LastSeq,
			strings.Join(in.Directories, ","))
		if in.EvictedPrefix {
			b.WriteString("  note: segments preceding the earliest available one have been evicted or are missing\n")
		}
		for _, g := range in.Gaps {
			fmt.Fprintf(&b, "  gap: seq %d..%d missing (after=%d before=%d)\n", g.After+1, g.Before-1, g.After, g.Before)
		}
	}
	return b.String()
}

type segRange struct {
	first, last uint64
	records     int
	dir         string
}

// VerifyDirectories verifies one or more ledger directories and merges the
// findings. Cross-instance gaps are listed per instance, never as a total.
// Each directory is locked in shared, non-blocking mode: verification refuses
// to run while a writer process may still be appending.
func VerifyDirectories(dirs []string, opts VerifyOptions) (*Report, error) {
	if len(dirs) == 0 {
		return nil, errors.New("no ledger directories given")
	}
	report := &Report{
		GeneratedAt: time.Now().UTC(),
	}

	// Hold shared locks on every directory for the whole scan.
	var locks []*dirLock
	releaseAll := func() {
		for _, lk := range locks {
			_ = lk.release()
		}
	}
	for _, dir := range dirs {
		lk, err := acquireDirLockNB(dir, true)
		if err != nil {
			releaseAll()
			return nil, fmt.Errorf("verify %s: %w", dir, err)
		}
		locks = append(locks, lk)
	}
	defer releaseAll()

	type instanceAgg struct {
		id       string
		dirs     map[string]struct{}
		segments []string
		ranges   []segRange
		records  int
		evicted  bool
	}
	instances := map[string]*instanceAgg{}
	var firstErr *ErrorLocation
	var confirmed int
	var totalSeen int

	for _, dir := range dirs {
		report.Directories = append(report.Directories, dir)
		paths, err := segmentPaths(dir)
		if err != nil {
			return nil, fmt.Errorf("list segments in %s: %w", dir, err)
		}
		if len(paths) == 0 {
			return nil, fmt.Errorf("no segments found in %s", dir)
		}

		var prevHash string
		// runningDigest carries the global record digest chain across
		// segments: every record's prev_digest points at the preceding
		// record, even when that record lives in another segment.
		var runningDigest string
		for segNo, path := range paths {
			sr, loc, seen, verified, nextDigest := verifyOneSegment(dir, path, opts, runningDigest)
			runningDigest = nextDigest
			if segNo == 0 {
				sr.ChainFromPriorOK = true
			} else {
				sr.ChainFromPriorOK = sr.PrevSegmentHash == prevHash
			}
			report.Segments = append(report.Segments, sr)
			totalSeen += seen
			confirmed += verified

			agg := instances[sr.InstanceID]
			if agg == nil {
				agg = &instanceAgg{id: sr.InstanceID, dirs: map[string]struct{}{}}
				instances[sr.InstanceID] = agg
			}

			if segNo > 0 && !sr.ChainFromPriorOK {
				// A missing predecessor (rotated away under the disk limit or
				// deleted) legitimately breaks the cross-segment link. The
				// surviving segments still authenticate individually, so this
				// is reported as an eviction rather than an anomaly; a
				// swapped-in forged segment fails its own digest checks above.
				agg.evicted = true
			}
			prevHash = sr.SegmentHash

			// A chain break from missing predecessors is reported as an
			// eviction/gap, not a forgery: every surviving record still
			// authenticated. Only genuine digest/signature failures populate
			// firstErr and fail the overall report.
			if !sr.OK && !sr.ChainBroken && firstErr == nil && loc != nil {
				firstErr = loc
			}

			agg.dirs[dir] = struct{}{}
			agg.segments = append(agg.segments, filepath.Join(dir, sr.File))
			agg.records += verified
			if sr.Records > 0 {
				agg.ranges = append(agg.ranges, segRange{first: sr.FirstSeq, last: sr.LastSeq, records: sr.Records, dir: dir})
			}
			if segNo == 0 && sr.PrevSegmentHash != "" {
				agg.evicted = true
			}
			if sr.ChainBroken {
				agg.evicted = true
			}
		}
	}

	ids := make([]string, 0, len(instances))
	for id := range instances {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		agg := instances[id]
		slices.SortFunc(agg.ranges, func(a, b segRange) int {
			if a.first < b.first {
				return -1
			}
			if a.first > b.first {
				return 1
			}
			return 0
		})
		ir := InstanceReport{
			InstanceID:      id,
			Segments:        agg.segments,
			RecordsVerified: agg.records,
			EvictedPrefix:   agg.evicted,
		}
		dirSet := make([]string, 0, len(agg.dirs))
		for d := range agg.dirs {
			dirSet = append(dirSet, d)
		}
		slices.Sort(dirSet)
		ir.Directories = dirSet
		if len(agg.ranges) > 0 {
			ir.EarliestAvailable = agg.ranges[0].first
			ir.LastSeq = agg.ranges[len(agg.ranges)-1].last
			prev := agg.ranges[0].first - 1
			for _, rng := range agg.ranges {
				if rng.first > prev+1 {
					ir.Gaps = append(ir.Gaps, Gap{After: prev, Before: rng.first})
				}
				if rng.last > prev {
					prev = rng.last
				}
			}
		}
		report.Instances = append(report.Instances, ir)
	}

	report.ConfirmedRecords = confirmed
	report.TotalRecords = totalSeen
	report.FirstError = firstErr
	// The report is OK only when no record failed authentication and no
	// digest chain was broken. Eviction gaps alone keep OK=true because the
	// surviving evidence is intact and the gap is listed under the instance.
	anyChainBroken := false
	for i := range report.Segments {
		if report.Segments[i].ChainBroken {
			anyChainBroken = true
			break
		}
	}
	report.OK = firstErr == nil && !anyChainBroken
	return report, nil
}

// verifyOneSegment verifies a single segment file and returns its report,
// the first error location (if any), how many record lines were seen and
// confirmed, and the digest of the final verified record so the global chain
// can continue into the next segment.
func verifyOneSegment(dir, path string, opts VerifyOptions, runningDigest string) (SegmentReport, *ErrorLocation, int, int, string) {
	sr := SegmentReport{
		Directory: dir,
		File:      filepath.Base(path),
		OK:        true,
	}
	idx, _ := segmentIndexFromName(sr.File)
	sr.SegmentIndex = idx

	f, err := os.Open(path)
	if err != nil {
		sr.OK = false
		sr.FirstError = err.Error()
		return sr, &ErrorLocation{Directory: dir, Segment: sr.File, Reason: err.Error()}, 0, 0, runningDigest
	}
	defer f.Close()
	reader := newLineReader(f)

	_, headerRaw, err := reader.nextLine()
	if err != nil {
		sr.OK = false
		sr.FirstError = "missing or unreadable header: " + err.Error()
		return sr, &ErrorLocation{Directory: dir, Segment: sr.File, Line: 1, Reason: sr.FirstError}, 0, 0, runningDigest
	}
	h, hp, err := decodeHeader(headerRaw)
	if err != nil {
		sr.OK = false
		sr.FirstError = "invalid header: " + err.Error()
		return sr, &ErrorLocation{Directory: dir, Segment: sr.File, Line: 1, Reason: sr.FirstError}, 0, 0, runningDigest
	}
	signer, err := verifierSigner(hp.Algorithm, opts)
	if err != nil {
		sr.OK = false
		sr.FirstError = err.Error()
		return sr, &ErrorLocation{Directory: dir, Segment: sr.File, Line: 1, Reason: sr.FirstError}, 0, 0, runningDigest
	}
	if err := signer.verify(h.Payload, h.Digest, h.Sig); err != nil {
		sr.OK = false
		sr.FirstError = "header digest mismatch: " + err.Error()
		return sr, &ErrorLocation{Directory: dir, Segment: sr.File, Line: 1, Reason: sr.FirstError}, 0, 0, runningDigest
	}
	sr.InstanceID = hp.InstanceID
	sr.Algorithm = hp.Algorithm
	sr.KeyID = hp.KeyID
	sr.FirstSeq = hp.FirstSeq
	sr.PrevSegmentHash = hp.PrevSegmentDigest

	segInputs := []string{h.Digest}
	expectedSeq := hp.FirstSeq
	// lastDigest starts at the running global chain tip, so a segment's
	// first record links to the last record of the preceding segment.
	lastDigest := runningDigest
	lineNo := 1
	seen, verified := 0, 0
	var firstErr *ErrorLocation

	// Read every record line up front so the chain-break reason can tell a
	// reorder (the predecessor digest still exists somewhere in this
	// segment) from a deleted/evicted predecessor segment.
	type parsedLine struct {
		lineNo int
		raw    []byte
	}
	var lines []parsedLine
	recordDigests := map[string]struct{}{}
	for {
		curLine := lineNo + 1
		_, raw, readErr := reader.nextLine()
		if raw != nil {
			lines = append(lines, parsedLine{lineNo: curLine, raw: raw})
			if validLine(raw) {
				var env Record
				if json.Unmarshal(raw, &env) == nil && env.Digest != "" {
					recordDigests[env.Digest] = struct{}{}
				}
			}
		}
		if readErr != nil {
			break
		}
	}

	for _, pl := range lines {
		lineNo = pl.lineNo
		line := pl.raw
		seen++

		fail := func(reason string, seq uint64) {
			sr.OK = false
			sr.FirstError = reason
			sr.ErrorLine = lineNo
			firstErr = &ErrorLocation{Directory: dir, Segment: sr.File, Line: lineNo, Seq: seq, Reason: reason}
		}

		if !validLine(line) {
			fail("malformed JSON line (truncation or torn write)", expectedSeq)
			break
		}
		var rec Record
		if err := json.Unmarshal(line, &rec); err != nil {
			fail("invalid record envelope: "+err.Error(), expectedSeq)
			break
		}
		if err := signer.verify(rec.Payload, rec.Digest, rec.Sig); err != nil {
			fail("record digest/signature mismatch: "+err.Error(), expectedSeq)
			break
		}
		var p payload
		if err := json.Unmarshal(rec.Payload, &p); err != nil {
			fail("invalid record payload: "+err.Error(), expectedSeq)
			break
		}
		if p.InstanceID != hp.InstanceID {
			fail(fmt.Sprintf("instance id %q does not match segment header %q", p.InstanceID, hp.InstanceID), p.Seq)
			break
		}
		if p.Seq != expectedSeq || p.PrevDigest != lastDigest {
			var reason string
			_, predInSegment := recordDigests[p.PrevDigest]
			// Check the predecessor-presence signal first: it is the
			// reliable discriminator between a reorder (predecessor still in
			// this segment) and a deleted/evicted predecessor segment.
			switch {
			case !predInSegment && p.PrevDigest != "":
				// The predecessor digest points at records no longer on disk:
				// a preceding segment was deleted or evicted.
				reason = fmt.Sprintf("digest chain broken at seq %d (missing predecessor records)", p.Seq)
			default:
				// Either the predecessor still exists at a different
				// position, or this is the genesis record of a tampered
				// segment: both are order/rewrite violations.
				reason = fmt.Sprintf("digest chain broken at seq %d (reordered or rewritten records)", p.Seq)
			}
			sr.OK = false
			sr.ChainBroken = true
			sr.FirstError = reason
			sr.ErrorLine = lineNo
			break
		}
		expectedSeq++
		lastDigest = rec.Digest
		segInputs = append(segInputs, rec.Digest)
		verified++
		sr.LastSeq = p.Seq
	}

	sr.Records = verified
	sr.SegmentHash = hashOfDigests(signer, segInputs)
	return sr, firstErr, seen, verified, lastDigest
}

func verifierSigner(alg string, opts VerifyOptions) (signer, error) {
	switch alg {
	case AlgSHA256:
		return &plainSigner{}, nil
	case AlgHS256:
		if len(opts.HMACKey) == 0 {
			return nil, errors.New("HS256 segment requires an HMAC key (pass --key)")
		}
		return newHMACSigner(opts.HMACKey, ""), nil
	case AlgEdDSA:
		if opts.PublicKey == nil {
			return nil, errors.New("EdDSA segment requires a public key (pass --public-key)")
		}
		return &ed25519Signer{pub: opts.PublicKey}, nil
	default:
		return nil, fmt.Errorf("unknown segment algorithm %q", alg)
	}
}
