// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package ledger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// segmentName returns the on-disk name of segment index i. Indices are zero
// padded so lexical and numeric ordering agree; they are not required to be
// contiguous after eviction.
func segmentName(i uint64) string {
	return fmt.Sprintf("%s%06d%s", segmentNamePrefix, i, segmentNameSuffix)
}

func segmentIndexFromName(name string) (uint64, bool) {
	if !strings.HasPrefix(name, segmentNamePrefix) || !strings.HasSuffix(name, segmentNameSuffix) {
		return 0, false
	}
	mid := name[len(segmentNamePrefix) : len(name)-len(segmentNameSuffix)]
	var idx uint64
	if _, err := fmt.Sscanf(mid, "%d", &idx); err != nil {
		return 0, false
	}
	return idx, true
}

// segmentPaths returns segment file paths ordered by segment index.
func segmentPaths(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if _, ok := segmentIndexFromName(e.Name()); ok {
			paths = append(paths, filepath.Join(dir, e.Name()))
		}
	}
	slices.SortFunc(paths, func(a, b string) int {
		ni, _ := segmentIndexFromName(filepath.Base(a))
		nj, _ := segmentIndexFromName(filepath.Base(b))
		if ni < nj {
			return -1
		}
		if ni > nj {
			return 1
		}
		return 0
	})
	return paths, nil
}

// activeSegment is the single segment file a ledger appends to.
type activeSegment struct {
	index        uint64
	file         *os.File
	header       *HeaderPayload
	headerDigest string
	records      uint64
	size         int64
	firstSeq     uint64
	lastSeq      uint64
	lastDigest   string
	prevSegHash  string
	// digests holds the hex digest of every record in segment order, so
	// rotation can compute the segment hash without re-reading the file.
	digests []string
}

// writeHeader creates a new segment file and persists its header line.
func writeHeader(dir string, index uint64, hp HeaderPayload, s signer) (*activeSegment, error) {
	raw, err := json.Marshal(&hp)
	if err != nil {
		return nil, err
	}
	env := Header{Payload: raw, Digest: s.digest(raw)}
	if env.Sig, err = s.sign(env.Digest); err != nil {
		return nil, err
	}
	line, err := json.Marshal(&env)
	if err != nil {
		return nil, err
	}
	line = append(line, '\n')

	path := filepath.Join(dir, segmentName(index))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create segment %s: %w", segmentName(index), err)
	}
	if _, err := f.Write(line); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := syncDir(dir); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &activeSegment{
		index:        index,
		file:         f,
		header:       &hp,
		headerDigest: env.Digest,
		size:         int64(len(line)),
		firstSeq:     hp.FirstSeq,
		prevSegHash:  hp.PrevSegmentDigest,
	}, nil
}

// appendRecord writes and fsyncs one record. The fsync is what makes an
// acknowledged append durable: a crash can only lose records whose
// acknowledgement had not been returned yet.
func (a *activeSegment) appendRecord(rec *Record) error {
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	if _, err := a.file.Write(line); err != nil {
		return err
	}
	if err := a.file.Sync(); err != nil {
		return err
	}
	a.size += int64(len(line))
	a.records++
	return nil
}

func (a *activeSegment) close() error {
	if a.file == nil {
		return nil
	}
	err := a.file.Sync()
	if cerr := a.file.Close(); cerr != nil && err == nil {
		err = cerr
	}
	a.file = nil
	return err
}

// validLine reports whether raw is a complete JSON object on one line. It is
// used to tell a torn trailing write (crash mid-append) from a complete but
// tampered record.
func validLine(raw []byte) bool {
	if len(raw) == 0 || raw[0] != '{' {
		return false
	}
	var v map[string]json.RawMessage
	return json.Unmarshal(raw, &v) == nil
}
