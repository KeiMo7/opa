// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package ledger

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/open-policy-agent/opa/v1/logging"
	"github.com/open-policy-agent/opa/v1/metrics"
)

// Metric names recorded on the OPA metrics provider.
const (
	MetricRecordsWritten   = "decision_logs_ledger_records_written"
	MetricWriteFailures    = "decision_logs_ledger_write_failures"
	MetricQueueRejected    = "decision_logs_ledger_queue_rejected"
	MetricSegmentRotations = "decision_logs_ledger_segment_rotations"
	MetricSegmentsEvicted  = "decision_logs_ledger_segments_evicted"
	MetricTailRecovered    = "decision_logs_ledger_torn_tail_recovered"
)

// Stats is a point-in-time snapshot of ledger state.
type Stats struct {
	InstanceID     string `json:"instance_id"`
	NextSeq        uint64 `json:"next_seq"`
	ActiveSegment  uint64 `json:"active_segment"`
	ActiveRecords  uint64 `json:"active_records"`
	Segments       int    `json:"segments"`
	DiskBytes      int64  `json:"disk_bytes"`
	RecordsWritten uint64 `json:"records_written"`
	WriteFailures  uint64 `json:"write_failures"`
	QueueRejected  uint64 `json:"queue_rejected"`
	Evicted        uint64 `json:"segments_evicted"`
}

type appendJob struct {
	entry Entry
	ack   chan error
}

// Ledger is an append-only, tamper-evident, fsynced decision record store.
type Ledger struct {
	cfg    Config
	signer signer
	salt   []byte
	logger logging.Logger
	mtx    metrics.Metrics

	lock   *dirLock
	active *activeSegment

	// the fields below are owned by the writer goroutine
	nextSeq     uint64
	lastDigest  string
	lastSegHash string
	instanceID  string

	jobs chan appendJob
	quit chan struct{}
	done chan struct{}

	closed   atomic.Bool
	fatalErr atomic.Pointer[error]

	written atomic.Uint64
	failed  atomic.Uint64
	reject  atomic.Uint64
	evicted atomic.Uint64
}

// Open creates or reopens a ledger in cfg.Directory. The directory is locked
// exclusively for the lifetime of the returned Ledger.
func Open(cfg *Config) (*Ledger, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.Directory, 0o700); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnwritable, err)
	}
	// Fail fast when the directory is not writable.
	probe, err := os.CreateTemp(cfg.Directory, ".ledger-probe.*.tmp")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnwritable, err)
	}
	_ = probe.Close()
	_ = os.Remove(probe.Name())

	lock, err := acquireDirLock(cfg.Directory, false)
	if err != nil {
		return nil, err
	}

	l := &Ledger{
		cfg:  *cfg,
		lock: lock,
		jobs: make(chan appendJob, cfg.QueueSize),
		quit: make(chan struct{}),
		done: make(chan struct{}),
	}
	if err := l.bootstrap(); err != nil {
		_ = lock.release()
		return nil, err
	}
	go l.runWriter()
	return l, nil
}

// WithMetrics attaches the OPA metrics provider.
func (l *Ledger) WithMetrics(m metrics.Metrics) *Ledger {
	l.mtx = m
	return l
}

// WithLogger attaches a structured logger.
func (l *Ledger) WithLogger(logger logging.Logger) *Ledger {
	l.logger = logger
	return l
}

// InstanceID returns the persistent identifier of this ledger writer.
func (l *Ledger) InstanceID() string { return l.instanceID }

// DigestInput returns the salted, one-way digest of a raw decision input.
// Raw inputs are never passed to Append and never touch disk.
func (l *Ledger) DigestInput(raw []byte) string {
	return l.DigestBytes(raw)
}

// DigestBytes returns the salted, one-way digest of arbitrary bytes,
// prefixed with the algorithm name ("sha256:...").
func (l *Ledger) DigestBytes(raw []byte) string {
	mac := hmac.New(sha256.New, l.salt)
	mac.Write(raw)
	return "sha256:" + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// Append enqueues a record and waits for its fsync acknowledgement. It
// applies backpressure: when the queue is full it blocks until space frees
// up or ctx is cancelled. A fatal disk error makes every subsequent Append
// fail with a wrapped ErrUnwritable; records are never dropped silently.
func (l *Ledger) Append(ctx context.Context, e Entry) error {
	if err := l.fatal(); err != nil {
		l.countReject()
		return err
	}
	if l.closed.Load() {
		l.countReject()
		return ErrClosed
	}
	job := appendJob{entry: e, ack: make(chan error, 1)}
	select {
	case l.jobs <- job:
	case <-ctx.Done():
		return ctx.Err()
	case <-l.quit:
		l.countReject()
		return ErrClosed
	}
	select {
	case err := <-job.ack:
		return err
	case <-ctx.Done():
		// The writer still durably appends queued records; the caller simply
		// stopped waiting. The buffered ack channel ensures no goroutine leak.
		return ctx.Err()
	case <-l.quit:
		return ErrClosed
	}
}

// Close drains queued appends, fsyncs and releases the directory lock.
func (l *Ledger) Close() error {
	if !l.closed.CompareAndSwap(false, true) {
		return ErrClosed
	}
	close(l.quit)
	<-l.done

	var errs []error
	if l.active != nil {
		if err := l.active.close(); err != nil {
			errs = append(errs, err)
		}
		if err := l.persistState(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := l.lock.release(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Stats returns a snapshot of counters and disk usage.
func (l *Ledger) Stats() Stats {
	paths, _ := segmentPaths(l.cfg.Directory)
	var disk int64
	for _, p := range paths {
		if info, err := os.Stat(p); err == nil {
			disk += info.Size()
		}
	}
	return Stats{
		InstanceID:     l.instanceID,
		NextSeq:        l.nextSeq,
		ActiveSegment:  l.active.index,
		ActiveRecords:  l.active.records,
		Segments:       len(paths),
		DiskBytes:      disk,
		RecordsWritten: l.written.Load(),
		WriteFailures:  l.failed.Load(),
		QueueRejected:  l.reject.Load(),
		Evicted:        l.evicted.Load(),
	}
}

func (l *Ledger) countMetric(name string) {
	if l.mtx != nil {
		l.mtx.Counter(name).Incr()
	}
}

func (l *Ledger) countReject() {
	l.reject.Add(1)
	l.countMetric(MetricQueueRejected)
}

func (l *Ledger) fatal() error {
	if p := l.fatalErr.Load(); p != nil {
		return *p
	}
	return nil
}

// failFatal marks the ledger unwritable. All future appends are rejected.
func (l *Ledger) failFatal(err error) {
	if errors.Is(err, ErrUnwritable) {
		if l.fatalErr.CompareAndSwap(nil, &err) {
			l.closed.Store(true)
			if l.logger != nil {
				l.logger.Error("Decision ledger became unwritable: %v", err)
			}
		}
		return
	}
	wrapped := fmt.Errorf("%w: %v", ErrUnwritable, err)
	if l.fatalErr.CompareAndSwap(nil, &wrapped) {
		l.closed.Store(true)
		if l.logger != nil {
			l.logger.Error("Decision ledger became unwritable: %v", err)
		}
	}
}

// bootstrap loads or creates key material, state and segments, and recovers
// from a possibly torn tail left by a hard crash.
func (l *Ledger) bootstrap() error {
	st, err := readStateFile(l.cfg.Directory)
	if err != nil {
		return err
	}

	var persistedKey []byte
	if l.cfg.Algorithm != AlgEdDSA && l.cfg.KeyFile == "" {
		persistedKey, _ = os.ReadFile(filepath.Join(l.cfg.Directory, keyFileName))
	}
	s, keyToPersist, err := newSigner(&l.cfg, persistedKey)
	if err != nil {
		return err
	}
	l.signer = s
	if keyToPersist != nil {
		if err := persistKey(l.cfg.Directory, keyToPersist); err != nil {
			return fmt.Errorf("%w: %v", ErrUnwritable, err)
		}
	}

	if st != nil && st.Algorithm != "" && st.Algorithm != s.algorithm() {
		return fmt.Errorf("%w: state algorithm %q does not match configured %q", ErrCorrupt, st.Algorithm, s.algorithm())
	}

	paths, err := segmentPaths(l.cfg.Directory)
	if err != nil {
		return err
	}

	if len(paths) == 0 {
		l.instanceID = firstNonEmpty(l.cfg.InstanceID, stateInstanceID(st), uuid.NewString())
		l.salt = stateSalt(st)
		if len(l.salt) == 0 {
			l.salt = randomSalt()
		}
		l.nextSeq = 1
		if err := l.rotate(nil); err != nil {
			return err
		}
		return l.persistState()
	}

	rec, err := l.recoverSegments(paths, s)
	if err != nil {
		return err
	}
	l.nextSeq = rec.nextSeq
	l.lastDigest = rec.lastDigest
	l.lastSegHash = rec.lastSegHash
	l.instanceID = firstNonEmpty(l.cfg.InstanceID, rec.instanceID, stateInstanceID(st), uuid.NewString())
	l.salt = rec.salt
	if len(l.salt) == 0 {
		l.salt = stateSalt(st)
	}
	if len(l.salt) == 0 {
		l.salt = randomSalt()
	}
	return l.persistState()
}

type recovery struct {
	nextSeq     uint64
	lastDigest  string
	lastSegHash string
	instanceID  string
	salt        []byte
	truncated   bool
}

// recoverSegments replays every segment, verifies the chain and truncates a
// torn tail of the final segment. Corruption anywhere else is fatal:
// evidence must never be silently repaired.
func (l *Ledger) recoverSegments(paths []string, s signer) (recovery, error) {
	var rec recovery
	var expectedSeq uint64 = 1
	var prevSegHash string
	var active *activeSegment

	for segNo, path := range paths {
		isLast := segNo == len(paths)-1
		f, err := os.OpenFile(path, os.O_RDWR, 0o600)
		if err != nil {
			return rec, err
		}
		reader := newLineReader(f)

		// Header line.
		_, raw, err := reader.nextLine()
		if err != nil {
			_ = f.Close()
			return rec, fmt.Errorf("%w: %s: missing header: %v", ErrCorrupt, filepath.Base(path), err)
		}
		h, hp, err := decodeHeader(raw)
		if err != nil {
			_ = f.Close()
			return rec, fmt.Errorf("%w: %s: bad header: %v", ErrCorrupt, filepath.Base(path), err)
		}
		if err := s.verify(h.Payload, h.Digest, h.Sig); err != nil {
			_ = f.Close()
			return rec, fmt.Errorf("%w: %s: %v", ErrCorrupt, filepath.Base(path), err)
		}
		idx, _ := segmentIndexFromName(filepath.Base(path))
		if idx != hp.SegmentIndex {
			_ = f.Close()
			return rec, fmt.Errorf("%w: %s: header index %d", ErrCorrupt, filepath.Base(path), hp.SegmentIndex)
		}
		// The first available segment may follow evicted ones; only check the
		// cross-segment link when both ends are present.
		if segNo > 0 && hp.PrevSegmentDigest != prevSegHash {
			_ = f.Close()
			return rec, fmt.Errorf("%w: %s: segment chain broken", ErrCorrupt, filepath.Base(path))
		}
		if segNo == 0 {
			rec.instanceID = hp.InstanceID
			if salt, derr := b64Decode(hp.SaltB64); derr == nil {
				rec.salt = salt
			}
			expectedSeq = hp.FirstSeq
		} else if hp.InstanceID != rec.instanceID {
			_ = f.Close()
			return rec, fmt.Errorf("%w: %s: instance id changed within ledger", ErrCorrupt, filepath.Base(path))
		}

		segDigestInputs := []string{h.Digest}
		// goodOffset is the file offset immediately after the last verified
		// line; truncation keeps exactly that prefix. It starts after the
		// header so a segment with only a torn first record keeps the header.
		goodOffset := reader.offset
		var records uint64

		for {
			startOff, line, readErr := reader.nextLine()
			if readErr == io.EOF && line == nil {
				break
			}
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				_ = f.Close()
				return rec, fmt.Errorf("%w: %s: %v", ErrCorrupt, filepath.Base(path), readErr)
			}

			bad := func(msg string, args ...any) (recovery, error) {
				_ = f.Close()
				return rec, fmt.Errorf("%w: %s: %v", ErrCorrupt, filepath.Base(path), fmt.Sprintf(msg, args...))
			}

			if !validLine(line) {
				if !isLast {
					return bad("malformed record at offset %d", startOff)
				}
				if err := f.Truncate(goodOffset); err != nil {
					_ = f.Close()
					return rec, fmt.Errorf("truncate torn tail: %w", err)
				}
				rec.truncated = true
				break
			}
			var recEnv Record
			if err := json.Unmarshal(line, &recEnv); err != nil {
				if !isLast {
					return bad("invalid record envelope at offset %d", startOff)
				}
				if err := f.Truncate(goodOffset); err != nil {
					_ = f.Close()
					return rec, fmt.Errorf("truncate torn tail: %w", err)
				}
				rec.truncated = true
				break
			}
			if err := s.verify(recEnv.Payload, recEnv.Digest, recEnv.Sig); err != nil {
				if !isLast {
					return bad("digest verification failed at offset %d: %v", startOff, err)
				}
				if err := f.Truncate(goodOffset); err != nil {
					_ = f.Close()
					return rec, fmt.Errorf("truncate torn tail: %w", err)
				}
				rec.truncated = true
				break
			}
			var p payload
			if err := json.Unmarshal(recEnv.Payload, &p); err != nil {
				if !isLast {
					return bad("invalid payload at offset %d", startOff)
				}
				if err := f.Truncate(goodOffset); err != nil {
					_ = f.Close()
					return rec, fmt.Errorf("truncate torn tail: %w", err)
				}
				rec.truncated = true
				break
			}
			if p.Seq != expectedSeq || p.PrevDigest != rec.lastDigest {
				if !isLast {
					return bad("seq/chain mismatch at seq %d (expected %d)", p.Seq, expectedSeq)
				}
				if err := f.Truncate(goodOffset); err != nil {
					_ = f.Close()
					return rec, fmt.Errorf("truncate torn tail: %w", err)
				}
				rec.truncated = true
				break
			}
			if p.InstanceID != rec.instanceID {
				return bad("record instance id mismatch at seq %d", p.Seq)
			}
			expectedSeq++
			rec.lastDigest = recEnv.Digest
			segDigestInputs = append(segDigestInputs, recEnv.Digest)
			records++
			goodOffset = reader.offset
			if errors.Is(readErr, io.EOF) {
				break
			}
		}

		segHash := hashOfDigests(s, segDigestInputs)
		prevSegHash = segHash

		if isLast {
			if rec.truncated {
				// Truncate shrank the file, but the open handle's append
				// offset is stale. Reopen in append mode so later writes land
				// exactly at the new end instead of leaving a zero hole.
				if err := f.Close(); err != nil {
					return rec, err
				}
				f, err = os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
				if err != nil {
					return rec, err
				}
				if err := f.Sync(); err != nil {
					_ = f.Close()
					return rec, err
				}
			}
			info, _ := f.Stat()
			size := info.Size()
			active = &activeSegment{
				index:        idx,
				file:         f,
				header:       hp,
				headerDigest: h.Digest,
				records:      records,
				size:         size,
				firstSeq:     hp.FirstSeq,
				lastSeq:      expectedSeq - 1,
				lastDigest:   rec.lastDigest,
				prevSegHash:  hp.PrevSegmentDigest,
				digests:      segDigestInputs[1:],
			}
		} else {
			_ = f.Close()
		}
	}

	if rec.truncated {
		l.countMetric(MetricTailRecovered)
	}
	l.active = active
	rec.nextSeq = expectedSeq
	rec.lastSegHash = prevSegHash
	return rec, nil
}

func (l *Ledger) runWriter() {
	defer close(l.done)
	for {
		select {
		case job := <-l.jobs:
			job.ack <- l.writeOne(job.entry)
		case <-l.quit:
			// Drain anything still queued so graceful shutdown loses nothing.
			for {
				select {
				case job := <-l.jobs:
					job.ack <- l.writeOne(job.entry)
				default:
					return
				}
			}
		}
	}
}

func (l *Ledger) writeOne(e Entry) error {
	if err := l.fatal(); err != nil {
		l.failed.Add(1)
		l.countMetric(MetricWriteFailures)
		return err
	}
	if l.active.records >= l.cfg.MaxRecordsPerSegment || l.active.size >= l.cfg.maxSegmentBytes() {
		if err := l.rotate(l.active); err != nil {
			l.failFatal(err)
			l.failed.Add(1)
			l.countMetric(MetricWriteFailures)
			return l.fatal()
		}
	}

	p := payload{
		Seq:          l.nextSeq,
		PrevDigest:   l.lastDigest,
		InstanceID:   l.instanceID,
		DecisionID:   e.DecisionID,
		Timestamp:    e.Timestamp,
		PolicyID:     e.PolicyID,
		Revision:     e.Revision,
		Bundles:      e.Bundles,
		Path:         e.Path,
		InputDigest:  e.InputDigest,
		Result:       e.Result,
		ResultDigest: e.ResultDigest,
		LatencyNS:    e.LatencyNS,
		DecisionErr:  e.DecisionErr,
		Masked:       e.Masked,
		Erased:       e.Erased,
	}
	raw, err := json.Marshal(&p)
	if err != nil {
		l.failed.Add(1)
		l.countMetric(MetricWriteFailures)
		return err
	}
	d := l.signer.digest(raw)
	sig, err := l.signer.sign(d)
	if err != nil {
		l.failed.Add(1)
		l.countMetric(MetricWriteFailures)
		return err
	}
	rec := Record{Payload: raw, Digest: d, Sig: sig}

	if err := l.active.appendRecord(&rec); err != nil {
		l.failFatal(classifyDiskError(err))
		l.failed.Add(1)
		l.countMetric(MetricWriteFailures)
		return l.fatal()
	}

	l.nextSeq++
	l.lastDigest = d
	l.active.lastSeq = p.Seq
	l.active.lastDigest = d
	l.active.digests = append(l.active.digests, d)
	l.written.Add(1)
	l.countMetric(MetricRecordsWritten)
	return nil
}

// rotate seals current (nil when bootstrapping the first segment) and opens
// the next segment whose header chains on the previous segment's hash.
func (l *Ledger) rotate(current *activeSegment) error {
	var prevHash string
	var nextIndex uint64 = 1
	firstSeq := l.nextSeq

	if current != nil {
		all := append([]string{current.headerDigest}, current.digests...)
		prevHash = hashOfDigests(l.signer, all)
		if err := current.close(); err != nil {
			return err
		}
		nextIndex = current.index + 1
		l.lastSegHash = prevHash
		l.countMetric(MetricSegmentRotations)
	}

	hp := HeaderPayload{
		SegmentIndex:      nextIndex,
		InstanceID:        l.instanceID,
		Algorithm:         l.signer.algorithm(),
		KeyID:             l.signer.keyID(),
		SaltB64:           mustB64(l.salt),
		FirstSeq:          firstSeq,
		PrevSegmentDigest: prevHash,
		CreatedAt:         time.Now().UTC(),
	}
	seg, err := writeHeader(l.cfg.Directory, nextIndex, hp, l.signer)
	if err != nil {
		return classifyDiskError(err)
	}
	l.active = seg
	if err := l.persistState(); err != nil {
		return err
	}
	return l.enforceDiskLimit()
}

// enforceDiskLimit evicts the oldest sealed segments until total segment
// size is within the configured hard limit. The active segment is never
// evicted; config validation guarantees it alone fits within the limit.
func (l *Ledger) enforceDiskLimit() error {
	for {
		paths, err := segmentPaths(l.cfg.Directory)
		if err != nil {
			return err
		}
		var total int64
		for _, p := range paths {
			info, err := os.Stat(p)
			if err != nil {
				return err
			}
			total += info.Size()
		}
		if total <= l.cfg.diskLimitBytes() || len(paths) <= 1 {
			return nil
		}
		oldest := paths[0]
		if idx, _ := segmentIndexFromName(filepath.Base(oldest)); idx == l.active.index {
			return nil
		}
		if err := os.Remove(oldest); err != nil {
			return classifyDiskError(err)
		}
		if err := syncDir(l.cfg.Directory); err != nil {
			return err
		}
		l.evicted.Add(1)
		l.countMetric(MetricSegmentsEvicted)
	}
}

func (l *Ledger) persistState() error {
	st := persistedState{
		InstanceID:      l.instanceID,
		NextSeq:         l.nextSeq,
		ActiveIndex:     l.active.index,
		ActiveRecords:   l.active.records,
		LastDigest:      l.lastDigest,
		LastSegmentHash: l.lastSegHash,
		Algorithm:       l.signer.algorithm(),
		KeyID:           l.signer.keyID(),
		SaltB64:         mustB64(l.salt),
	}
	return writeStateFile(l.cfg.Directory, st)
}

// lineReader returns raw lines without the trailing newline and tracks the
// byte offset immediately following each line.
type lineReader struct {
	r      *bufio.Reader
	offset int64
}

func newLineReader(f *os.File) *lineReader {
	return &lineReader{r: bufio.NewReaderSize(f, 1<<20)}
}

func (r *lineReader) nextLine() (offset int64, line []byte, err error) {
	offset = r.offset
	raw, err := r.r.ReadBytes('\n')
	r.offset += int64(len(raw))
	if len(raw) == 0 {
		return offset, nil, err
	}
	line = bytes.TrimRight(raw, "\n")
	if len(line) > maxLineBytes {
		return offset, nil, fmt.Errorf("line exceeds %d bytes", maxLineBytes)
	}
	// A final line without a trailing newline is returned alongside io.EOF.
	return offset, line, err
}

func hashOfDigests(s signer, digests []string) string {
	return s.digest([]byte(strings.Join(digests, "")))
}

func randomSalt() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func stateInstanceID(st *persistedState) string {
	if st == nil {
		return ""
	}
	return st.InstanceID
}

func stateSalt(st *persistedState) []byte {
	if st == nil || st.SaltB64 == "" {
		return nil
	}
	b, err := b64Decode(st.SaltB64)
	if err != nil {
		return nil
	}
	return b
}

func classifyDiskError(err error) error {
	if errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EROFS) {
		return fmt.Errorf("%w: %v", ErrUnwritable, err)
	}
	return err
}
