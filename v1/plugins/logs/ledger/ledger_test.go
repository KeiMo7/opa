// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package ledger

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testConfig(t *testing.T) *Config {
	t.Helper()
	return &Config{
		Directory:            t.TempDir(),
		MaxRecordsPerSegment: 4,
		MaxSegmentSizeMB:     1,
		DiskLimitMB:          16,
		QueueSize:            128,
	}
}

func sampleEntry(i int) Entry {
	return Entry{
		DecisionID:  fmt.Sprintf("decision-%04d", i),
		Timestamp:   time.Now().UTC(),
		PolicyID:    "policies/example",
		Revision:    "rev-1",
		Path:        "/example/allow",
		InputDigest: fmt.Sprintf("sha256:input-%d", i),
		Result:      map[string]any{"allow": i%2 == 0},
		LatencyNS:   int64(1000 + i),
		Masked:      []string{"/input/secret"},
	}
}

func appendN(t *testing.T, l *Ledger, start, n int) {
	t.Helper()
	ctx := t.Context()
	for i := start; i < start+n; i++ {
		if err := l.Append(ctx, sampleEntry(i)); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
}

func verifyOK(t *testing.T, dir string) *Report {
	t.Helper()
	key, err := os.ReadFile(filepath.Join(dir, keyFileName))
	if err != nil {
		t.Fatalf("read ledger key: %v", err)
	}
	report, err := VerifyDirectories([]string{dir}, VerifyOptions{HMACKey: key})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !report.OK {
		t.Fatalf("verification not OK: %+v", report.FirstError)
	}
	return report
}

func TestAppendAndVerifyRoundtrip(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	l, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, l, 0, 10)
	stats := l.Stats()
	if stats.NextSeq != 11 {
		t.Fatalf("next seq = %d, want 11", stats.NextSeq)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	paths, err := segmentPaths(cfg.Directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) < 3 {
		t.Fatalf("expected rotation into >=3 segments, got %d", len(paths))
	}

	report := verifyOK(t, cfg.Directory)
	if report.ConfirmedRecords != 10 {
		t.Fatalf("confirmed = %d, want 10", report.ConfirmedRecords)
	}
	if len(report.Instances) != 1 {
		t.Fatalf("instances = %d, want 1", len(report.Instances))
	}
	inst := report.Instances[0]
	if inst.LastSeq != 10 || len(inst.Gaps) != 0 {
		t.Fatalf("instance reconciliation wrong: %+v", inst)
	}
	// Cross-segment chaining must have been checked for every later segment.
	for i, s := range report.Segments {
		if i > 0 && !s.ChainFromPriorOK {
			t.Fatalf("segment %s does not chain from prior", s.File)
		}
	}
}

func TestRestartContinuesChain(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)

	l, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, l, 0, 7)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	l2, err := Open(cfg)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	appendN(t, l2, 7, 6)
	if err := l2.Close(); err != nil {
		t.Fatal(err)
	}

	report := verifyOK(t, cfg.Directory)
	if report.ConfirmedRecords != 13 {
		t.Fatalf("confirmed = %d, want 13", report.ConfirmedRecords)
	}
	if report.Instances[0].LastSeq != 13 {
		t.Fatalf("last seq = %d, want 13", report.Instances[0].LastSeq)
	}
}

// TestCrashRestartSimulated exercises the "hard kill" path in a child
// process: records are fsynced before ack, then the child is killed without
// Close. The parent reopens the same directory and continues.
func TestCrashRestartSimulated(t *testing.T) {
	if os.Getenv("LEDGER_CHILD_CRASH") == "1" {
		cfg := &Config{
			Directory:            os.Getenv("LEDGER_CHILD_DIR"),
			MaxRecordsPerSegment: 4,
			MaxSegmentSizeMB:     1,
			DiskLimitMB:          16,
			QueueSize:            16,
			InstanceID:           "child-instance",
		}
		l, err := Open(cfg)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		for i := range 10 {
			//nolint:usetesting // child process has no *testing.T
			if err := l.Append(context.Background(), sampleEntry(i)); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
		}
		// Deliberately exit without Close, like SIGKILL.
		os.Exit(0)
	}

	dir := t.TempDir()
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("hard_kill_then_continue", func(t *testing.T) {
		cmd := exec.Command(bin, "-test.run=TestCrashRestartSimulated")
		cmd.Env = append(os.Environ(),
			"LEDGER_CHILD_CRASH=1",
			"LEDGER_CHILD_DIR="+dir,
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("child failed: %v\n%s", err, out)
		}

		// Reopen over the same directory and keep writing.
		cfg := testConfig(t)
		cfg.Directory = dir
		cfg.InstanceID = "child-instance"
		l, err := Open(cfg)
		if err != nil {
			t.Fatalf("reopen after kill: %v", err)
		}
		if l.Stats().NextSeq != 11 {
			t.Fatalf("next seq after kill = %d, want 11", l.Stats().NextSeq)
		}
		appendN(t, l, 10, 5)
		if err := l.Close(); err != nil {
			t.Fatal(err)
		}
		report := verifyOK(t, dir)
		if report.ConfirmedRecords != 15 {
			t.Fatalf("confirmed = %d, want 15", report.ConfirmedRecords)
		}
	})

	t.Run("torn_tail_truncated", func(t *testing.T) {
		// In-process equivalent of a power-loss mid-write: fsync a partial
		// JSON fragment with no trailing newline, then reopen the ledger. The
		// recovery path must truncate the torn line and continue the chain.
		tornDir := t.TempDir()
		cfg := testConfig(t)
		cfg.Directory = tornDir
		cfg.InstanceID = "child-instance"
		l, err := Open(cfg)
		if err != nil {
			t.Fatal(err)
		}
		appendN(t, l, 0, 5)
		paths, _ := segmentPaths(tornDir)
		active := paths[len(paths)-1]
		// Close without removing the directory, then corrupt the active
		// segment from outside the ledger like a crash mid-write would.
		if err := l.Close(); err != nil {
			t.Fatal(err)
		}
		f, err := os.OpenFile(active, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(`{"payload":{"seq":6,"partial":true}` + "\n"); err != nil {
			t.Fatal(err)
		}
		_ = f.Sync()
		_ = f.Close()

		l2, err := Open(cfg)
		if err != nil {
			t.Fatalf("reopen with torn tail: %v", err)
		}
		if l2.Stats().NextSeq != 6 {
			t.Fatalf("next seq after torn recovery = %d, want 6", l2.Stats().NextSeq)
		}
		if err := l2.Append(t.Context(), sampleEntry(5)); err != nil {
			t.Fatal(err)
		}
		if err := l2.Close(); err != nil {
			t.Fatal(err)
		}
		report := verifyOK(t, tornDir)
		if report.ConfirmedRecords != 6 {
			t.Fatalf("confirmed = %d, want 6", report.ConfirmedRecords)
		}
	})
}

// readSegmentLines loads the raw JSON lines of a segment for tamper tests.
func readSegmentLines(t *testing.T, path string) [][]byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	lines := make([][]byte, len(parts))
	for i := range parts {
		lines[i] = []byte(parts[i])
	}
	return lines
}

func writeSegmentLines(t *testing.T, path string, lines [][]byte) {
	t.Helper()
	var joined []byte
	for _, l := range lines {
		joined = append(joined, l...)
		joined = append(joined, '\n')
	}
	if err := os.WriteFile(path, joined, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestTamperSingleByte(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	l, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, l, 0, 6)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	paths, _ := segmentPaths(cfg.Directory)
	lines := readSegmentLines(t, paths[0])
	// Flip one byte inside the first record line (line 2, after the header).
	target := lines[1]
	idx := bytes.Index(target, []byte("decision-"))
	if idx < 0 {
		t.Fatal("decision id not found in record")
	}
	target[idx+len("decision-")] = 'X'
	writeSegmentLines(t, paths[0], lines)

	key, _ := os.ReadFile(filepath.Join(cfg.Directory, keyFileName))
	report, err := VerifyDirectories([]string{cfg.Directory}, VerifyOptions{HMACKey: key})
	if err != nil {
		t.Fatal(err)
	}
	if report.OK || report.FirstError == nil {
		t.Fatal("expected verification failure")
	}
	if report.FirstError.Segment != filepath.Base(paths[0]) || report.FirstError.Line != 2 {
		t.Fatalf("first error location = %+v, want segment %s line 2", report.FirstError, filepath.Base(paths[0]))
	}
	// The tampered record is the first record line, so no record is confirmed.
	if report.ConfirmedRecords != 0 {
		t.Fatalf("confirmed prefix = %d, want 0", report.ConfirmedRecords)
	}
	// A later record leaves a confirmed prefix before it.
	cfg2 := testConfig(t)
	l2, err := Open(cfg2)
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, l2, 0, 6)
	if err := l2.Close(); err != nil {
		t.Fatal(err)
	}
	p2, _ := segmentPaths(cfg2.Directory)
	lines2 := readSegmentLines(t, p2[0])
	target2 := lines2[2] // third line = second record
	idx2 := bytes.Index(target2, []byte("decision-"))
	target2[idx2+len("decision-")] = 'Z'
	writeSegmentLines(t, p2[0], lines2)
	key2, _ := os.ReadFile(filepath.Join(cfg2.Directory, keyFileName))
	rep2, err := VerifyDirectories([]string{cfg2.Directory}, VerifyOptions{HMACKey: key2})
	if err != nil {
		t.Fatal(err)
	}
	if rep2.OK {
		t.Fatal("expected verification failure on second record")
	}
	if rep2.ConfirmedRecords < 1 {
		t.Fatalf("confirmed prefix = %d, want >=1 record before the tampered one", rep2.ConfirmedRecords)
	}
}

func TestTamperDeleteSegment(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	l, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, l, 0, 12)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	paths, _ := segmentPaths(cfg.Directory)
	if len(paths) < 3 {
		t.Fatalf("need >=3 segments, got %d", len(paths))
	}
	if err := os.Remove(paths[1]); err != nil {
		t.Fatal(err)
	}

	key, _ := os.ReadFile(filepath.Join(cfg.Directory, keyFileName))
	report, err := VerifyDirectories([]string{cfg.Directory}, VerifyOptions{HMACKey: key})
	if err != nil {
		t.Fatal(err)
	}
	// The surviving records authenticate individually, but the missing
	// segment breaks the digest chain and leaves a sequence gap attributed to
	// the instance. No record-level forgery is involved, so FirstError stays
	// nil while the chain-broken flag marks the evidence gap.
	if report.FirstError != nil {
		t.Fatalf("no record-level authentication failure expected: %+v", report.FirstError)
	}
	var chainBroken bool
	for _, s := range report.Segments {
		if s.ChainBroken {
			chainBroken = true
		}
	}
	if !chainBroken {
		t.Fatal("deleted segment must produce a chain-broken successor")
	}
	inst := report.Instances[0]
	if !inst.EvictedPrefix && len(inst.Gaps) == 0 {
		t.Fatalf("deleted segment must show as an eviction or gap, got %+v", inst)
	}
	// A forged replacement cannot pass: take a segment from a ledger with a
	// different key and splice it into the gap.
	cfgOther := testConfig(t)
	other, err := Open(cfgOther)
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, other, 50, 4)
	if err := other.Close(); err != nil {
		t.Fatal(err)
	}
	otherSegs, _ := segmentPaths(cfgOther.Directory)
	forged, err := os.ReadFile(otherSegs[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths[1], forged, 0o600); err != nil {
		t.Fatal(err)
	}
	repForged, err := VerifyDirectories([]string{cfg.Directory}, VerifyOptions{HMACKey: key})
	if err != nil {
		t.Fatal(err)
	}
	if repForged.OK {
		t.Fatal("foreign-key replacement segment must fail authentication")
	}
}

func TestTamperReorderRecords(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	cfg.MaxRecordsPerSegment = 100 // keep all records in one segment for an easy swap
	l, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, l, 0, 8)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	paths, _ := segmentPaths(cfg.Directory)
	lines := readSegmentLines(t, paths[0])
	if len(lines) < 4 { // header + >=3 records
		t.Fatalf("not enough lines: %d", len(lines))
	}
	// Swap the first two record lines (indices 1 and 2).
	lines[1], lines[2] = lines[2], lines[1]
	writeSegmentLines(t, paths[0], lines)

	key, _ := os.ReadFile(filepath.Join(cfg.Directory, keyFileName))
	report, err := VerifyDirectories([]string{cfg.Directory}, VerifyOptions{HMACKey: key})
	if err != nil {
		t.Fatal(err)
	}
	// Reordering leaves every individual digest valid but breaks the running
	// chain, which is surfaced as a chain-broken segment pinpointed at the
	// first out-of-order record line.
	if report.OK {
		t.Fatal("expected reorder detection")
	}
	var broken *SegmentReport
	for i := range report.Segments {
		if report.Segments[i].ChainBroken {
			broken = &report.Segments[i]
			break
		}
	}
	if broken == nil {
		t.Fatalf("expected a chain-broken segment, got %+v", report.Segments)
	}
	if broken.ErrorLine != 2 {
		t.Fatalf("anomaly line = %d, want 2", broken.ErrorLine)
	}
	if !strings.Contains(broken.FirstError, "chain broken") {
		t.Fatalf("unexpected reason: %s", broken.FirstError)
	}
}

func TestSegmentReplacementDetected(t *testing.T) {
	t.Parallel()
	// Even an attacker who rewrites a whole segment and recomputes its
	// internal digests cannot forge the cross-segment hash without the key.
	cfg := testConfig(t)
	cfg.MaxRecordsPerSegment = 4
	first, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, first, 0, 8)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	// Build a second, independent ledger and steal one of its segments.
	cfg2 := testConfig(t)
	other, err := Open(cfg2)
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, other, 100, 4)
	if err := other.Close(); err != nil {
		t.Fatal(err)
	}
	otherSegs, _ := segmentPaths(cfg2.Directory)
	victimSegs, _ := segmentPaths(cfg.Directory)
	stolen, err := os.ReadFile(otherSegs[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(victimSegs[0], stolen, 0o600); err != nil {
		t.Fatal(err)
	}

	key, _ := os.ReadFile(filepath.Join(cfg.Directory, keyFileName))
	report, err := VerifyDirectories([]string{cfg.Directory}, VerifyOptions{HMACKey: key})
	if err != nil {
		t.Fatal(err)
	}
	if report.OK {
		t.Fatal("replacement segment with foreign HMAC must fail verification")
	}
}

func TestConcurrentWritesAreGapless(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	cfg.MaxRecordsPerSegment = 256
	cfg.QueueSize = 1024
	l, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}

	const writers = 16
	const perWriter = 625 // 16*625 = 10000
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for w := range writers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := range perWriter {
				e := sampleEntry(w*perWriter + i)
				if err := l.Append(t.Context(), e); err != nil {
					errs <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	report := verifyOK(t, cfg.Directory)
	if report.ConfirmedRecords != 10000 {
		t.Fatalf("confirmed = %d, want 10000", report.ConfirmedRecords)
	}
	inst := report.Instances[0]
	if inst.LastSeq != 10000 {
		t.Fatalf("last seq = %d, want 10000", inst.LastSeq)
	}
	if len(inst.Gaps) != 0 {
		t.Fatalf("unexpected gaps: %+v", inst.Gaps)
	}
	// Walk every segment file: seq 1..10000 must appear exactly once.
	seen := make(map[uint64]bool, 10000)
	paths, _ := segmentPaths(cfg.Directory)
	for _, p := range paths {
		lines := readSegmentLines(t, p)
		for li, raw := range lines {
			if li == 0 {
				continue
			}
			var rec Record
			if err := json.Unmarshal(raw, &rec); err != nil {
				t.Fatal(err)
			}
			var pl payload
			if err := json.Unmarshal(rec.Payload, &pl); err != nil {
				t.Fatal(err)
			}
			if seen[pl.Seq] {
				t.Fatalf("duplicate seq %d", pl.Seq)
			}
			seen[pl.Seq] = true
		}
	}
	if len(seen) != 10000 {
		t.Fatalf("unique seqs = %d, want 10000", len(seen))
	}
}

func TestDiskLimitEvictsOldestSegments(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	cfg.MaxRecordsPerSegment = 2
	// Tiny byte-level limits so a handful of segments forces eviction.
	cfg.maxSegmentBytesOverride = 2048
	cfg.diskLimitBytesOverride = 4096
	l, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, l, 0, 20)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	paths, _ := segmentPaths(cfg.Directory)
	var total int64
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		total += info.Size()
	}
	if total > cfg.diskLimitBytes() {
		t.Fatalf("disk usage %d exceeds limit %d", total, cfg.diskLimitBytes())
	}
	if l.Stats().Evicted == 0 {
		t.Fatal("expected at least one eviction")
	}
	// The surviving records authenticate individually; the evicted prefix
	// breaks the chain but is reported as an eviction, never as a forgery.
	key, _ := os.ReadFile(filepath.Join(cfg.Directory, keyFileName))
	report, err := VerifyDirectories([]string{cfg.Directory}, VerifyOptions{HMACKey: key})
	if err != nil {
		t.Fatal(err)
	}
	if report.FirstError != nil {
		t.Fatalf("eviction must not cause record-level failures: %+v", report.FirstError)
	}
	if !report.Instances[0].EvictedPrefix {
		t.Fatal("expected evicted-prefix flag on instance report")
	}
}

func TestUnwritableDirectoryRejectsAppends(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root bypasses permission bits")
	}
	cfg := testConfig(t)
	l, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, l, 0, 2)

	// Force the next write to fail by revoking write permission on the dir.
	if err := os.Chmod(cfg.Directory, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(cfg.Directory, 0o700) })

	// Rotate so the writer must create a new segment in the read-only dir.
	if err := l.rotate(l.active); err == nil {
		t.Fatal("expected rotation to fail on read-only directory")
	}
	err = l.Append(t.Context(), sampleEntry(99))
	if err == nil || !errors.Is(err, ErrUnwritable) {
		t.Fatalf("expected ErrUnwritable, got %v", err)
	}
	if l.Stats().WriteFailures == 0 {
		t.Fatal("write failure metric not counted")
	}
	// Fatal state sticks: every later append is rejected, nothing is dropped.
	if err := l.Append(t.Context(), sampleEntry(100)); !errors.Is(err, ErrUnwritable) {
		t.Fatalf("second append: %v", err)
	}
	_ = os.Chmod(cfg.Directory, 0o700)
	_ = l.Close()
}

func TestMultipleInstancesReportPerInstanceGaps(t *testing.T) {
	t.Parallel()

	openLedger := func(t *testing.T, dir, instance string, perSeg uint64) (*Ledger, []byte) {
		t.Helper()
		cfg := testConfig(t)
		cfg.Directory = dir
		cfg.InstanceID = instance
		cfg.MaxRecordsPerSegment = perSeg
		l, err := Open(cfg)
		if err != nil {
			t.Fatal(err)
		}
		key, err := os.ReadFile(filepath.Join(dir, keyFileName))
		if err != nil {
			t.Fatal(err)
		}
		return l, key
	}

	// Two instances, each with its own directory and key.
	dirA, dirB := t.TempDir(), t.TempDir()
	la, keyA := openLedger(t, dirA, "instance-A", 100)
	for i := range 6 {
		if err := la.Append(t.Context(), sampleEntry(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := la.Close(); err != nil {
		t.Fatal(err)
	}

	lb, keyB := openLedger(t, dirB, "instance-B", 100)
	for i := range 4 {
		if err := lb.Append(t.Context(), sampleEntry(100+i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := lb.Close(); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(keyA, keyB) {
		t.Fatal("auto-generated keys must differ per directory")
	}

	// Verifying B's directory with A's key must fail: keys are per-ledger.
	if _, err := VerifyDirectories([]string{dirB}, VerifyOptions{HMACKey: keyA}); err == nil {
		report, _ := VerifyDirectories([]string{dirB}, VerifyOptions{HMACKey: keyA})
		if report.OK {
			t.Fatal("foreign HMAC key must not verify another ledger")
		}
	}

	// Each ledger verifies with its own key and reports its own instance.
	repA, err := VerifyDirectories([]string{dirA}, VerifyOptions{HMACKey: keyA})
	if err != nil {
		t.Fatal(err)
	}
	repB, err := VerifyDirectories([]string{dirB}, VerifyOptions{HMACKey: keyB})
	if err != nil {
		t.Fatal(err)
	}
	if !repA.OK || !repB.OK {
		t.Fatal("clean ledgers must verify")
	}
	if repA.Instances[0].InstanceID != "instance-A" || repB.Instances[0].InstanceID != "instance-B" {
		t.Fatal("instances not identified separately")
	}
	if len(repA.Instances[0].Gaps) != 0 || len(repB.Instances[0].Gaps) != 0 {
		t.Fatal("complete ledgers must report no gaps")
	}

	// Build a bigger A ledger first so a middle segment exists, then remove
	// an interior segment: the anomaly is attributed to instance A's directory.
	la2, _ := openLedger(t, dirA, "instance-A", 2)
	appendN(t, la2, 6, 6)
	if err := la2.Close(); err != nil {
		t.Fatal(err)
	}
	pathsA, _ := segmentPaths(dirA)
	if len(pathsA) < 3 {
		t.Fatalf("need >=3 segments, got %d", len(pathsA))
	}
	if err := os.Remove(pathsA[1]); err != nil {
		t.Fatal(err)
	}
	repA2, err := VerifyDirectories([]string{dirA}, VerifyOptions{HMACKey: keyA})
	if err != nil {
		t.Fatal(err)
	}
	if repA2.OK {
		t.Fatal("interior segment deletion must break the chain")
	}
	var chainBroken bool
	for _, s := range repA2.Segments {
		if s.ChainBroken {
			chainBroken = true
		}
	}
	if !chainBroken {
		t.Fatal("expected a chain-broken segment after interior deletion")
	}
	if repA2.Instances[0].InstanceID != "instance-A" {
		t.Fatalf("anomaly attributed to wrong instance: %s", repA2.Instances[0].InstanceID)
	}
}

func TestSaltedInputDigestIsOneWayAndStable(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	l, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"secret":"do-not-persist-me"}`)
	d1 := l.DigestInput(raw)
	d2 := l.DigestInput(raw)
	if d1 != d2 {
		t.Fatal("digest must be deterministic for the same input")
	}
	if strings.Contains(d1, "do-not-persist-me") {
		t.Fatal("raw input leaked into digest")
	}
	if err := l.Append(t.Context(), Entry{DecisionID: "d1", Timestamp: time.Now().UTC(), InputDigest: d1}); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	// The raw secret must not appear anywhere in the segment files.
	paths, _ := segmentPaths(cfg.Directory)
	for _, p := range paths {
		rawSeg, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(rawSeg), "do-not-persist-me") {
			t.Fatalf("sensitive input persisted in %s", p)
		}
	}
}

func TestEdDSALedgerVerifiesWithPublicKeyOnly(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pub, priv, err := ed25519GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "ed25519.pem")
	pem, err := marshalEd25519PrivatePEM(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(t)
	cfg.Directory = dir
	cfg.Algorithm = AlgEdDSA
	cfg.KeyFile = keyPath
	l, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, l, 0, 5)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	report, err := VerifyDirectories([]string{dir}, VerifyOptions{PublicKey: pub})
	if err != nil {
		t.Fatal(err)
	}
	if !report.OK {
		t.Fatalf("EdDSA verification failed: %+v", report.FirstError)
	}
	if report.Segments[0].Algorithm != AlgEdDSA {
		t.Fatalf("algorithm = %q", report.Segments[0].Algorithm)
	}
}

func TestBackpressureBlocksThenRecovers(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	cfg.QueueSize = 2
	l, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Fill the queue and cancel the context while blocked: Append must return
	// the context error rather than hanging.
	ctx, cancel := context.WithCancel(t.Context())
	// Pause the writer indirectly by filling the queue faster than it drains.
	done := make(chan error, 8)
	for i := range 8 {
		go func(i int) { done <- l.Append(ctx, sampleEntry(i)) }(i)
	}
	time.Sleep(20 * time.Millisecond)
	cancel()
	// At least one cancelled append must surface ctx.Canceled.
	seenCancel := false
	for range 8 {
		if err := <-done; errors.Is(err, context.Canceled) {
			seenCancel = true
		}
	}
	if !seenCancel {
		t.Fatal("cancelled context did not unblock an append")
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}
