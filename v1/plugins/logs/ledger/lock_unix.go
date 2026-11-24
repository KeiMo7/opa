// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

//go:build !windows

package ledger

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// dirLock is an advisory, process-scoped lock on the ledger directory. It
// prevents two OPA processes from appending to the same directory and
// corrupting the sequence numbering; an offline verifier takes a shared lock
// so it refuses to run against a live writer.
type dirLock struct {
	f *os.File
}

func acquireDirLock(dir string, shared bool) (*dirLock, error) {
	path := filepath.Join(dir, lockFileName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open ledger lock: %w", err)
	}
	op := unix.LOCK_EX
	if shared {
		op = unix.LOCK_SH
	}
	if err := unix.Flock(int(f.Fd()), op); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("acquire ledger lock: %w", err)
	}
	return &dirLock{f: f}, nil
}

func (l *dirLock) release() error {
	if l == nil || l.f == nil {
		return nil
	}
	err := unix.Flock(int(l.f.Fd()), unix.LOCK_UN)
	if cerr := l.f.Close(); cerr != nil && err == nil {
		err = cerr
	}
	l.f = nil
	return err
}

// acquireDirLockNB is the non-blocking variant. It returns an error wrapping
// syscall.EWOULDBLOCK when another process holds the lock, so a verifier can
// refuse to read a ledger that may still be growing instead of hanging.
func acquireDirLockNB(dir string, shared bool) (*dirLock, error) {
	path := filepath.Join(dir, lockFileName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open ledger lock: %w", err)
	}
	op := unix.LOCK_EX | unix.LOCK_NB
	if shared {
		op = unix.LOCK_SH | unix.LOCK_NB
	}
	if err := unix.Flock(int(f.Fd()), op); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("acquire ledger lock: %w", err)
	}
	return &dirLock{f: f}, nil
}
