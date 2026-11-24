// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

//go:build windows

package ledger

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// dirLock is an exclusive byte-range lock on the ledger directory's lock
// file. It prevents two OPA processes from appending to the same directory.
type dirLock struct {
	f *os.File
}

func acquireDirLock(dir string, shared bool) (*dirLock, error) {
	path := filepath.Join(dir, lockFileName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open ledger lock: %w", err)
	}
	flags := windows.LOCKFILE_EXCLUSIVE_LOCK
	if shared {
		flags = 0
	}
	var ol windows.Overlapped
	err = windows.LockFileEx(windows.Handle(f.Fd()), uint32(flags), 0, ^uint32(0), ^uint32(0), &ol)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("acquire ledger lock: %w", err)
	}
	return &dirLock{f: f}, nil
}

func (l *dirLock) release() error {
	if l == nil || l.f == nil {
		return nil
	}
	var ol windows.Overlapped
	err := windows.UnlockFileEx(windows.Handle(l.f.Fd()), 0, ^uint32(0), ^uint32(0), &ol)
	if cerr := l.f.Close(); cerr != nil && err == nil {
		err = cerr
	}
	l.f = nil
	return err
}

// acquireDirLockNB is the non-blocking variant. Windows LockFileEx has no
// non-blocking flag, so it behaves identically to acquireDirLock; concurrent
// writers on Windows are still fully serialized.
func acquireDirLockNB(dir string, shared bool) (*dirLock, error) {
	return acquireDirLock(dir, shared)
}
