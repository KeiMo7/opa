// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package ledger

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// persistedState is the small, atomically rewritten state file that lets a
// reopened ledger continue its sequence and digest chain without scanning
// every segment. It can always be rebuilt from the segments themselves.
type persistedState struct {
	Version         uint64 `json:"version"`
	InstanceID      string `json:"instance_id"`
	NextSeq         uint64 `json:"next_seq"`
	ActiveIndex     uint64 `json:"active_index"`
	ActiveRecords   uint64 `json:"active_records"`
	LastDigest      string `json:"last_digest"`
	LastSegmentHash string `json:"last_segment_hash"`
	Algorithm       string `json:"algorithm"`
	KeyID           string `json:"key_id,omitempty"`
	SaltB64         string `json:"salt_b64,omitempty"`
}

const stateVersion = 1

// writeStateFile persists state via the temp-file + rename convention and
// fsyncs both the file and the directory so a crash cannot leave a missing or
// partially renamed state file.
func writeStateFile(dir string, st persistedState) error {
	st.Version = stateVersion
	tmp, err := os.CreateTemp(dir, ".ledger-state.*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	enc := json.NewEncoder(tmp)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(&st); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, filepath.Join(dir, stateFileName)); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return syncDir(dir)
}

func readStateFile(dir string) (*persistedState, error) {
	raw, err := os.ReadFile(filepath.Join(dir, stateFileName))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var st persistedState
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("parse %s: %w", stateFileName, err)
	}
	if st.Version != stateVersion {
		return nil, fmt.Errorf("unsupported ledger state version %d", st.Version)
	}
	return &st, nil
}

// persistKey writes an auto-generated HMAC key with restrictive permissions.
func persistKey(dir string, key []byte) error {
	path := filepath.Join(dir, keyFileName)
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return err
	}
	return syncDir(dir)
}

// syncDir flushes a directory's metadata, which is required for a rename or
// new file to survive a crash on Linux.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// parseEd25519PrivateKeyPEM reads an ED25519 PRIVATE KEY PEM block (PKCS#8,
// as produced by openssl genpkey -algorithm ED25519).
func parseEd25519PrivateKeyPEM(raw []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	// PKCS#8 is the standard container for Ed25519 keys.
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("PEM block does not contain an Ed25519 private key")
	}
	return priv, nil
}

// ParseEd25519PublicKeyPEM reads an ED25519 PUBLIC KEY PEM block for offline
// verification.
func ParseEd25519PublicKeyPEM(raw []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("PEM block does not contain an Ed25519 public key")
	}
	return pub, nil
}
