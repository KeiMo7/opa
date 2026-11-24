// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package ledger

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
)

// Config configures a local tamper-evident decision ledger.
type Config struct {
	// Directory holds the segment and state files. It is created if missing.
	Directory string `json:"directory"`
	// Algorithm is one of HS256 (default), EdDSA, SHA256.
	Algorithm string `json:"algorithm,omitempty"`
	// KeyFile optionally points at an HMAC secret or PEM-encoded Ed25519 key.
	// When unset for HS256, a random secret is generated inside Directory and
	// persisted with 0600 permissions.
	KeyFile string `json:"key_file,omitempty"`
	// KeyID is recorded in every segment header to support future key
	// rotation; it is informational for HMAC and SHA256 ledgers.
	KeyID string `json:"key_id,omitempty"`
	// InstanceID identifies this writer in every record. When unset, a random
	// UUID is generated on first open and persisted in the state file.
	InstanceID string `json:"instance_id,omitempty"`
	// MaxRecordsPerSegment rotates the active segment after this many records.
	// Zero defaults to 10,000.
	MaxRecordsPerSegment uint64 `json:"max_records_per_segment,omitempty"`
	// MaxSegmentSizeMB rotates the active segment when it grows past this size.
	// Zero defaults to 32 MiB.
	MaxSegmentSizeMB uint64 `json:"max_segment_size_mb,omitempty"`
	// DiskLimitMB is the hard cap on total size of segment files in the
	// directory. The oldest sealed segments are evicted to stay under it; if
	// the active segment alone exceeds the limit, appends are rejected. Zero
	// defaults to 1 GiB.
	DiskLimitMB uint64 `json:"disk_limit_mb,omitempty"`
	// QueueSize bounds the in-memory append queue that applies backpressure
	// onto decision producers. Zero defaults to 1024.
	QueueSize uint64 `json:"queue_size,omitempty"`
	// RedactResult stores only a digest of the decision result instead of the
	// result itself, for environments where even masked results must not be
	// persisted locally.
	RedactResult bool `json:"redact_result,omitempty"`

	// diskLimitBytesOverride, when non-zero, replaces DiskLimitMB in byte
	// calculations. It is unexported and only used by tests that need a
	// sub-megabyte hard limit.
	diskLimitBytesOverride int64
	// maxSegmentBytesOverride, when non-zero, replaces MaxSegmentSizeMB in
	// byte calculations. It is unexported and only used by tests.
	maxSegmentBytesOverride int64
}

// Validate fills defaults and checks the configuration for errors.
func (c *Config) Validate() error {
	if c == nil {
		return errors.New("ledger config is nil")
	}
	if c.Directory == "" {
		return errors.New("ledger config: directory must be set")
	}
	switch c.Algorithm {
	case "":
		c.Algorithm = defaultAlgorithm
	case AlgHS256, AlgEdDSA, AlgSHA256:
	default:
		return fmt.Errorf("ledger config: unknown algorithm %q, expected one of %q, %q, %q", c.Algorithm, AlgHS256, AlgEdDSA, AlgSHA256)
	}
	if c.MaxRecordsPerSegment == 0 {
		c.MaxRecordsPerSegment = defaultMaxRecords
	}
	if c.MaxSegmentSizeMB == 0 {
		c.MaxSegmentSizeMB = defaultMaxSegmentMB
	}
	if c.DiskLimitMB == 0 {
		c.DiskLimitMB = defaultDiskLimitMB
	}
	if c.QueueSize == 0 {
		c.QueueSize = defaultQueueSize
	}
	if c.maxSegmentBytesOverride == 0 && c.diskLimitBytesOverride == 0 && c.MaxSegmentSizeMB > c.DiskLimitMB {
		return errors.New("ledger config: max_segment_size_mb must be <= disk_limit_mb")
	}
	return nil
}

func (c Config) maxSegmentBytes() int64 {
	if c.maxSegmentBytesOverride > 0 {
		return c.maxSegmentBytesOverride
	}
	return int64(c.MaxSegmentSizeMB) << 20
}

func (c Config) diskLimitBytes() int64 {
	if c.diskLimitBytesOverride > 0 {
		return c.diskLimitBytesOverride
	}
	return int64(c.DiskLimitMB) << 20
}

// signer produces and verifies the digest/signature envelopes. Implementations
// are stateless apart from their key material.
type signer interface {
	algorithm() string
	keyID() string
	// digest returns the hex digest that authenticates payload.
	digest(payload []byte) string
	// sign returns an Ed25519 signature over the hex digest bytes, or "" for
	// non-asymmetric algorithms.
	sign(digest string) (string, error)
	// verify checks digest (and sig, if applicable) against payload.
	verify(payload []byte, digest, sig string) error
}

// hmacSigner implements HS256.
type hmacSigner struct {
	key []byte
	id  string
}

func newHMACSigner(key []byte, id string) *hmacSigner {
	return &hmacSigner{key: key, id: id}
}

func (*hmacSigner) algorithm() string { return AlgHS256 }
func (s *hmacSigner) keyID() string   { return s.id }

func (s *hmacSigner) digest(payload []byte) string {
	mac := hmac.New(sha256.New, s.key)
	mac.Write(payload)
	return hexEncode(mac.Sum(nil))
}

func (*hmacSigner) sign(string) (string, error) { return "", nil }

func (s *hmacSigner) verify(payload []byte, digest, _ string) error {
	expected, err := decodeHex(digest)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, s.key)
	mac.Write(payload)
	if !hmac.Equal(expected, mac.Sum(nil)) {
		return errors.New("HMAC digest mismatch")
	}
	return nil
}

// plainSigner implements keyless SHA256.
type plainSigner struct{}

func (*plainSigner) algorithm() string           { return AlgSHA256 }
func (*plainSigner) keyID() string               { return "" }
func (*plainSigner) sign(string) (string, error) { return "", nil }

func (*plainSigner) digest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hexEncode(sum[:])
}

func (*plainSigner) verify(payload []byte, digest, _ string) error {
	expected, err := decodeHex(digest)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(payload)
	if !hmac.Equal(expected, sum[:]) {
		return errors.New("SHA-256 digest mismatch")
	}
	return nil
}

// ed25519Signer implements EdDSA. The verifier only needs the public key.
type ed25519Signer struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	id   string
}

func (*ed25519Signer) algorithm() string { return AlgEdDSA }
func (s *ed25519Signer) keyID() string   { return s.id }

func (*ed25519Signer) digest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hexEncode(sum[:])
}

func (s *ed25519Signer) sign(digest string) (string, error) {
	sig := ed25519.Sign(s.priv, []byte(digest))
	return hexEncode(sig), nil
}

func (s *ed25519Signer) verify(payload []byte, digest, sig string) error {
	sum := sha256.Sum256(payload)
	expected, err := decodeHex(digest)
	if err != nil {
		return err
	}
	if !hmac.Equal(expected, sum[:]) {
		return errors.New("SHA-256 digest mismatch")
	}
	if sig == "" {
		return errors.New("missing Ed25519 signature")
	}
	rawSig, err := hex.DecodeString(sig)
	if err != nil {
		return err
	}
	if !ed25519.Verify(s.pub, []byte(digest), rawSig) {
		return errors.New("Ed25519 signature mismatch")
	}
	return nil
}

// newSigner builds the signer for cfg. A pre-existing key file in the
// directory (auto-generated HS256) is loaded through persistedKey when cfg
// does not name one.
func newSigner(cfg *Config, persistedKey []byte) (signer, []byte, error) {
	switch cfg.Algorithm {
	case AlgSHA256:
		return &plainSigner{}, nil, nil

	case AlgEdDSA:
		if cfg.KeyFile == "" {
			return nil, nil, errors.New("ledger config: key_file is required for EdDSA")
		}
		pemBytes, err := os.ReadFile(cfg.KeyFile)
		if err != nil {
			return nil, nil, fmt.Errorf("read ledger key file: %w", err)
		}
		priv, err := parseEd25519PrivateKeyPEM(pemBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse ledger key file: %w", err)
		}
		return &ed25519Signer{priv: priv, pub: priv.Public().(ed25519.PublicKey), id: cfg.KeyID}, nil, nil

	default: // HS256
		if cfg.KeyFile != "" {
			key, err := os.ReadFile(cfg.KeyFile)
			if err != nil {
				return nil, nil, fmt.Errorf("read ledger key file: %w", err)
			}
			if len(key) < 32 {
				return nil, nil, errors.New("ledger HMAC key must be at least 32 bytes")
			}
			return newHMACSigner(key, cfg.KeyID), nil, nil
		}
		if len(persistedKey) >= 32 {
			return newHMACSigner(persistedKey, cfg.KeyID), persistedKey, nil
		}
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, nil, err
		}
		return newHMACSigner(key, cfg.KeyID), key, nil
	}
}

func decodeHex(s string) ([]byte, error) {
	if len(s) != digestLen {
		return nil, fmt.Errorf("invalid digest length %d", len(s))
	}
	out := make([]byte, digestLen/2)
	if _, err := hex.Decode(out, []byte(s)); err != nil {
		return nil, err
	}
	return out, nil
}
