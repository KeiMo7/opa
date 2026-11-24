// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

// Package ledgerplugin exposes the tamper-evident decision ledger as an OPA
// decision log backend. It is selected by name through the standard
// decision_logs.plugin configuration key, so the existing buffer and upload
// behaviour is untouched when it is absent.
package ledgerplugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/open-policy-agent/opa/v1/logging"
	"github.com/open-policy-agent/opa/v1/plugins"
	"github.com/open-policy-agent/opa/v1/plugins/logs"
	"github.com/open-policy-agent/opa/v1/plugins/logs/ledger"
)

// Name identifies the plugin in the OPA configuration.
const Name = "ledger_logger"

var errLedgerNotStarted = errors.New("ledger logger is not started")

// Config is the plugin configuration. Ledger settings are embedded, so the
// accepted keys are the same ones ledger.Config documents.
type Config struct {
	ledger.Config
}

// Factory builds ledger-backed decision log plugins.
type Factory struct{}

// Validate parses and validates the plugin configuration.
func (*Factory) Validate(manager *plugins.Manager, raw []byte) (any, error) {
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse ledger logger config: %w", err)
	}
	if cfg.Directory == "" {
		if manager == nil {
			return nil, errors.New("ledger logger requires 'directory' to be specified when no plugin manager is available")
		}
		persistDir, err := manager.GetConfig().GetPersistenceDirectory()
		if err != nil {
			return nil, fmt.Errorf("ledger logger requires an explicit directory: %w", err)
		}
		cfg.Directory = filepath.Join(persistDir, "decision-ledger")
	}
	if cfg.InstanceID == "" && manager != nil {
		cfg.InstanceID = manager.ID
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid ledger logger config: %w", err)
	}
	return cfg, nil
}

// New constructs the plugin. The ledger directory is opened on Start.
func (*Factory) New(manager *plugins.Manager, config any) plugins.Plugin {
	return &Plugin{manager: manager, config: config.(Config)}
}

// Plugin implements the logs.Logger interface on top of a ledger.
type Plugin struct {
	manager *plugins.Manager
	config  Config
	ledger  *ledger.Ledger
}

var _ logs.Logger = (*Plugin)(nil)

// Name returns the plugin name.
func (*Plugin) Name() string { return Name }

func (p *Plugin) setStatus(state plugins.State, message string) {
	if p.manager == nil {
		return
	}
	p.manager.UpdatePluginStatus(Name, &plugins.Status{State: state, Message: message})
}

func (p *Plugin) logger() logging.Logger {
	if p.manager == nil {
		return nil
	}
	return p.manager.Logger()
}

// Start opens (or reopens and recovers) the ledger.
func (p *Plugin) Start(context.Context) error {
	l, err := ledger.Open(&p.config.Config)
	if err != nil {
		p.setStatus(plugins.StateErr, err.Error())
		return err
	}
	p.ledger = l.WithLogger(p.logger())
	p.setStatus(plugins.StateOK, "")
	return nil
}

// Stop closes the ledger, flushing queued records first.
func (p *Plugin) Stop(_ context.Context) {
	if p.ledger == nil {
		p.setStatus(plugins.StateNotReady, "")
		return
	}
	if err := p.ledger.Close(); err != nil && p.logger() != nil {
		p.logger().Error("Decision ledger close failed: %v", err)
	}
	p.ledger = nil
	p.setStatus(plugins.StateNotReady, "")
}

// Reconfigure swaps the ledger configuration. The directory cannot change at
// runtime: doing so would split the chain across directories.
func (p *Plugin) Reconfigure(_ context.Context, config any) {
	newCfg := config.(Config)
	if newCfg.Directory != p.config.Directory {
		if p.logger() != nil {
			p.logger().Error("Ledger directory cannot be reconfigured; keeping %q", p.config.Directory)
		}
		return
	}
	p.Stop(context.Background())
	p.config = newCfg
	if err := p.Start(context.Background()); err != nil && p.logger() != nil {
		p.logger().Error("Ledger reconfiguration failed: %v", err)
	}
}

// Log appends one already-masked decision event to the ledger. A returned
// error means the decision was not durably recorded; callers can reject the
// request instead of continuing without evidence.
func (p *Plugin) Log(ctx context.Context, event logs.EventV1) error {
	if p.ledger == nil {
		return errLedgerNotStarted
	}

	entry, err := p.toEntry(event)
	if err != nil {
		return err
	}
	return p.ledger.Append(ctx, entry)
}

// toEntry converts a decision log event into a ledger entry. Raw input never
// reaches this layer: only a salted digest is stored.
func (p *Plugin) toEntry(event logs.EventV1) (ledger.Entry, error) {
	inputDigest := ""
	if event.Input != nil {
		raw, err := json.Marshal(*event.Input)
		if err != nil {
			return ledger.Entry{}, fmt.Errorf("digest decision input: %w", err)
		}
		inputDigest = p.ledger.DigestInput(raw)
	}

	entry := ledger.Entry{
		DecisionID:  event.DecisionID,
		Timestamp:   event.Timestamp,
		Revision:    event.Revision,
		Path:        event.Path,
		InputDigest: inputDigest,
		LatencyNS:   evalLatencyNS(event.Metrics),
		Masked:      event.Masked,
		Erased:      event.Erased,
		Bundles:     bundleRevisions(event.Bundles),
	}
	if event.Error != nil {
		entry.DecisionErr = event.Error.Error()
	}
	if !p.config.RedactResult && event.Result != nil {
		entry.Result = *event.Result
	}
	if event.Result != nil {
		raw, err := json.Marshal(*event.Result)
		if err == nil {
			entry.ResultDigest = p.ledger.DigestBytes(raw)
		}
	}
	return entry, nil
}

// evalLatencyNS extracts the Rego evaluation timer OPA attaches to every
// decision. It returns zero when instrumentation is disabled.
func evalLatencyNS(m map[string]any) int64 {
	if m == nil {
		return 0
	}
	v, ok := m["timer_rego_query_eval_ns"]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case json.Number:
		i, _ := n.Int64()
		return i
	}
	return 0
}

func bundleRevisions(bundles map[string]logs.BundleInfoV1) map[string]any {
	if len(bundles) == 0 {
		return nil
	}
	out := make(map[string]any, len(bundles))
	for name, info := range bundles {
		out[name] = map[string]string{"revision": info.Revision}
	}
	return out
}
