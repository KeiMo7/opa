package server

import (
	"testing"

	"github.com/open-policy-agent/opa/v1/plugins"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
)

func TestDecisionCacheInvalidConfig(t *testing.T) {
	t.Parallel()

	cases := []string{
		`{"caching":{"decision_cache":{"enabled":true,"max_num_entries":-1}}}`,
		`{"caching":{"decision_cache":{"enabled":true,"max_size_bytes":-1}}}`,
		`{"caching":{"decision_cache":{"enabled":true,"ttl_seconds":-1}}}`,
		`{"caching":{"decision_cache":{"enabled":true,"negative_ttl_seconds":-1}}}`,
	}
	for _, raw := range cases {
		if _, err := plugins.New([]byte(raw), "test", inmem.New()); err == nil {
			t.Fatalf("expected error for config %s", raw)
		}
	}
}

func TestDecisionCacheDefaultsInjected(t *testing.T) {
	t.Parallel()

	raw := `{"caching":{"decision_cache":{"enabled":true}}}`
	m, err := plugins.New([]byte(raw), "test", inmem.New())
	if err != nil {
		t.Fatal(err)
	}
	cfg := m.InterQueryBuiltinCacheConfig()
	if cfg.DecisionCache == nil {
		t.Fatal("decision cache config missing")
	}
	if *cfg.DecisionCache.TTLSeconds != 30 || *cfg.DecisionCache.NegativeTTL != 5 {
		t.Fatalf("default TTLs not injected: %+v", cfg.DecisionCache)
	}
	if cfg.DecisionCache.Enabled != true {
		t.Fatal("enabled flag lost")
	}

	// Clone round trip preserves the section.
	cloned := cfg.Clone()
	if cloned.DecisionCache == nil || *cloned.DecisionCache.TTLSeconds != 30 {
		t.Fatalf("clone lost decision cache config: %+v", cloned)
	}
}
