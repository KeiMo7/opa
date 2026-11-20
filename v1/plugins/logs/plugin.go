// Copyright 2018 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

// Package logs implements decision log buffering and uploading.
package logs

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/internal/ref"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/logging"
	"github.com/open-policy-agent/opa/v1/metrics"
	"github.com/open-policy-agent/opa/v1/plugins"
	lstat "github.com/open-policy-agent/opa/v1/plugins/logs/status"
	"github.com/open-policy-agent/opa/v1/plugins/rest"
	"github.com/open-policy-agent/opa/v1/plugins/status"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/server"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/topdown"
	"github.com/open-policy-agent/opa/v1/util"
)

const DecisionLogType = "openpolicyagent.org/decision_logs"

// Logger defines the interface for decision logging plugins.
type Logger interface {
	plugins.Plugin

	Log(context.Context, EventV1) error
}

// EventV1 represents a decision log event.
// WARNING: The AST() function for EventV1 must be kept in sync with
// the struct. Any changes here MUST be reflected in the AST()
// implementation below.
type EventV1 struct {
	Labels              map[string]string       `json:"labels"`
	DecisionID          string                  `json:"decision_id"`
	BatchDecisionID     string                  `json:"batch_decision_id,omitempty"`
	TraceID             string                  `json:"trace_id,omitempty"`
	SpanID              string                  `json:"span_id,omitempty"`
	Revision            string                  `json:"revision,omitempty"` // Deprecated: Use Bundles instead
	Bundles             map[string]BundleInfoV1 `json:"bundles,omitempty"`
	Path                string                  `json:"path,omitempty"`
	Query               string                  `json:"query,omitempty"`
	Input               *any                    `json:"input,omitempty"`
	Result              *any                    `json:"result,omitempty"`
	IntermediateResults map[string]any          `json:"intermediate_results,omitempty"`
	MappedResult        *any                    `json:"mapped_result,omitempty"`
	NDBuiltinCache      *any                    `json:"nd_builtin_cache,omitempty"`
	Erased              []string                `json:"erased,omitempty"`
	Masked              []string                `json:"masked,omitempty"`
	MaskingVersion      string                  `json:"masking_version,omitempty"`
	Error               error                   `json:"error,omitempty"`
	RequestedBy         string                  `json:"requested_by,omitempty"`
	Timestamp           time.Time               `json:"timestamp"`
	Metrics             map[string]any          `json:"metrics,omitempty"`
	RequestID           uint64                  `json:"req_id,omitempty"`
	RuleLabels          []map[string]any        `json:"rule_labels,omitempty"`
	RuleID              string                  `json:"rule_id,omitempty"`
	RulePackage         string                  `json:"rule_package,omitempty"`
	PolicyVersion       string                  `json:"policy_version,omitempty"`
	RequestContext      *RequestContext         `json:"request_context,omitempty"`
	Custom              map[string]any          `json:"custom,omitempty"`
	Sampled             bool                    `json:"sampled,omitempty"`
	Truncated           bool                    `json:"truncated,omitempty"`
	TruncatedParts      []string                `json:"truncated_parts,omitempty"`

	inputAST ast.Value
}

// BundleInfoV1 describes a bundle associated with a decision log event.
type BundleInfoV1 struct {
	Revision string `json:"revision,omitempty"`
}

type RequestContext struct {
	HTTPRequest *HTTPRequestContext `json:"http,omitempty"`
}

type HTTPRequestContext struct {
	Headers map[string][]string `json:"headers,omitempty"`
}

// AST returns the BundleInfoV1 as an AST value
func (b *BundleInfoV1) AST() ast.Value {
	result := ast.NewObject()
	if len(b.Revision) > 0 {
		result.Insert(ast.InternedTerm("revision"), ast.StringTerm(b.Revision))
	}
	return result
}

// AST returns the Rego AST representation for a given EventV1 object.
// This avoids having to round trip through JSON while applying a decision log
// mask policy to the event.
func (e *EventV1) AST() (ast.Value, error) {
	var err error
	event := ast.NewObject(
		ast.Item(ast.InternedTerm("decision_id"), ast.StringTerm(e.DecisionID)),
	)

	if e.BatchDecisionID != "" {
		event.Insert(ast.InternedTerm("batch_decision_id"), ast.StringTerm(e.BatchDecisionID))
	}

	if e.TraceID != "" {
		event.Insert(ast.InternedTerm("trace_id"), ast.StringTerm(e.TraceID))
	}

	if e.SpanID != "" {
		event.Insert(ast.InternedTerm("span_id"), ast.StringTerm(e.SpanID))
	}

	if e.Labels != nil {
		labelsObj := ast.NewObject()
		for k, v := range e.Labels {
			labelsObj.Insert(ast.StringTerm(k), ast.StringTerm(v))
		}
		event.Insert(ast.InternedTerm("labels"), ast.NewTerm(labelsObj))
	} else {
		event.Insert(ast.InternedTerm("labels"), ast.NullTerm())
	}

	if len(e.Revision) > 0 {
		event.Insert(ast.InternedTerm("revision"), ast.StringTerm(e.Revision))
	}

	if len(e.Bundles) > 0 {
		bundlesObj := ast.NewObject()
		for k, v := range e.Bundles {
			bundlesObj.Insert(ast.StringTerm(k), ast.NewTerm(v.AST()))
		}
		event.Insert(ast.InternedTerm("bundles"), ast.NewTerm(bundlesObj))
	}

	if len(e.Path) > 0 {
		event.Insert(ast.InternedTerm("path"), ast.StringTerm(e.Path))
	}

	if len(e.Query) > 0 {
		event.Insert(ast.InternedTerm("query"), ast.StringTerm(e.Query))
	}

	if e.inputAST != nil {
		event.Insert(ast.InternedTerm("input"), ast.NewTerm(e.inputAST))
	} else if e.Input != nil {
		e.inputAST, err = roundtripJSONToAST(e.Input)
		if err != nil {
			return nil, err
		}
		event.Insert(ast.InternedTerm("input"), ast.NewTerm(e.inputAST))
	}

	if e.Result != nil {
		results, err := roundtripJSONToAST(e.Result)
		if err != nil {
			return nil, err
		}
		event.Insert(ast.InternedTerm("result"), ast.NewTerm(results))
	}

	if len(e.IntermediateResults) > 0 {
		iresults, err := roundtripJSONToAST(e.IntermediateResults)
		if err != nil {
			return nil, err
		}
		event.Insert(ast.InternedTerm("intermediate_results"), ast.NewTerm(iresults))
	}

	if e.MappedResult != nil {
		mResults, err := roundtripJSONToAST(e.MappedResult)
		if err != nil {
			return nil, err
		}
		event.Insert(ast.InternedTerm("mapped_result"), ast.NewTerm(mResults))
	}

	if e.NDBuiltinCache != nil {
		ndbCache, err := roundtripJSONToAST(e.NDBuiltinCache)
		if err != nil {
			return nil, err
		}
		event.Insert(ast.InternedTerm("nd_builtin_cache"), ast.NewTerm(ndbCache))
	}

	if len(e.Erased) > 0 {
		erased := make([]*ast.Term, len(e.Erased))
		for i, v := range e.Erased {
			erased[i] = ast.StringTerm(v)
		}
		event.Insert(ast.InternedTerm("erased"), ast.ArrayTerm(erased...))
	}

	if len(e.Masked) > 0 {
		masked := make([]*ast.Term, len(e.Masked))
		for i, v := range e.Masked {
			masked[i] = ast.StringTerm(v)
		}
		event.Insert(ast.InternedTerm("masked"), ast.ArrayTerm(masked...))
	}

	if len(e.MaskingVersion) > 0 {
		event.Insert(ast.InternedTerm("masking_version"), ast.StringTerm(e.MaskingVersion))
	}

	if e.Error != nil {
		evalErr, err := roundtripJSONToAST(e.Error)
		if err != nil {
			return nil, err
		}
		event.Insert(ast.InternedTerm("error"), ast.NewTerm(evalErr))
	}

	if len(e.RequestedBy) > 0 {
		event.Insert(ast.InternedTerm("requested_by"), ast.StringTerm(e.RequestedBy))
	}

	if len(e.RuleLabels) > 0 {
		v, err := ast.InterfaceToValue(e.RuleLabels)
		if err == nil {
			event.Insert(ast.InternedTerm("rule_labels"), ast.NewTerm(v))
		}
	}

	if len(e.RuleID) > 0 {
		event.Insert(ast.InternedTerm("rule_id"), ast.StringTerm(e.RuleID))
	}

	if len(e.RulePackage) > 0 {
		event.Insert(ast.InternedTerm("rule_package"), ast.StringTerm(e.RulePackage))
	}

	if len(e.PolicyVersion) > 0 {
		event.Insert(ast.InternedTerm("policy_version"), ast.StringTerm(e.PolicyVersion))
	}

	if e.Sampled {
		event.Insert(ast.InternedTerm("sampled"), ast.BooleanTerm(true))
	}

	if e.Truncated {
		event.Insert(ast.InternedTerm("truncated"), ast.BooleanTerm(true))
	}

	if len(e.TruncatedParts) > 0 {
		parts := make([]*ast.Term, len(e.TruncatedParts))
		for i, v := range e.TruncatedParts {
			parts[i] = ast.StringTerm(v)
		}
		event.Insert(ast.InternedTerm("truncated_parts"), ast.ArrayTerm(parts...))
	}

	// Use the timestamp JSON marshaller to ensure the format is the same as
	// round tripping through JSON.
	timeBytes, err := e.Timestamp.MarshalJSON()
	if err != nil {
		return nil, err
	}
	event.Insert(ast.InternedTerm("timestamp"), ast.StringTerm(strings.Trim(string(timeBytes), "\"")))

	if e.Metrics != nil {
		m, err := ast.InterfaceToValue(e.Metrics)
		if err != nil {
			return nil, err
		}
		event.Insert(ast.InternedTerm("metrics"), ast.NewTerm(m))
	}

	if e.RequestID > 0 {
		event.Insert(ast.InternedTerm("req_id"), ast.UIntNumberTerm(e.RequestID))
	}

	// The nesting mirrors the `omitempty` tags on RequestContext, so that a
	// mask policy sees the same shape as the uploaded event.
	if e.RequestContext != nil {
		requestContext := ast.NewObject()

		if httpRequest := e.RequestContext.HTTPRequest; httpRequest != nil {
			httpObj := ast.NewObject()

			if len(httpRequest.Headers) > 0 {
				headers := ast.NewObject()
				for name, values := range httpRequest.Headers {
					terms := make([]*ast.Term, len(values))
					for i, v := range values {
						terms[i] = ast.StringTerm(v)
					}
					headers.Insert(ast.StringTerm(name), ast.ArrayTerm(terms...))
				}
				httpObj.Insert(ast.InternedTerm("headers"), ast.NewTerm(headers))
			}

			requestContext.Insert(ast.InternedTerm("http"), ast.NewTerm(httpObj))
		}

		event.Insert(ast.InternedTerm("request_context"), ast.NewTerm(requestContext))
	}

	if len(e.Custom) > 0 {
		custom, err := roundtripJSONToAST(e.Custom)
		if err != nil {
			return nil, err
		}
		event.Insert(ast.InternedTerm("custom"), ast.NewTerm(custom))
	}

	return event, nil
}

func roundtripJSONToAST(x any) (ast.Value, error) {
	rawPtr := util.Reference(x)
	// roundtrip through json: this turns slices (e.g. []string, []bool) into
	// []any, the only array type ast.InterfaceToValue can work with
	if err := util.RoundTripFast(rawPtr); err != nil {
		return nil, err
	}

	return ast.InterfaceToValue(*rawPtr)
}

const (
	// min amount of time to wait following a failure
	minRetryDelay                       = time.Millisecond * 100
	defaultMinDelaySeconds              = int64(300)
	defaultMaxDelaySeconds              = int64(600)
	defaultBufferSizeLimitEvents        = int64(10000)
	defaultUploadSizeLimitBytes         = int64(32768)      // 32KB limit
	minUploadSizeLimitBytes             = int64(90)         // A single event with a decision ID (69 bytes) + empty gzip file (21 bytes)
	maxUploadSizeLimitBytes             = int64(4294967296) // about 4GB
	defaultBufferSizeLimitBytes         = int64(0)          // unlimited
	defaultMaskDecisionPath             = "/system/log/mask"
	defaultDropDecisionPath             = "/system/log/drop"
	logRateLimitExDropCounterName       = "decision_logs_dropped_rate_limit_exceeded"
	logBufferEventDropCounterName       = "decision_logs_dropped_buffer_size_limit_exceeded"
	logBufferSizeLimitExDropCounterName = "decision_logs_dropped_buffer_size_limit_bytes_exceeded"
	logEncodingFailureCounterName       = "decision_logs_encoding_failure"
	logChunkUploadedCounterName         = "decision_logs_chunks_uploaded"
	logChunkUploadFailedCounterName     = "decision_logs_chunks_upload_failed"
	logMaskFailureCounterName           = "decision_logs_masking_failure"
	logMaskParseFailureCounterName      = "decision_logs_masking_parse_failure"
	logMaskUndefinedDropCounterName     = "decision_logs_masking_undefined_path_dropped"
	logSampledCounterName               = "decision_logs_sampled"
	logTruncatedCounterName             = "decision_logs_truncated"
	defaultResourcePath                 = "/logs"
	sizeBufferType                      = "size"
	eventBufferType                     = "event"
)

// ReportingConfig represents configuration for the plugin's reporting behaviour.
type ReportingConfig struct {
	BufferType            string               `json:"buffer_type,omitempty"`              // toggles how the buffer stores events, defaults to using bytes
	BufferSizeLimitBytes  *int64               `json:"buffer_size_limit_bytes,omitempty"`  // max size of in-memory size buffer
	BufferSizeLimitEvents *int64               `json:"buffer_size_limit_events,omitempty"` // max size of in-memory event channel buffer
	UploadSizeLimitBytes  *int64               `json:"upload_size_limit_bytes,omitempty"`  // max size of upload payload
	MinDelaySeconds       *int64               `json:"min_delay_seconds,omitempty"`        // min amount of time to wait between successful poll attempts
	MaxDelaySeconds       *int64               `json:"max_delay_seconds,omitempty"`        // max amount of time to wait between poll attempts
	MaxDecisionsPerSecond *float64             `json:"max_decisions_per_second,omitempty"` // max number of decision logs to buffer per second
	Trigger               *plugins.TriggerMode `json:"trigger,omitempty"`                  // trigger mode
	// SampleRate optionally keeps only a fraction of decision events. A
	// sampled-out event is replaced by a summary event carrying its decision
	// ID, result and rule provenance. Values in (0,1]; 1 (or unset) keeps all.
	SampleRate *float64 `json:"sample_rate,omitempty"`
}

type RequestContextConfig struct {
	HTTPRequest *HTTPRequestContextConfig `json:"http,omitempty"`
}

type HTTPRequestContextConfig struct {
	Headers []string `json:"headers,omitempty"`
}

// Config represents the plugin configuration.
type Config struct {
	Plugin          *string              `json:"plugin"`
	Service         string               `json:"service"`
	PartitionName   string               `json:"partition_name,omitempty"`
	Reporting       ReportingConfig      `json:"reporting"`
	RequestContext  RequestContextConfig `json:"request_context"`
	MaskDecision    *string              `json:"mask_decision"`
	DropDecision    *string              `json:"drop_decision"`
	ConsoleLogs     bool                 `json:"console"`
	Resource        *string              `json:"resource"`
	NDBuiltinCache  bool                 `json:"nd_builtin_cache,omitempty"`
	Masking         MaskingConfig        `json:"masking,omitempty"`
	maskDecisionRef ast.Ref
	dropDecisionRef ast.Ref
}

// MaskingConfig controls how mask rule failures are handled.
type MaskingConfig struct {
	// UndefinedPathPolicy decides what happens when a mask rule targets a
	// path that does not exist or has an incompatible type. Valid values are
	// "drop" (default) and "clear".
	UndefinedPathPolicy string `json:"undefined_path_policy,omitempty"`
	// Version is an operator supplied label for the active mask rules. It is
	// recorded on each masked event. When empty, a digest of the effective
	// rules is used instead.
	Version string `json:"version,omitempty"`
}

func (c *Config) validateAndInjectDefaults(services []string, pluginsList []string, trigger *plugins.TriggerMode, l logging.Logger) error {

	if c.Plugin != nil {
		var found bool
		if slices.Contains(pluginsList, *c.Plugin) {
			found = true
		}
		if !found {
			return fmt.Errorf("invalid plugin name %q in decision_logs", *c.Plugin)
		}
	} else if c.Service == "" && len(services) != 0 && !c.ConsoleLogs {
		// For backwards compatibility allow defaulting to the first
		// service listed, but only if console logging is disabled. If enabled
		// we can't tell if the deployer wanted to use only console logs or
		// both console logs and the default service option.
		c.Service = services[0]
	} else if c.Service != "" {
		found := slices.Contains(services, c.Service)

		if !found {
			return fmt.Errorf("invalid service name %q in decision_logs", c.Service)
		}
	}

	t, err := plugins.ValidateAndInjectDefaultsForTriggerMode(trigger, c.Reporting.Trigger)
	if err != nil {
		return fmt.Errorf("invalid decision_log config: %w", err)
	}
	c.Reporting.Trigger = t

	min := defaultMinDelaySeconds
	max := defaultMaxDelaySeconds

	// reject bad min/max values
	if c.Reporting.MaxDelaySeconds != nil && c.Reporting.MinDelaySeconds != nil {
		if *c.Reporting.MaxDelaySeconds < *c.Reporting.MinDelaySeconds {
			return errors.New("max reporting delay must be >= min reporting delay in decision_logs")
		}
		min = *c.Reporting.MinDelaySeconds
		max = *c.Reporting.MaxDelaySeconds
	} else if c.Reporting.MaxDelaySeconds == nil && c.Reporting.MinDelaySeconds != nil {
		return errors.New("reporting configuration missing 'max_delay_seconds' in decision_logs")
	} else if c.Reporting.MinDelaySeconds == nil && c.Reporting.MaxDelaySeconds != nil {
		return errors.New("reporting configuration missing 'min_delay_seconds' in decision_logs")
	}

	// scale to seconds
	minSeconds := int64(time.Duration(min) * time.Second)
	c.Reporting.MinDelaySeconds = &minSeconds

	maxSeconds := int64(time.Duration(max) * time.Second)
	c.Reporting.MaxDelaySeconds = &maxSeconds

	// default the upload size limit
	uploadLimit := defaultUploadSizeLimitBytes
	if c.Reporting.UploadSizeLimitBytes != nil {
		uploadLimit = *c.Reporting.UploadSizeLimitBytes
	}

	switch {
	case uploadLimit > maxUploadSizeLimitBytes:
		maxUploadLimit := maxUploadSizeLimitBytes
		c.Reporting.UploadSizeLimitBytes = &maxUploadLimit
		if l != nil {
			l.Warn("the configured `upload_size_limit_bytes` (%d) has been set to the maximum limit (%d)", uploadLimit, maxUploadLimit)
		}
	case uploadLimit < minUploadSizeLimitBytes:
		minUploadLimit := minUploadSizeLimitBytes
		c.Reporting.UploadSizeLimitBytes = &minUploadLimit
		if l != nil {
			l.Warn("the configured `upload_size_limit_bytes` (%d) has been set to the minimum limit (%d)", uploadLimit, minUploadLimit)
		}
	default:
		c.Reporting.UploadSizeLimitBytes = &uploadLimit
	}

	if c.Reporting.BufferType == "" {
		c.Reporting.BufferType = sizeBufferType
	} else if c.Reporting.BufferType != eventBufferType && c.Reporting.BufferType != sizeBufferType {
		return fmt.Errorf("invalid buffer type %q, expected %q or %q", c.Reporting.BufferType, eventBufferType, sizeBufferType)
	}

	if c.Reporting.BufferType == eventBufferType && c.Reporting.BufferSizeLimitBytes != nil {
		return fmt.Errorf("invalid decision_log config, 'buffer_size_limit_bytes' isn't supported for the %v buffer type", eventBufferType)
	}
	if c.Reporting.BufferType == sizeBufferType && c.Reporting.BufferSizeLimitEvents != nil {
		return fmt.Errorf("invalid decision_log config, 'buffer_size_limit_events' isn't supported for the %v buffer type", sizeBufferType)
	}

	if c.Reporting.BufferSizeLimitBytes != nil && c.Reporting.MaxDecisionsPerSecond != nil {
		return errors.New("invalid decision_log config, specify either 'buffer_size_limit_bytes' or 'max_decisions_per_second'")
	}

	// default the buffer size limit
	sizeBufferLimit := defaultBufferSizeLimitBytes
	if c.Reporting.BufferSizeLimitBytes != nil {
		if *c.Reporting.BufferSizeLimitBytes <= int64(0) {
			return errors.New("invalid decision_log config, 'buffer_size_limit_bytes' must be higher than 0")
		}
		sizeBufferLimit = *c.Reporting.BufferSizeLimitBytes
	}
	c.Reporting.BufferSizeLimitBytes = &sizeBufferLimit

	eventBufferLimit := defaultBufferSizeLimitEvents
	if c.Reporting.BufferSizeLimitEvents != nil {
		if *c.Reporting.BufferSizeLimitEvents <= int64(0) {
			return errors.New("invalid decision_log config, 'buffer_size_limit_entries' must be higher than 0")
		}
		eventBufferLimit = *c.Reporting.BufferSizeLimitEvents
	}
	c.Reporting.BufferSizeLimitEvents = &eventBufferLimit

	if c.MaskDecision == nil {
		maskDecision := defaultMaskDecisionPath
		c.MaskDecision = &maskDecision
	}

	c.maskDecisionRef, err = ref.ParseDataPath(*c.MaskDecision)
	if err != nil {
		return fmt.Errorf("invalid mask_decision in decision_logs: %w", err)
	}

	if c.DropDecision == nil {
		dropDecision := defaultDropDecisionPath
		c.DropDecision = &dropDecision
	}

	c.dropDecisionRef, err = ref.ParseDataPath(*c.DropDecision)
	if err != nil {
		return fmt.Errorf("invalid drop_decision in decision_logs: %w", err)
	}

	switch c.Masking.UndefinedPathPolicy {
	case "", maskUndefinedDrop:
		c.Masking.UndefinedPathPolicy = maskUndefinedDrop
	case maskUndefinedClear:
	default:
		return fmt.Errorf("invalid masking.undefined_path_policy %q, expected %q or %q",
			c.Masking.UndefinedPathPolicy, maskUndefinedDrop, maskUndefinedClear)
	}

	if c.Reporting.SampleRate != nil {
		if *c.Reporting.SampleRate <= 0 || *c.Reporting.SampleRate > 1 {
			return fmt.Errorf("invalid reporting.sample_rate %v, expected a value in (0, 1]", *c.Reporting.SampleRate)
		}
	}

	if c.PartitionName != "" {
		resourcePath := fmt.Sprintf("/logs/%v", c.PartitionName)
		c.Resource = &resourcePath
	} else if c.Resource == nil {
		resourcePath := defaultResourcePath
		c.Resource = &resourcePath
	} else {
		if _, err := url.Parse(*c.Resource); err != nil {
			return fmt.Errorf("invalid resource path %q: %w", *c.Resource, err)
		}
	}

	return nil
}

type buffer interface {
	Name() string
	Push(*EventV1)
	Upload(context.Context) error
	WithMetrics(metrics.Metrics)
	Stop(context.Context)
	Flush() []*EventV1
	// Size returns how much is waiting in the buffer, in the unit its limit is
	// configured in: items for the event buffer, bytes for the size buffer.
	Size() int64
}

// Plugin implements decision log buffering and uploading.
type Plugin struct {
	manager       *plugins.Manager
	config        Config
	reconfigMtx   sync.RWMutex // reconfigMtx blocks reads/writes on buffer reconfiguration
	b             buffer
	statusMtx     sync.Mutex
	stop          chan chan struct{}
	reconfig      chan reconfigure
	preparedMask  preparedQueryCache
	preparedDrop  preparedQueryCache
	metrics       metrics.Metrics
	logger        logging.Logger
	status        *lstat.Status
	drops         *dropRecorder
	cachedSlogger *slog.Logger
	sloggerMtx    sync.RWMutex
}

// preparedQueryCache caches the prepared mask or drop query. The prepared query
// is tied to the compiler and plugin config it was built from, so it is dropped
// whenever either of those change.
type preparedQueryCache struct {
	// mtx guards the fields below. It is held across preparation so that a
	// concurrent drop() is ordered after it and invalidates the query that was
	// just cached, rather than being lost.
	mtx           sync.RWMutex
	prepared      bool
	preparedQuery *rego.PreparedEvalQuery
	err           error
}

// drop invalidates the cached query, so that the next caller prepares a new one.
func (pc *preparedQueryCache) drop() {
	pc.mtx.Lock()
	pc.prepared = false
	pc.preparedQuery = nil
	pc.err = nil
	pc.mtx.Unlock()
}

// prepare returns the cached query, preparing it with f if it isn't cached yet.
func (pc *preparedQueryCache) prepare(f func() (*rego.PreparedEvalQuery, error)) (*rego.PreparedEvalQuery, error) {
	pc.mtx.RLock()
	if pc.prepared {
		preparedQuery, err := pc.preparedQuery, pc.err
		pc.mtx.RUnlock()
		return preparedQuery, err
	}
	pc.mtx.RUnlock()

	pc.mtx.Lock()
	defer pc.mtx.Unlock()

	// another caller may have prepared the query while the write lock was
	// being acquired
	if pc.prepared {
		return pc.preparedQuery, pc.err
	}

	pc.preparedQuery, pc.err = f()
	pc.prepared = true

	return pc.preparedQuery, pc.err
}

type reconfigure struct {
	config any
	done   chan struct{}
}

// ParseConfig validates the config and injects default values.
func ParseConfig(config []byte, services []string, pluginList []string) (*Config, error) {
	t := plugins.DefaultTriggerMode
	return NewConfigBuilder().
		WithBytes(config).
		WithServices(services).
		WithPlugins(pluginList).
		WithTriggerMode(&t).
		Parse()
}

// ConfigBuilder assists in the construction of the plugin configuration.
type ConfigBuilder struct {
	raw      []byte
	services []string
	plugins  []string
	trigger  *plugins.TriggerMode
	logger   logging.Logger
}

// NewConfigBuilder returns a new ConfigBuilder to build and parse the plugin config.
func NewConfigBuilder() *ConfigBuilder {
	return &ConfigBuilder{}
}

func (b *ConfigBuilder) WithLogger(l logging.Logger) *ConfigBuilder {
	b.logger = l
	return b
}

// WithBytes sets the raw plugin config.
func (b *ConfigBuilder) WithBytes(config []byte) *ConfigBuilder {
	b.raw = config
	return b
}

// WithServices sets the services that implement control plane APIs.
func (b *ConfigBuilder) WithServices(services []string) *ConfigBuilder {
	b.services = services
	return b
}

// WithPlugins sets the list of named plugins for decision logging.
func (b *ConfigBuilder) WithPlugins(plugins []string) *ConfigBuilder {
	b.plugins = plugins
	return b
}

// WithTriggerMode sets the plugin trigger mode.
func (b *ConfigBuilder) WithTriggerMode(trigger *plugins.TriggerMode) *ConfigBuilder {
	b.trigger = trigger
	return b
}

// Parse validates the config and injects default values.
func (b *ConfigBuilder) Parse() (*Config, error) {
	if b.raw == nil {
		return nil, nil
	}

	var parsedConfig Config

	if err := util.Unmarshal(b.raw, &parsedConfig); err != nil {
		return nil, err
	}

	if parsedConfig.Plugin == nil && parsedConfig.Service == "" && len(b.services) == 0 && !parsedConfig.ConsoleLogs {
		// Nothing to validate or inject
		return nil, nil
	}

	if err := parsedConfig.validateAndInjectDefaults(b.services, b.plugins, b.trigger, b.logger); err != nil {
		return nil, err
	}

	return &parsedConfig, nil
}

// New returns a new Plugin with the given config.
func New(parsedConfig *Config, manager *plugins.Manager) *Plugin {
	plugin := &Plugin{
		manager:  manager,
		config:   *parsedConfig,
		stop:     make(chan chan struct{}),
		reconfig: make(chan reconfigure),
		logger:   manager.Logger().WithFields(map[string]any{"plugin": Name}),
		status:   &lstat.Status{},
		drops:    newDropRecorder(defaultDropRecordLimit, manager.Logger().WithFields(map[string]any{"plugin": Name})),
	}

	switch parsedConfig.Reporting.BufferType {
	case eventBufferType:
		plugin.b = newEventBuffer(
			*parsedConfig.Reporting.BufferSizeLimitEvents,
			*parsedConfig.Reporting.UploadSizeLimitBytes,
			plugin.manager.Client(plugin.config.Service),
			*parsedConfig.Resource,
			*parsedConfig.Reporting.Trigger,
		).WithLogger(plugin.logger).WithLimiter(parsedConfig.Reporting.MaxDecisionsPerSecond)
		plugin.b.(*eventBuffer).onDrop = plugin.dropCallback()
		plugin.b.(*eventBuffer).enc.onDrop = plugin.encoderDropCallback()
	case sizeBufferType:
		plugin.b = newSizeBuffer(
			*parsedConfig.Reporting.BufferSizeLimitBytes,
			*parsedConfig.Reporting.UploadSizeLimitBytes,
			plugin.manager.Client(plugin.config.Service),
			*parsedConfig.Resource,
			*parsedConfig.Reporting.Trigger,
		).WithLogger(plugin.logger).WithLimiter(parsedConfig.Reporting.MaxDecisionsPerSecond)
		plugin.b.(*sizeBuffer).onDrop = plugin.dropCallback()
		plugin.b.(*sizeBuffer).enc.onDrop = plugin.encoderDropCallback()
	}

	manager.RegisterCompilerTrigger(plugin.compilerUpdated)

	manager.UpdatePluginStatus(Name, &plugins.Status{State: plugins.StateNotReady})

	return plugin
}

// WithMetrics sets the global metrics provider to be used by the plugin.
func (p *Plugin) WithMetrics(m metrics.Metrics) *Plugin {
	p.metrics = m
	p.b.WithMetrics(m)
	return p
}

// Name identifies the plugin on manager.
const Name = "decision_logs"

// Lookup returns the decision logs plugin registered with the manager.
func Lookup(manager *plugins.Manager) *Plugin {
	if p := manager.Plugin(Name); p != nil {
		return p.(*Plugin)
	}
	return nil
}

// Start starts the plugin.
func (p *Plugin) Start(_ context.Context) error {
	p.logger.Info("Starting decision logger.")
	go p.loop()
	p.manager.UpdatePluginStatus(Name, &plugins.Status{State: plugins.StateOK})
	return nil
}

// Stop stops the plugin.
func (p *Plugin) Stop(ctx context.Context) {
	p.logger.Info("Stopping decision logger.")
	p.b.Stop(ctx)

	if *p.config.Reporting.Trigger == plugins.TriggerPeriodic || *p.config.Reporting.Trigger == plugins.TriggerImmediate {
		if _, ok := ctx.Deadline(); ok && p.config.Service != "" {
			p.flushDecisions(ctx)
		}
	}

	done := make(chan struct{})
	p.stop <- done
	<-done
	p.manager.UpdatePluginStatus(Name, &plugins.Status{State: plugins.StateNotReady})
}

// Config returns the plugin's current configuration
func (p *Plugin) Config() *Config {
	return &p.config
}

// BufferSize returns the configured buffer type and how much is waiting in the
// buffer to be uploaded: items for the event buffer, bytes for the size buffer.
func (p *Plugin) BufferSize() (bufferType string, size int64) {
	p.reconfigMtx.RLock()
	b := p.b
	p.reconfigMtx.RUnlock()
	return b.Name(), b.Size()
}

func (p *Plugin) flushDecisions(ctx context.Context) {
	p.logger.Info("Flushing decision logs.")

	done := make(chan bool)

	go func(ctx context.Context, done chan bool) {
		for ctx.Err() == nil {
			if err := p.b.Upload(ctx); err != nil && !util.ErrorIs[*bufferEmpty](err) {
				p.logger.Error("Error flushing decisions: %s", err)
				// Wait some before retrying, but skip incrementing interval since we are shutting down
				time.Sleep(1 * time.Second)
			} else {
				done <- true
				return
			}
		}
	}(ctx, done)

	select {
	case <-done:
		p.logger.Info("All decisions in buffer uploaded.")
	case <-ctx.Done():
		switch ctx.Err() {
		case context.DeadlineExceeded, context.Canceled:
			p.logger.Error("Plugin stopped with decisions possibly still in buffer.")
		}
	}
}

// Log appends a decision log event to the buffer for uploading.
func (p *Plugin) Log(ctx context.Context, decision *server.Info) error {
	bundles := map[string]BundleInfoV1{}
	for name, info := range decision.Bundles {
		bundles[name] = BundleInfoV1{Revision: info.Revision}
	}

	event := EventV1{
		Labels:              p.manager.Labels(),
		DecisionID:          decision.DecisionID,
		BatchDecisionID:     decision.BatchDecisionID,
		TraceID:             decision.TraceID,
		SpanID:              decision.SpanID,
		Revision:            decision.Revision,
		Bundles:             bundles,
		Path:                decision.Path,
		Query:               decision.Query,
		Input:               decision.Input,
		Result:              decision.Results,
		IntermediateResults: decision.IntermediateResults,
		MappedResult:        decision.MappedResults,
		NDBuiltinCache:      decision.NDBuiltinCache,
		RequestedBy:         decision.RemoteAddr,
		Timestamp:           decision.Timestamp,
		RequestID:           decision.RequestID,
		RuleLabels:          decision.EvaluatedRuleLabels,
		inputAST:            decision.InputAST,
		Custom:              decision.Custom,
	}

	headers := map[string][]string{}
	rctx := p.config.RequestContext

	if rctx.HTTPRequest != nil && len(rctx.HTTPRequest.Headers) > 0 && decision.HTTPRequestContext.Header != nil {
		for _, h := range rctx.HTTPRequest.Headers {
			values := decision.HTTPRequestContext.Header.Values(h)
			if len(values) > 0 {
				headers[h] = decision.HTTPRequestContext.Header.Values(h)
			}
		}
	}

	if len(headers) > 0 {
		event.RequestContext = &RequestContext{HTTPRequest: &HTTPRequestContext{Headers: headers}}
	}

	// Metrics and Error must be attached before the policy input is built, otherwise
	// the mask and drop policies cannot observe them. EventV1.AST() serializes both.
	if decision.Metrics != nil {
		event.Metrics = decision.Metrics.All()
	}

	if decision.Error != nil {
		event.Error = decision.Error
	}

	// Record which rule, package and per-policy version determined the
	// decision. Decisions produced by the server and SDK always carry this
	// (with deterministic placeholders when nothing was tracked). Callers that
	// construct events directly and leave it unset keep the historical event
	// shape, so their output is unchanged.
	if rule := decision.EvaluatedRule; rule != (topdown.EvaluatedRule{}) {
		event.RuleID = cmp.Or(rule.ID, topdown.UnknownRuleID)
		event.RulePackage = cmp.Or(rule.Package, topdown.UnknownRulePackage)
		event.PolicyVersion = cmp.Or(rule.Version, topdown.UnversionedPolicyVersion)
	}

	input, err := event.AST()
	if err != nil {
		return err
	}

	drop, err := p.dropEvent(ctx, decision.Txn, input)
	if err != nil {
		p.logger.Error("Log drop decision failed: %v.", err)
		return nil
	}

	if drop {
		p.logger.Debug("Decision log event to path %v dropped", event.Path)
		return nil
	}

	dropped, err := p.maskEvent(ctx, decision.Txn, input, &event)
	if err != nil {
		// A mask evaluation failure means the event may still carry raw
		// values. It must not be persisted; count it instead.
		p.incrMetric(logMaskFailureCounterName)
		p.recordDrop(event, dropReasonMaskFailure)
		p.logger.Error("Log event masking failed: %v.", err)
		return nil
	}
	if dropped {
		// The mask policy could not be applied and the selected policy is to
		// drop the event rather than persist it unmasked.
		return nil
	}

	// Sampling happens after masking so that a retained summary never carries
	// values the mask policy removed. Sampled-out events keep just enough to
	// correlate them: decision ID, result and rule provenance.
	if sampled, ok := p.sampleEvent(event); ok {
		p.incrMetric(logSampledCounterName)
		event = sampled
	}

	if p.config.ConsoleLogs {
		p.logEvent(event)
	}

	if p.config.Service != "" {
		p.push(event)
	}

	if p.config.Plugin != nil {
		plugin := p.manager.Plugin(*p.config.Plugin)
		if plugin == nil {
			return fmt.Errorf("plugin %q not found", *p.config.Plugin)
		}

		switch l := plugin.(type) {
		case Logger:
			return l.Log(ctx, event)
		case plugins.LoggerPlugin:
			logger, err := p.getSlogLogger(l)
			if err != nil {
				return err
			}
			logger.LogAttrs(ctx, slog.LevelInfo, "Decision Log", eventToAttrs(event)...)
			return nil
		}

		return fmt.Errorf("plugin %q does not implement Logger or LoggerPlugin interface", *p.config.Plugin)
	}

	return nil
}

// sampleEvent applies the configured sample rate. It returns the summary event
// and true when the event is sampled out. The summary deliberately keeps only
// the identifiers needed to correlate it with the full decision: decision ID,
// result, rule provenance and timestamp. It never carries input, headers or
// other values the mask policy may have removed.
func (p *Plugin) sampleEvent(event EventV1) (EventV1, bool) {
	rate := p.config.Reporting.SampleRate
	if rate == nil || *rate >= 1 {
		return event, false
	}
	if rand.Float64() < *rate {
		return event, false
	}

	return EventV1{
		DecisionID:    event.DecisionID,
		Path:          event.Path,
		Query:         event.Query,
		Result:        event.Result,
		RuleID:        event.RuleID,
		RulePackage:   event.RulePackage,
		PolicyVersion: event.PolicyVersion,
		Timestamp:     event.Timestamp,
		Sampled:       true,
	}, true
}

func (p *Plugin) getSlogLogger(l plugins.LoggerPlugin) (*slog.Logger, error) {
	p.sloggerMtx.RLock()
	if p.cachedSlogger != nil {
		logger := p.cachedSlogger
		p.sloggerMtx.RUnlock()
		return logger, nil
	}
	p.sloggerMtx.RUnlock()

	p.sloggerMtx.Lock()
	defer p.sloggerMtx.Unlock()

	if p.cachedSlogger != nil {
		return p.cachedSlogger, nil
	}

	handler := l.Logger()
	if handler == nil {
		return nil, fmt.Errorf("plugin %q returned nil logger", *p.config.Plugin)
	}

	p.cachedSlogger = slog.New(handler)
	return p.cachedSlogger, nil
}

func (p *Plugin) clearSlogCache() {
	p.sloggerMtx.Lock()
	p.cachedSlogger = nil
	p.sloggerMtx.Unlock()
}

// Reconfigure notifies the plugin with a new configuration.
func (p *Plugin) Reconfigure(_ context.Context, config any) {

	done := make(chan struct{})
	p.reconfig <- reconfigure{config: config, done: done}
	<-done

	// Drop the cached queries only once the new config is installed. Dropping
	// them earlier lets a concurrent Log() re-prepare against the old config and
	// cache it, leaving the new mask/drop decision paths without effect.
	p.preparedMask.drop()
	p.preparedDrop.drop()
	p.clearSlogCache()

	go p.loop()
}

// Trigger can be used to control when the plugin attempts to upload
// a new decision log in manual triggering mode.
func (p *Plugin) Trigger(ctx context.Context) error {
	done := make(chan error)

	go func() {
		if p.config.Service != "" {
			err := p.doOneShot(ctx)
			if err != nil {
				if ctx.Err() == nil {
					done <- err
				}
			}
		}
		close(done)
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// compilerUpdated is called when a compiler trigger on the plugin manager
// fires. This indicates a new compiler instance is available. The decision
// logger needs to prepare a new masking query.
func (p *Plugin) compilerUpdated(storage.Transaction) {
	p.preparedMask.drop()
	p.preparedDrop.drop()
}

func (p *Plugin) loop() {
	ctx, cancel := context.WithCancel(context.Background())

	var retry int

	for {
		var waitC chan struct{}

		if (*p.config.Reporting.Trigger == plugins.TriggerPeriodic || *p.config.Reporting.Trigger == plugins.TriggerImmediate) && p.config.Service != "" {
			p.reconfigMtx.RLock()

			err := p.doOneShot(ctx)

			var delay time.Duration

			if err == nil {
				min := float64(*p.config.Reporting.MinDelaySeconds)
				max := float64(*p.config.Reporting.MaxDelaySeconds)
				delay = time.Duration(((max - min) * rand.Float64()) + min)
			} else {
				delay = util.DefaultBackoff(float64(minRetryDelay), float64(*p.config.Reporting.MaxDelaySeconds), retry)
			}

			p.reconfigMtx.RUnlock()

			p.logger.Debug("Waiting %v before next upload/retry.", delay)

			waitC = make(chan struct{})
			go func() {
				timer := time.NewTimer(delay)
				select {
				case <-timer.C:
					if err != nil {
						retry++
					} else {
						retry = 0
					}
					close(waitC)
					return
				case <-ctx.Done():
					timer.Stop()
					return
				}
			}()
		}

		select {
		case <-waitC:
		case update := <-p.reconfig:
			cancel() // need to cancel so that the timer loop is closed and reset
			p.reconfigure(ctx, update.config)
			update.done <- struct{}{}
			return
		case done := <-p.stop:
			cancel()
			done <- struct{}{}
			return
		}
	}
}

type bufferEmpty struct{}

func (*bufferEmpty) Error() string {
	return "buffer is empty"
}

type uploadCancelled struct{}

func (*uploadCancelled) Error() string {
	return "cancelled upload"
}

func (p *Plugin) doOneShot(ctx context.Context) (err error) {
	if err = p.b.Upload(ctx); err != nil {
		if util.ErrorIs[*bufferEmpty](err) {
			p.logger.Debug("Log upload queue was empty.")
			err = nil
		} else if util.ErrorIs[*uploadCancelled](err) {
			err = nil
		} else {
			p.logger.Error("%v.", err)
		}
	} else {
		p.logger.Info("Logs uploaded successfully.")
	}

	p.setStatus(err)
	return err
}

func (p *Plugin) reconfigure(ctx context.Context, config any) {
	newConfig := config.(*Config)

	if reflect.DeepEqual(p.config, *newConfig) {
		p.logger.Debug("Decision log uploader configuration unchanged.")
		return
	}

	p.reconfigMtx.Lock()
	defer p.reconfigMtx.Unlock()

	p.logger.Info("Decision log uploader configuration changed.")
	p.config = *newConfig

	// upload all events in the current buffer type
	if err := p.b.Upload(ctx); err != nil && !util.ErrorIs[*bufferEmpty](err) {
		p.setStatus(err)
	}
	p.b.Stop(ctx)
	events := p.b.Flush()

	switch newConfig.Reporting.BufferType {
	case eventBufferType:
		p.b = newEventBuffer(
			*p.config.Reporting.BufferSizeLimitEvents,
			*p.config.Reporting.UploadSizeLimitBytes,
			p.manager.Client(p.config.Service),
			*p.config.Resource,
			*p.config.Reporting.Trigger,
		).WithLogger(p.logger).WithLimiter(p.config.Reporting.MaxDecisionsPerSecond)
		p.b.(*eventBuffer).onDrop = p.dropCallback()
		p.b.(*eventBuffer).enc.onDrop = p.encoderDropCallback()
	case sizeBufferType:
		p.b = newSizeBuffer(
			*p.config.Reporting.BufferSizeLimitBytes,
			*p.config.Reporting.UploadSizeLimitBytes,
			p.manager.Client(p.config.Service),
			*p.config.Resource,
			*p.config.Reporting.Trigger,
		).WithLogger(p.logger).WithLimiter(p.config.Reporting.MaxDecisionsPerSecond)
		p.b.(*sizeBuffer).onDrop = p.dropCallback()
		p.b.(*sizeBuffer).enc.onDrop = p.encoderDropCallback()
	}
	p.b.WithMetrics(p.metrics)

	for _, event := range events {
		p.b.Push(event)
	}
}

func (p *Plugin) push(event EventV1) {
	// only blocks when the buffer is being reconfigured
	p.reconfigMtx.RLock()
	defer p.reconfigMtx.RUnlock()

	p.b.Push(&event)
}

func (p *Plugin) incrMetric(name string) {
	if p.metrics != nil {
		p.metrics.Counter(name).Incr()
	}
}

// recordDrop stores a searchable drop record for an event that will not be
// persisted. It intentionally keeps only identifiers, never event values.
func (p *Plugin) recordDrop(event EventV1, reason string) {
	if p.drops == nil {
		return
	}
	p.drops.record(DropRecord{
		DecisionID:    event.DecisionID,
		Reason:        reason,
		Time:          time.Now().UTC(),
		RuleID:        event.RuleID,
		PolicyVersion: event.PolicyVersion,
	})
}

// dropCallback adapts recording for buffers, which only have an event pointer.
func (p *Plugin) dropCallback() func(*EventV1, string) {
	return func(event *EventV1, reason string) {
		if event == nil {
			return
		}
		p.recordDrop(*event, reason)
	}
}

// encoderDropCallback records events discarded by the chunk encoder.
func (p *Plugin) encoderDropCallback() func(EventV1) {
	return func(event EventV1) {
		p.recordDrop(event, dropReasonEncoding)
	}
}

// maskEvent applies the configured mask policy to event. It returns true when
// the event must be dropped because a mask rule could not be applied while the
// drop policy is in effect, or because the rule set could not be parsed (the
// conservative mode required to avoid persisting unmasked values).
func (p *Plugin) maskEvent(ctx context.Context, txn storage.Transaction, input ast.Value, event *EventV1) (dropped bool, err error) {
	pq, err := p.preparedMask.prepare(func() (*rego.PreparedEvalQuery, error) {
		var pq rego.PreparedEvalQuery

		query := ast.NewBody(ast.NewExpr(ast.NewTerm(p.config.maskDecisionRef)))

		r := rego.New(
			rego.ParsedQuery(query),
			rego.Compiler(p.manager.GetCompiler()),
			rego.Store(p.manager.Store),
			rego.Transaction(txn),
			rego.Runtime(p.manager.Info),
			rego.EnablePrintStatements(p.manager.EnablePrintStatements()),
			rego.PrintHook(p.manager.PrintHook()),
		)

		pq, err := r.PrepareForEval(context.Background())
		if err != nil {
			return nil, err
		}
		return &pq, nil
	})

	if err != nil {
		return false, err
	}

	rs, err := pq.Eval(
		ctx,
		rego.EvalParsedInput(input),
		rego.EvalTransaction(txn),
	)

	if err != nil {
		return false, err
	} else if len(rs) == 0 {
		return false, nil
	}

	mRuleSet, err := newMaskRuleSet(
		rs[0].Expressions[0].Value,
		func(mRule *maskRule, err error) {
			p.logger.Error("mask rule skipped: %s: %s", mRule.String(), err.Error())
		},
	)
	if err != nil {
		// A rule set that cannot be parsed cannot be trusted to have removed
		// sensitive data. Drop the event rather than persist it unmasked.
		p.incrMetric(logMaskParseFailureCounterName)
		p.recordDrop(*event, dropReasonMaskParse)
		return true, nil
	}

	mRuleSet.UndefinedPolicy = p.config.Masking.UndefinedPathPolicy
	mRuleSet.MaskVersion = p.maskingVersion(mRuleSet)

	if mRuleSet.Mask(event) {
		p.incrMetric(logMaskUndefinedDropCounterName)
		p.recordDrop(*event, dropReasonMaskUndefined)
		return true, nil
	}

	if len(mRuleSet.Rules) > 0 {
		event.MaskingVersion = mRuleSet.MaskVersion
	}

	return false, nil
}

// maskingVersion returns the version recorded on masked events. An operator
// supplied version takes precedence; otherwise a digest of the effective
// rules is used so that events can always be tied to masking semantics.
func (p *Plugin) maskingVersion(rs *maskRuleSet) string {
	if p.config.Masking.Version != "" {
		return p.config.Masking.Version
	}
	return rs.Digest()
}

func (p *Plugin) dropEvent(ctx context.Context, txn storage.Transaction, input ast.Value) (bool, error) {
	var err error

	pq, err := p.preparedDrop.prepare(func() (*rego.PreparedEvalQuery, error) {
		var pq rego.PreparedEvalQuery

		query := ast.NewBody(ast.NewExpr(ast.NewTerm(p.config.dropDecisionRef)))
		r := rego.New(
			rego.ParsedQuery(query),
			rego.Compiler(p.manager.GetCompiler()),
			rego.Store(p.manager.Store),
			rego.Transaction(txn),
			rego.Runtime(p.manager.Info),
			rego.EnablePrintStatements(p.manager.EnablePrintStatements()),
			rego.PrintHook(p.manager.PrintHook()),
		)

		pq, err := r.PrepareForEval(context.Background())
		if err != nil {
			return nil, err
		}
		return &pq, nil
	})

	if err != nil {
		return false, err
	}

	rs, err := pq.Eval(
		ctx,
		rego.EvalParsedInput(input),
		rego.EvalTransaction(txn),
	)

	if err != nil {
		return false, err
	}

	return rs.Allowed(), nil
}

// uploadChunk uploads a single chunk and counts the outcome on m, if set.
func uploadChunk(ctx context.Context, client rest.Client, uploadPath string, data []byte, m metrics.Metrics) error {
	err := doUploadChunk(ctx, client, uploadPath, data)
	if m != nil {
		if err != nil {
			m.Counter(logChunkUploadFailedCounterName).Incr()
		} else {
			m.Counter(logChunkUploadedCounterName).Incr()
		}
	}
	return err
}

func doUploadChunk(ctx context.Context, client rest.Client, uploadPath string, data []byte) error {

	resp, err := client.
		WithHeader("Content-Type", "application/json").
		WithHeader("Content-Encoding", "gzip").
		WithBytes(data).
		Do(ctx, "POST", uploadPath)

	if err != nil {
		return fmt.Errorf("log upload failed: %w", err)
	}

	defer util.Close(resp)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return lstat.HTTPError{StatusCode: resp.StatusCode}
	}

	return nil
}

func (p *Plugin) logEvent(event EventV1) {
	fields := eventToFields(event)
	p.manager.ConsoleLogger().WithFields(fields).Info("Decision Log")
}

func addAttrIfNonZeroString(attrs *[]slog.Attr, key string, value string) {
	if value != "" {
		*attrs = append(*attrs, slog.String(key, value))
	}
}

func addAttrIfNonZero[T comparable](attrs *[]slog.Attr, key string, value T) {
	var zero T
	if value != zero {
		*attrs = append(*attrs, slog.Any(key, value))
	}
}

func addAttrIfNotNil[T any](attrs *[]slog.Attr, key string, value *T) {
	if value != nil {
		*attrs = append(*attrs, slog.Any(key, *value))
	}
}

func addAttrIfHasLen[M ~map[K]V, K comparable, V any](attrs *[]slog.Attr, key string, value M) {
	if len(value) > 0 {
		*attrs = append(*attrs, slog.Any(key, value))
	}
}

func addAttrIfSliceNotEmpty[T any](attrs *[]slog.Attr, key string, value []T) {
	if len(value) > 0 {
		*attrs = append(*attrs, slog.Any(key, value))
	}
}

func eventToAttrs(event EventV1) []slog.Attr {
	attrs := make([]slog.Attr, 0, 24)
	attrs = append(attrs,
		slog.String("type", DecisionLogType),
		slog.Time("timestamp", event.Timestamp),
		slog.String("decision_id", event.DecisionID))
	addAttrIfNonZeroString(&attrs, "batch_decision_id", event.BatchDecisionID)
	addAttrIfNonZeroString(&attrs, "trace_id", event.TraceID)
	addAttrIfNonZeroString(&attrs, "span_id", event.SpanID)
	addAttrIfHasLen(&attrs, "labels", event.Labels)
	addAttrIfNonZeroString(&attrs, "revision", event.Revision)
	addAttrIfHasLen(&attrs, "bundles", event.Bundles)
	addAttrIfNonZeroString(&attrs, "path", event.Path)
	addAttrIfNonZeroString(&attrs, "query", event.Query)
	addAttrIfNotNil(&attrs, "input", event.Input)
	addAttrIfNotNil(&attrs, "result", event.Result)
	addAttrIfHasLen(&attrs, "intermediate_results", event.IntermediateResults)
	addAttrIfNotNil(&attrs, "mapped_result", event.MappedResult)
	addAttrIfNotNil(&attrs, "nd_builtin_cache", event.NDBuiltinCache)
	addAttrIfSliceNotEmpty(&attrs, "erased", event.Erased)
	addAttrIfSliceNotEmpty(&attrs, "masked", event.Masked)
	addAttrIfNonZeroString(&attrs, "masking_version", event.MaskingVersion)

	if event.Error != nil {
		attrs = append(attrs, slog.String("error", event.Error.Error()))
	}

	addAttrIfNonZeroString(&attrs, "requested_by", event.RequestedBy)
	addAttrIfHasLen(&attrs, "metrics", event.Metrics)
	addAttrIfNonZero(&attrs, "req_id", event.RequestID)

	if event.RequestContext != nil {
		attrs = append(attrs, slog.Any("request_context", event.RequestContext))
	}

	addAttrIfSliceNotEmpty(&attrs, "rule_labels", event.RuleLabels)
	addAttrIfNonZeroString(&attrs, "rule_id", event.RuleID)
	addAttrIfNonZeroString(&attrs, "rule_package", event.RulePackage)
	addAttrIfNonZeroString(&attrs, "policy_version", event.PolicyVersion)
	addAttrIfNonZero(&attrs, "sampled", event.Sampled)
	addAttrIfNonZero(&attrs, "truncated", event.Truncated)
	addAttrIfSliceNotEmpty(&attrs, "truncated_parts", event.TruncatedParts)
	addAttrIfHasLen(&attrs, "custom", event.Custom)

	return attrs
}

func addIfNonZero[T comparable](fields map[string]any, key string, value T) {
	var zero T
	if value != zero {
		fields[key] = value
	}
}

func addIfHasLen[M ~map[K]V, K comparable, V any](fields map[string]any, key string, value M) {
	if len(value) > 0 {
		fields[key] = value
	}
}

func addIfSliceNotEmpty[T any](fields map[string]any, key string, value []T) {
	if len(value) > 0 {
		fields[key] = value
	}
}

// roundTripAny JSON-marshals and unmarshals a value into a fresh any,
// ensuring that struct types are converted to map[string]any etc.
// Unlike util.RoundTrip, this always unmarshals into a nil any target,
// which prevents json.Decoder from reusing the existing concrete type.
func roundTripAny(x any) (v any, err error) {
	if !util.NeedsRoundTrip(x) {
		return x, nil
	}
	switch x.(type) {
	case map[string]any, []any:
		// Values that are already JSON-shaped, like a decoded request input,
		// are copied natively rather than serialized and parsed again.
		err = util.RoundTripFast(&x)
		return x, err
	}
	var bs []byte
	if bs, err = json.Marshal(x); err == nil {
		err = util.UnmarshalJSON(bs, &v)
	}
	return v, err
}

func stringsMapToAny(m map[string]string) map[string]any {
	result := make(map[string]any, len(m))
	for k, v := range m {
		result[k] = v
	}
	return result
}

func eventToFields(event EventV1) map[string]any {
	// NOTE(sr): This used to do a JSON roundtrip. I didn't like that, so I've converted
	// it to simple conversion steps. These, however, try to keep types as they were
	// before after the roundtrip. So if you find any of the [stringsToAny] business
	// curious, that's why we're doing it.
	fields := make(map[string]any)
	fields["type"] = DecisionLogType
	fields["timestamp"] = event.Timestamp.UTC().Format(time.RFC3339Nano)
	fields["decision_id"] = event.DecisionID
	addIfNonZero(fields, "batch_decision_id", event.BatchDecisionID)
	addIfNonZero(fields, "trace_id", event.TraceID)
	addIfNonZero(fields, "span_id", event.SpanID)
	if len(event.Labels) > 0 {
		fields["labels"] = stringsMapToAny(event.Labels)
	}
	addIfNonZero(fields, "revision", event.Revision)
	addIfHasLen(fields, "bundles", event.Bundles)
	addIfNonZero(fields, "path", event.Path)
	addIfNonZero(fields, "query", event.Query)
	if event.Input != nil {
		if v, err := roundTripAny(*event.Input); err == nil {
			fields["input"] = v
		}
	}
	if event.Result != nil {
		if v, err := roundTripAny(*event.Result); err == nil {
			fields["result"] = v
		}
	}
	addIfHasLen(fields, "intermediate_results", event.IntermediateResults)
	if event.MappedResult != nil {
		if v, err := roundTripAny(*event.MappedResult); err == nil {
			fields["mapped_result"] = v
		}
	}
	if event.NDBuiltinCache != nil {
		v := *event.NDBuiltinCache
		if err := util.RoundTripFast(&v); err == nil {
			fields["nd_builtin_cache"] = v
		}
	}
	addIfSliceNotEmpty(fields, "erased", util.ToSliceOf[any](event.Erased))
	addIfSliceNotEmpty(fields, "masked", util.ToSliceOf[any](event.Masked))
	addIfNonZero(fields, "masking_version", event.MaskingVersion)

	if event.Error != nil {
		fields["error"] = event.Error.Error()
	}

	addIfNonZero(fields, "requested_by", event.RequestedBy)
	addIfHasLen(fields, "metrics", event.Metrics)
	if event.RequestID != 0 {
		var v any = event.RequestID
		if err := util.RoundTripFast(&v); err == nil {
			fields["req_id"] = v
		}
	}

	if event.RequestContext != nil {
		fields["request_context"] = event.RequestContext
	}

	if len(event.RuleLabels) > 0 {
		var v any = event.RuleLabels
		if err := util.RoundTripFast(&v); err == nil {
			fields["rule_labels"] = v
		}
	}
	addIfNonZero(fields, "rule_id", event.RuleID)
	addIfNonZero(fields, "rule_package", event.RulePackage)
	addIfNonZero(fields, "policy_version", event.PolicyVersion)
	if event.Sampled {
		fields["sampled"] = true
	}
	if event.Truncated {
		fields["truncated"] = true
	}
	addIfSliceNotEmpty(fields, "truncated_parts", util.ToSliceOf[any](event.TruncatedParts))

	if len(event.Custom) > 0 {
		var v any = event.Custom
		if err := util.RoundTripFast(&v); err == nil {
			fields["custom"] = v
		}
	}

	return fields
}

func (p *Plugin) setStatus(err error) {
	p.statusMtx.Lock()
	p.status.SetError(err)
	oldStatus := p.status
	p.statusMtx.Unlock()

	if s := status.Lookup(p.manager); s != nil {
		s.UpdateDecisionLogsStatus(*oldStatus)
	}
}
