// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package decisioncache

import (
	"container/list"
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"
)

// cleanupInterval is the fixed period of the background entry sweeper.
const cleanupInterval = 30 * time.Second

type storedEntry struct {
	entry *Entry
	// elem is the entry's position in the FIFO eviction queue.
	elem *list.Element
}

type decisionCache struct {
	// config is guarded by mtx; it is replaced atomically on UpdateConfig.
	config *Config

	mtx        sync.RWMutex
	entries    map[Key]storedEntry
	queue      *list.List
	usage      int64
	generation atomic.Uint64

	state atomic.Int32

	sf singleflight.Group

	hits     atomic.Uint64
	misses   atomic.Uint64
	bypasses atomic.Uint64
	expired  atomic.Uint64
	evicted  atomic.Uint64
	dropped  atomic.Uint64

	cancel context.CancelFunc
	done   chan struct{}
	closed atomic.Bool
	closeM sync.Mutex
}

// New returns a decision cache configured by cfg. A nil or disabled config
// produces a cache that stays in StateDisabled. The returned cache's cleanup
// goroutine is bound to ctx and exits when ctx is cancelled or Close is
// called.
func New(ctx context.Context, cfg *Config) Cache {
	if cfg == nil {
		cfg = &Config{}
	}
	// Copy so later caller mutations cannot change behaviour underneath us.
	config := *cfg
	if config.Now == nil {
		config.Now = time.Now
	}

	c := &decisionCache{
		config:  &config,
		entries: map[Key]storedEntry{},
		queue:   list.New(),
		done:    make(chan struct{}),
	}
	if config.Enabled {
		c.state.Store(int32(StateEnabled))
	} else {
		c.state.Store(int32(StateDisabled))
	}

	sweepCtx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	go c.runJanitor(sweepCtx)

	return c
}

func (c *decisionCache) Begin() *Ticket {
	return &Ticket{generation: c.generation.Load()}
}

func (c *decisionCache) State() State {
	return State(c.state.Load())
}

func (c *decisionCache) Config() Config {
	c.mtx.RLock()
	defer c.mtx.RUnlock()
	return *c.config
}

// now returns the configured clock under the read lock so concurrent
// UpdateConfig calls cannot race the pointer read.
func (c *decisionCache) now() time.Time {
	c.mtx.RLock()
	now := c.config.Now
	c.mtx.RUnlock()
	return now()
}

func (c *decisionCache) SetState(s State) {
	c.state.Store(int32(s))
}

func (c *decisionCache) Bypass() {
	c.bypasses.Add(1)
}

func (c *decisionCache) Invalidate(_ Reason) {
	// Every policy or data commit advances the generation and retires the
	// whole entry set: even policy writes that leave bundle revisions
	// untouched must not be answered with stale decisions.
	c.generation.Add(1)

	c.mtx.Lock()
	oldQueue := c.queue
	c.entries = map[Key]storedEntry{}
	c.queue = list.New()
	c.usage = 0
	c.mtx.Unlock()

	// Release the retired queue outside the lock so concurrent readers do
	// not stall behind the garbage collector walking it.
	for oldQueue.Len() > 0 {
		oldQueue.Remove(oldQueue.Front())
	}
}

func (c *decisionCache) Get(ctx context.Context, t *Ticket, key Key, load func(context.Context) (*Entry, error)) (*Entry, bool, error) {
	state := c.State()
	if state == StateDisabled || state == StateDegraded {
		// Disabled: the feature is off. Degraded: the fence could not be
		// established for this request, so no entry can be trusted — evaluate
		// directly without consulting or mutating the store.
		entry, err := load(ctx)
		return entry, false, err
	}

	if entry, ok := c.lookup(key); ok {
		c.hits.Add(1)
		return cloneEntry(entry), true, nil
	}

	// A miss or an expired entry: coordinate concurrent requests on the same
	// key so the load runs exactly once. The singleflight key includes the
	// fence, so requests from different policy generations never share a
	// load. A no-store request is coordinated separately so it cannot prevent
	// an ordinary request from retaining the decision, or vice versa.
	noStore := noStoreFromContext(ctx)
	sfKey := singleflightKey(key)
	if noStore {
		sfKey += "\x00no-store"
	}
	leader := false
	v, err, _ := c.sf.Do(sfKey, func() (any, error) {
		leader = true
		return c.loadAndStore(ctx, t, key, load)
	})
	if err != nil {
		return nil, false, err
	}
	outcome := v.(loadOutcome)
	if !leader {
		// A singleflight waiter: the leader's evaluation produced the result,
		// so the waiter was served from the coordinated decision and counts
		// as a hit.
		c.hits.Add(1)
		return cloneEntry(*outcome.entry), true, nil
	}
	if outcome.hit {
		c.hits.Add(1)
		return cloneEntry(*outcome.entry), true, nil
	}
	c.misses.Add(1)
	return cloneEntry(*outcome.entry), false, nil
}

// loadOutcome is what loadAndStore hands back to Get so the hit/miss counters
// can be recorded exactly once regardless of singleflight sharing.
type loadOutcome struct {
	entry *Entry
	// hit is true when another goroutine populated the entry while the leader
	// waited at the singleflight gate.
	hit bool
}

// lookup returns a fresh, fence-matching entry for key or false. Expired and
// mismatching entries are removed under the same lock used for writes.
func (c *decisionCache) lookup(key Key) (Entry, bool) {
	c.mtx.RLock()
	stored, ok := c.entries[key]
	c.mtx.RUnlock()
	if !ok {
		return Entry{}, false
	}

	now := c.now()
	if !stored.entry.ExpiresAt.IsZero() && !stored.entry.ExpiresAt.After(now) {
		// Re-check under the write lock before deleting; another request may
		// have replaced the entry meanwhile.
		c.mtx.Lock()
		if current, ok := c.entries[key]; ok && current.entry == stored.entry {
			c.removeLocked(key, current)
		}
		c.mtx.Unlock()
		c.expired.Add(1)
		return Entry{}, false
	}

	return *stored.entry, true
}

// loadAndStore runs the evaluation once and writes the result when the
// generation has not advanced in the meantime. It holds no cache lock while
// evaluating. Hit/miss counters are recorded by Get so singleflight waiters
// are counted exactly once.
func (c *decisionCache) loadAndStore(ctx context.Context, t *Ticket, key Key, load func(context.Context) (*Entry, error)) (loadOutcome, error) {
	// Another goroutine may have populated the entry while this one waited on
	// the singleflight gate; check once more before evaluating.
	if entry, ok := c.lookup(key); ok {
		return loadOutcome{entry: &entry, hit: true}, nil
	}

	entry, err := load(ctx)
	if err != nil {
		return loadOutcome{}, err
	}
	if entry == nil {
		return loadOutcome{}, nil
	}
	if noStoreFromContext(ctx) {
		entry.noStore = true
	}

	// A commit landed during evaluation: the decision was computed against a
	// stale snapshot, so it must not be stored or served from the cache.
	if t == nil || c.generation.Load() != t.generation {
		c.dropped.Add(1)
		return loadOutcome{entry: entry}, nil
	}

	// The request must not retain its decision (e.g. it produced response
	// metadata); return it without storing.
	if entry.noStore {
		return loadOutcome{entry: entry}, nil
	}

	c.mtx.Lock()
	defer c.mtx.Unlock()

	// Re-check under the lock to close the window between the generation read
	// above and acquiring the lock.
	if c.generation.Load() != t.generation {
		c.dropped.Add(1)
		return loadOutcome{entry: entry}, nil
	}

	// Normalize the decision value once: this yields an immutable deep copy,
	// its serialized size and a value safe to hand back to callers.
	value, size, err := normalizeValue(entry.Value)
	if err != nil {
		return loadOutcome{entry: entry}, nil
	}
	entry.Value = value
	entry.size = size

	c.evictToFitLocked(key, entry)
	c.insertLocked(key, entry)

	return loadOutcome{entry: entry}, nil
}

// evictToFitLocked removes oldest entries (never the one for key) until the
// new entry fits both configured limits. An entry larger than a non-zero
// limit is not stored at all.
func (c *decisionCache) evictToFitLocked(key Key, entry *Entry) {
	cfg := c.config

	// A single entry that exceeds the byte budget can never fit.
	if cfg.MaxSizeBytes > 0 && int64(entry.size) > cfg.MaxSizeBytes {
		c.dropped.Add(1)
		entry.size = -1
		return
	}

	for cfg.MaxNumEntries > 0 && len(c.entries) >= cfg.MaxNumEntries {
		c.evictOldestLocked(key)
	}
	for cfg.MaxSizeBytes > 0 && c.usage+int64(entry.size) > cfg.MaxSizeBytes {
		if !c.evictOldestLocked(key) {
			break
		}
	}
}

// evictOldestLocked removes the FIFO-oldest entry. It returns false when no
// removable entry exists (the only remaining entry is the one being written).
func (c *decisionCache) evictOldestLocked(incoming Key) bool {
	for elem := c.queue.Front(); elem != nil; elem = elem.Next() {
		oldestKey := elem.Value.(Key)
		if oldestKey == incoming {
			continue
		}
		if stored, ok := c.entries[oldestKey]; ok {
			c.removeLocked(oldestKey, stored)
			c.evicted.Add(1)
			return true
		}
		// Defensive: queue/entries divergence should never happen.
		c.queue.Remove(elem)
	}
	return false
}

func (c *decisionCache) insertLocked(key Key, entry *Entry) {
	if entry.size < 0 {
		// The entry was rejected for exceeding the byte budget.
		return
	}
	// Replace an existing entry rather than duplicating queue positions.
	if existing, ok := c.entries[key]; ok {
		c.removeLocked(key, existing)
	}
	elem := c.queue.PushBack(key)
	c.entries[key] = storedEntry{entry: entry, elem: elem}
	c.usage += int64(entry.size)
}

func (c *decisionCache) removeLocked(key Key, stored storedEntry) {
	delete(c.entries, key)
	c.queue.Remove(stored.elem)
	c.usage -= int64(stored.entry.size)
}

func (c *decisionCache) UpdateConfig(cfg *Config) {
	if cfg == nil {
		return
	}
	newConfig := *cfg

	c.mtx.Lock()
	if newConfig.Now == nil {
		newConfig.Now = c.config.Now
	}
	c.config = &newConfig

	// Growing a limit only adjusts the bound; shrinking applies immediately.
	if newConfig.MaxNumEntries > 0 {
		for len(c.entries) > newConfig.MaxNumEntries {
			if elem := c.queue.Front(); elem != nil {
				oldestKey := elem.Value.(Key)
				if stored, ok := c.entries[oldestKey]; ok {
					c.removeLocked(oldestKey, stored)
					c.evicted.Add(1)
				}
			} else {
				break
			}
		}
	}
	if newConfig.MaxSizeBytes > 0 {
		for c.usage > newConfig.MaxSizeBytes {
			if elem := c.queue.Front(); elem != nil {
				oldestKey := elem.Value.(Key)
				if stored, ok := c.entries[oldestKey]; ok {
					c.removeLocked(oldestKey, stored)
					c.evicted.Add(1)
					continue
				}
			}
			break
		}
	}
	c.mtx.Unlock()

	if newConfig.Enabled {
		if c.State() == StateDisabled {
			c.SetState(StateEnabled)
		}
	} else {
		c.SetState(StateDisabled)
	}
}

func (c *decisionCache) Stats() Stats {
	c.mtx.RLock()
	entries := len(c.entries)
	usage := c.usage
	c.mtx.RUnlock()

	return Stats{
		Hits:     c.hits.Load(),
		Misses:   c.misses.Load(),
		Bypasses: c.bypasses.Load(),
		Expired:  c.expired.Load(),
		Evicted:  c.evicted.Load(),
		Dropped:  c.dropped.Load(),
		Entries:  entries,
		Bytes:    usage,
	}
}

func (c *decisionCache) Close() error {
	c.closeM.Lock()
	defer c.closeM.Unlock()
	if c.closed.Swap(true) {
		return nil
	}
	if c.cancel != nil {
		c.cancel()
	}
	if c.done != nil {
		<-c.done
	}
	return nil
}

// runJanitor periodically sweeps expired entries. Scan failures only affect
// counters; the sweep never touches storage or evaluation, so it cannot
// influence request handling.
func (c *decisionCache) runJanitor(ctx context.Context) {
	defer close(c.done)

	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.sweep()
		}
	}
}

func (c *decisionCache) sweep() {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	now := c.config.Now()
	for key, stored := range c.entries {
		if stored.entry.ExpiresAt.IsZero() || stored.entry.ExpiresAt.After(now) {
			continue
		}
		c.removeLocked(key, stored)
		c.expired.Add(1)
	}
}

// normalizeValue round-trips the decision value through JSON so the stored
// value is an independent deep copy and its serialized size is measured once.
func normalizeValue(value any) (any, int, error) {
	serialized, err := json.Marshal(value)
	if err != nil {
		return nil, 0, err
	}
	var decoded any
	if err := json.Unmarshal(serialized, &decoded); err != nil {
		return nil, 0, err
	}
	return decoded, len(serialized), nil
}

// cloneEntry returns a copy of entry whose Value does not share any mutable
// state with the stored value.
func cloneEntry(entry Entry) *Entry {
	if entry.Value == nil {
		return &entry
	}
	serialized, err := json.Marshal(entry.Value)
	if err != nil {
		// Values were normalized on write, so this should not fail; fall back
		// to sharing the value rather than dropping the decision.
		return &entry
	}
	var decoded any
	if err := json.Unmarshal(serialized, &decoded); err != nil {
		return &entry
	}
	entry.Value = decoded
	return &entry
}

func singleflightKey(key Key) string {
	// The fields cannot contain a null byte, so this separator is unambiguous.
	return key.Path + "\x00" + key.Input + "\x00" + key.Fence
}
