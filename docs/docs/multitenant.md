# Multi-tenant Evaluation: Resource Isolation and Quotas

The `multitenant` package lets one OPA process serve multiple tenants from
the same evaluation instances without letting one tenant's workload starve
or crash the others. It is **opt-in**: nothing changes unless you construct a
`multitenant.Manager`, and no existing package imports it.

## Guarantees

| Concern | Mechanism |
|---|---|
| Per-tenant concurrency | One resizable, FIFO semaphore per tenant plus an optional instance-wide FIFO gate |
| Per-evaluation time | Every evaluation runs under a `context` deadline; the engine checks cancellation between every expression |
| Per-evaluation memory | A single watchdog samples heap growth and cancels evaluations past their tenant's memory quota |
| Fairness under overload | FIFO admission into a bounded global pool, so no tenant is starved |
| Policy/data isolation | Each tenant owns an independent `storage.Store` and compiler; there is no shared data path |
| Audit isolation | Every record carries the tenant ID, decision ID, package and request ID; records are retrievable per tenant |
| Sensitive data | Audit records store locator fields only — never policy text, input documents or results |

## Limits of in-process isolation

A Go process cannot give goroutines kernel-enforced CPU or memory
boundaries. The package therefore combines every isolation mechanism
available inside one process:

- **CPU** is bounded cooperatively through the evaluation deadline. The
  topdown engine polls a cancellation flag between expressions, so an
  infinite loop unwinds cleanly. A custom (Go) builtin that ignores its
  `context.Context` cannot be interrupted until it returns.
- **Memory** is a cooperative guard, not a hard limit. A single allocation
  that crosses the quota in one step is only observed after it happens. Enable
  `Config.EnableProcessMemoryLimit` to additionally set a process-wide soft
  limit via `debug.SetMemoryLimit` so the runtime forces GC before the
  process is OOM-killed. For hard per-tenant limits, run tenant groups in
  separate processes/containers (cgroups) and use this package on top.

## Quick start

```go
mgr, err := multitenant.NewManager(multitenant.Config{
    Defaults: multitenant.Defaults{Quota: multitenant.Quota{
        MaxConcurrent:    4,
        EvalTimeout:      250 * time.Millisecond,
        MemoryLimitBytes: 64 << 20,
        MaxQueued:        16,
        QueueTimeout:     time.Second,
    }},
})
if err != nil { /* ... */ }
defer mgr.Close()

if err := mgr.RegisterTenant(ctx, "team-a", multitenant.Quota{
    MaxConcurrent: 2,
    EvalTimeout:   100 * time.Millisecond,
}); err != nil { /* ... */ }

rt := multitenant.NewTenantRuntime("team-a")
if err := rt.LoadModule(ctx, "authz.rego", module); err != nil { /* ... */ }

res, err := mgr.EvalPolicy(ctx, "team-a", rt, multitenant.EvalInput{
    Package:   "authz/allow",
    Input:     map[string]any{"user": "alice"},
    RequestID: "req-123",
})
```

## Quota fields

- `MaxConcurrent` — evaluations running at once for the tenant.
- `EvalTimeout` — deadline for one evaluation; expiry cancels it with
  `ReasonTimeout`.
- `MemoryLimitBytes` — heap-growth guard for one evaluation; a breach
  cancels it with `ReasonMemory`. `0` disables the guard.
- `MaxQueued` — requests allowed to wait for a slot; `0` means saturated
  tenants fail immediately with `ReasonConcurrency`.
- `QueueTimeout` — max wait in queue before `ReasonQueueTimeout`. `0` means
  unbounded (subject to the caller's context).

Zero-valued `MaxConcurrent` and `EvalTimeout` fall back to the instance
defaults; the other fields keep their explicit zero semantics.

## Failure and degradation

- If a `QuotaProvider` is configured and unavailable, tenants keep serving
  under their last known quota or the instance defaults — never
  unconstrained. `Stats(tenant).Degraded` reports the condition.
- Audit writes are asynchronous and never block evaluation. When the sink
  fails, records are buffered and retried with backoff; the overflow ring
  keeps them for a later flush. `AuditHealth` reports enqueued/dropped
  counts.
- Cancelling one evaluation leaves the engine reusable: every query gets
  fresh per-query state, and a tenant's later requests are unaffected.

## Retrieving audit records

The default in-memory sink implements `QueryableSink`:

```go
recs, err := mgr.AuditRecords("team-a")
```

Production deployments typically supply their own durable `Sink` (and may
implement `QueryableSink` on it).
