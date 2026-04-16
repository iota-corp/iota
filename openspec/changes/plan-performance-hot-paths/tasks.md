# Tasks: plan-performance-hot-paths

## Documentation and specs (this change)

- [x] Add `openspec/specs/performance/spec.md` (roadmap SHOULD/MAY requirements).
- [x] Add `openspec/changes/plan-performance-hot-paths/` (`proposal.md`, `tasks.md`, `design.md`, `spec-diff/index.md`).
- [x] Add `docs/PERFORMANCE-ROADMAP.md` (audit summary, links, verification).
- [x] Link from `openspec/project.md` to the roadmap doc and this change id.

## Implementation backlog (unchecked — develop in separate PRs)

### P0 — Rule evaluation amortization

- [x] **Long-lived Python worker (or equivalent):** Default path uses `python engines/iota/engine.py worker` with length-prefixed JSON frames; rules load once per worker; `Engine.Close()` stops the subprocess. Set `IOTA_ENGINE_ONESHOT=1` to restore one process per `Analyze` (debug). **Verify:** `internal/engine/engine_test.go`; `go test ./...`.
- [ ] **Rule indexing / filtering:** Reduce O(events × all rules) in Python without changing rule semantics (e.g. by `rules/{log_type}/` or manifest). **Verify:** unit tests that only matching rules run for a log type; regression on rule count × latency.

### P1 — Ingest memory

- [x] **Streaming CloudTrail (and similar) parse:** Root JSON array and `{"Records":[...]}` (when `"Records":[` appears in the first 1 KiB) stream via `json.Decoder` without `ReadAll` of the full file; other shapes fall back to buffered path. **Verify:** existing `internal/logprocessor` tests; profile large fixtures as follow-up.
- [x] **Scanner buffer policy:** `processLineByLine` uses `Scanner.Buffer` with max token 10 MiB. **Verify:** extend with an oversized-line test if needed.

### P2 — Async / contention

- [x] **Data lake async flush (optional):** Set `IOTA_DATALAKE_ASYNC_FLUSH=1` (optional `IOTA_DATALAKE_FLUSH_QUEUE_DEPTH`, default 4). `Flush()` closes the queue and waits for the worker. `iota_datalake_async_flush_queue_depth` gauge; S3/Glue failures increment `iota_processing_errors_total` and `iota_datalake_writes_total{status=error}`.
- [x] **SQLite contention:** `sqliteutil.ConfigureConnectionPool` sets `MaxOpenConns(1)`; `Deduplicator` and `state.DB` use `RWMutex` on all DB methods (writers serialized; reads can share the lock with WAL semantics at the driver level).

### P3 — Operations and observability

- [x] **`--process-workers`:** Default `1`. Values `1–32` set parallel classifiers for batched JSON (root arrays, streaming `Records`, buffered `Records` when `len ≥ 2×workers`); each worker uses `NewAdaptiveClassifier` + shared bloom; line-delimited parsing stays sequential. Wired in `sqs` and `eventbridge`. **Verify:** `internal/logprocessor/processor_workers_test.go`; `go test -race ./...`.
- [x] **OTel sampling:** `OTEL_TRACES_SAMPLER_ARG` or `IOTA_OTEL_TRACE_SAMPLE_RATIO` (`0`–`1`); `ParentBased(TraceIDRatioBased)` when `0 < rate < 1`. Logged at startup with `sample_rate`. **Verify:** `internal/telemetry/telemetry_test.go`.

### Baseline / no code change

- [x] **Bloom filter concurrency:** `internal/bloom/bloom.go` already uses `RWMutex`; no task unless profiling shows lock churn.

## Archive

When the backlog above is either completed or superseded, archive this change:

`openspec archive plan-performance-hot-paths --skip-specs --yes` (after updating `tasks.md` and any spec follow-ups).
