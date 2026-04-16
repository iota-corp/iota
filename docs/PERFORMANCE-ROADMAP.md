# Performance roadmap

This document captures a **performance discovery pass** on iota’s hot paths: what to optimize, where in the code, and how to verify improvements. Authoritative task tracking lives in OpenSpec:

- **Change id:** `plan-performance-hot-paths`
- **Proposal / tasks / design:** [openspec/changes/plan-performance-hot-paths/](../openspec/changes/plan-performance-hot-paths/)
- **Capability spec (SHOULD/MAY targets):** [openspec/specs/performance/spec.md](../openspec/specs/performance/spec.md)

Use this doc for onboarding and prioritization; use `tasks.md` in the change folder for checkboxes and PR scope.

## Summary (priority order)

| Priority | Theme | Idea | Primary code |
|----------|--------|------|----------------|
| P0 | Python + rules | Avoid reloading every rule on every batch; long-lived worker and/or rule indexing | `internal/engine/engine.go`, `engines/iota/engine.py` |
| P1 | Memory | Stream or chunk large CloudTrail `Records` instead of full-buffer read + per-record string copies | `internal/logprocessor/processor.go`, classifiers |
| P1 | Correctness / edge perf | Raise or document `bufio.Scanner` max token for huge lines | `internal/logprocessor/` |
| P2 | Lake write path | Optional async flush after measurement (bounded queue, backpressure) | `internal/datalake/writer.go` |
| P2 | SQLite | Reduce write contention under parallel SQS/object work (single-writer queue, tuning) | `internal/deduplication/deduplicator.go`, `internal/state/state.go` |
| P3 | Parallelism | Document and safely use `--process-workers` with parser/engine constraints | `cmd/iota/sqs_handler.go` |
| P3 | Observability | OTel sampling at very high QPS | tracing setup |
| — | Bloom | Existing `RWMutex` usage is reasonable unless profiling shows lock churn | `internal/bloom/bloom.go` |

## Baseline figures

See [openspec/project.md](../openspec/project.md) (**Performance Characteristics**) for published throughput and memory notes. Re-benchmark after each merged optimization.

## How to verify

1. **Correctness:** `go test ./...` (and Python/ruff if rules or engine change).
2. **Throughput:** Reproduce project’s CloudTrail-style load or internal benchmark; compare events/sec before/after.
3. **Memory:** `runtime.MemStats` or `pprof` heap profiles on large S3 fixtures; watch RSS under sustained load.
4. **Latency:** p99 for end-to-end processing and for SQLite-backed dedup if contention work lands.
5. **Tracing:** Span count per 1k events with sampling off vs on.

## Operational mitigations (today)

Narrowing `--rules` to a single pack or symlinked subtree still reduces Python work per event (see detection-engine spec and `openspec/project.md`).

### Implemented (this repo)

- **Persistent Python worker:** By default the Go engine starts `engines/iota/engine.py worker` once and reuses loaded rules across `Analyze` calls. Set **`IOTA_ENGINE_ONESHOT=1`** to force the legacy one-subprocess-per-batch behavior (for debugging or A/B).
- **Streaming `Records` / top-level arrays:** The log processor streams those JSON shapes instead of always `ReadAll` first.
- **Line scanner:** Up to **10 MiB** per line in line-delimited mode (avoids default 64 KiB `bufio.Scanner` limit).
- **Data lake async flush (optional):** **`IOTA_DATALAKE_ASYNC_FLUSH=1`** moves S3/Glue upload off the synchronous `WriteEvent` path after a buffer is sealed; bounded queue (**`IOTA_DATALAKE_FLUSH_QUEUE_DEPTH`**, default 4). **`Flush()`** must run on shutdown so the worker drains (same as before). Prometheus: **`iota_datalake_async_flush_queue_depth`**.
- **SQLite:** `MaxOpenConns(1)` on dedup and state DBs; **`sync.RWMutex`** serializes API usage per store to reduce lock churn with parallel SQS workers.
- **`--process-workers`:** Parallel JSON record classification for batched shapes (default **`1`**). Not used for line-delimited JSONL (adaptive parser priority learning stays single-threaded there).
- **OTel trace sampling:** Set **`OTEL_TRACES_SAMPLER_ARG`** (e.g. `0.1`) or **`IOTA_OTEL_TRACE_SAMPLE_RATIO`** to reduce span volume; startup log shows `sample_rate`. Uses parent-based ratio sampling when `0 < rate < 1`.
