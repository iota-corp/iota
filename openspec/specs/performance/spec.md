---
version: 1.0.0
status: active
owner: bilals12
---

# Capability: Performance and hot paths

Cross-cutting throughput, memory, and contention targets for the detection pipeline. Requirements here are **roadmap** items (SHOULD/MAY): implementations land under tracked OpenSpec changes; until then, behavior in `openspec/specs/*` elsewhere remains authoritative.

Tracked change: `openspec/changes/plan-performance-hot-paths/`.

## Requirements

### Requirement: Python rule engine amortization

The system SHOULD avoid reloading the full Python rule set on every detection batch when doing so materially limits throughput.

#### Scenario: Long-lived evaluation context

- **GIVEN** sustained event processing in `sqs` or `eventbridge` mode
- **WHEN** rules are loaded from `--rules`
- **THEN** deployments SHOULD prefer a pattern that loads rules once per process lifetime (e.g. long-lived Python worker or equivalent), subject to safety and reload semantics

#### Scenario: Rule selection cost

- **GIVEN** a large `rules/` tree
- **WHEN** evaluating events for a known log type
- **THEN** implementations SHOULD reduce redundant work versus evaluating every rule file against every event (e.g. indexing, pre-filtering, or pack-scoped `--rules`), without changing rule semantics

**Reference:** `internal/engine/engine.go`, `engines/iota/engine.py`

### Requirement: Bounded memory for large S3 objects

The log processor SHOULD avoid holding entire decompressed objects in memory when streaming decode yields equivalent correctness.

#### Scenario: CloudTrail Records array

- **GIVEN** a large JSON object with a top-level `Records` array
- **WHEN** the file is processed from S3
- **THEN** memory use SHOULD remain bounded relative to configured batching (streaming or chunked decode), except where a documented compatibility mode requires full-file behavior

**Reference:** `internal/logprocessor/processor.go`

### Requirement: Line-oriented parsing limits

For newline-delimited or line-scanned inputs, the system SHOULD tolerate log lines larger than the default `bufio.Scanner` token limit where supported log sources can produce them.

#### Scenario: Oversized line

- **GIVEN** a line exceeding 64 KiB
- **WHEN** the scanner reads a complete logical line
- **THEN** processing SHOULD either succeed with an explicit buffer policy or fail with a clear error (not silent truncation)

**Reference:** `internal/logprocessor/` (scanner-based paths)

### Requirement: Data lake write latency vs throughput

The data lake writer MAY move flush/upload work off the synchronous hot path after measurement shows benefit, while preserving durability and observability expectations defined elsewhere.

#### Scenario: Flush does not block detection unbounded

- **GIVEN** high sustained ingest rate
- **WHEN** a batch is ready to flush to S3 / Glue
- **THEN** implementations SHOULD document queueing/backpressure behavior and ensure alerts and metrics still reflect failures

**Reference:** `internal/datalake/writer.go`

### Requirement: SQLite write contention

Under parallel handlers (e.g. multiple SQS consumers or concurrent object processing), alert deduplication and state SQLite SHOULD avoid systematic write lock contention that degrades p99 latency.

#### Scenario: Concurrent dedup updates

- **GIVEN** concurrent alert or dedup state updates
- **WHEN** WAL mode and busy timeout are in use
- **THEN** implementations MAY introduce a single-writer queue or equivalent, and SHOULD document tuning (`busy_timeout`, batching) for operators

**Reference:** `internal/deduplication/deduplicator.go`, `internal/state/state.go`

### Requirement: Configurable ingest parallelism

The system SHOULD document and, where safe, implement parallelism for `Process()`-style work such that parser and engine invariants (ordering, subprocess usage) remain valid.

#### Scenario: Process workers flag

- **GIVEN** `--process-workers` between 1 and 32
- **WHEN** ingesting batched JSON (S3 `logprocessor.Process` paths)
- **THEN** that many isolated `AdaptiveClassifier` instances MAY classify records in parallel; shared bloom filter remains thread-safe; line-delimited parsing remains sequential; Python `engine.Analyze` is unchanged (still one batch per object)

**Reference:** `cmd/iota/sqs_handler.go`, `cmd/iota/eventbridge_handler.go`, `internal/logprocessor/processor.go`

### Requirement: Observability overhead at scale

When OpenTelemetry tracing is enabled, deployments SHOULD be able to reduce span volume (sampling) so observability cost does not dominate CPU at high QPS.

#### Scenario: Sampling configuration

- **GIVEN** production-like event rates
- **WHEN** tracing is on
- **THEN** operators SHOULD configure sampling via `OTEL_TRACES_SAMPLER_ARG` or `IOTA_OTEL_TRACE_SAMPLE_RATIO` (documented in `docs/PERFORMANCE-ROADMAP.md`); parent-based ratio sampling applies for rates between 0 and 1

## Current implementation (baseline)

- **Python worker:** `internal/engine/engine.go` runs `engines/iota/engine.py worker` with length-prefixed JSON frames; rules stay loaded until `Engine.Close()` or process error. `IOTA_ENGINE_ONESHOT=1` selects one subprocess per `Analyze`.
- **Streaming ingest:** `internal/logprocessor/processor.go` streams root JSON arrays and `{"Records":[...]}` when the file prefix matches (see code); other layouts use the prior buffered path.
- **Line scanner:** Line mode allows up to 10 MiB tokens via `Scanner.Buffer`.
- **Data lake:** Optional async flush via `IOTA_DATALAKE_ASYNC_FLUSH`; writer mutex protects the buffer; `Flush` drains async work.
- **SQLite:** `internal/sqliteutil.ConfigureConnectionPool`; `internal/deduplication` and `internal/state` use `RWMutex` around DB access.
- **Process workers:** `--process-workers` + `Processor.SetClassifyWorkers` for parallel batched classification; see CLI help.
- **OTel sampling:** `internal/telemetry` reads `OTEL_TRACES_SAMPLER_ARG` / `IOTA_OTEL_TRACE_SAMPLE_RATIO`.
- **Bloom filter:** `internal/bloom/bloom.go` uses `RWMutex` for concurrent readers; no change required for basic concurrency.
- **Measured baselines:** See `openspec/project.md` (Performance Characteristics) and `docs/PERFORMANCE-ROADMAP.md`.
