# Proposal: Performance hot-path improvements (roadmap)

## Why

An internal performance pass identified the largest CPU and memory wins in the detection and ingest path: repeated Python process/rule load per batch, full-buffer reads of large CloudTrail files, line scanner limits, synchronous data lake flush, and SQLite write contention under parallelism. This change does **not** implement those optimizations in one shot; it captures them as **OpenSpec tasks**, a **performance capability spec**, and a **developer doc** so work can be scheduled, reviewed, and verified against acceptance criteria.

## Goals

1. Checked-in **tasks** (`tasks.md`) with clear ordering, owners optional, and verification steps.
2. **Normative roadmap** in `openspec/specs/performance/spec.md` (SHOULD/MAY) so specs stay the source of truth.
3. **`docs/PERFORMANCE-ROADMAP.md`** summarizing findings, links to code and OpenSpec IDs, and how to benchmark or validate.

## Non-goals

- Mandating a specific implementation (e.g. gRPC vs stdio to Python) before design review.
- Changing detection semantics or rule interfaces without a follow-up proposal.

## Success criteria

- `plan-performance-hot-paths` is listed under `openspec/changes/` with proposal, tasks, design, and spec-diff.
- `openspec/specs/performance/spec.md` exists and is referenced from `openspec/project.md`.
- Engineers can implement items independently and check off `tasks.md` as merges land.

## References

- Code: `internal/engine/engine.go`, `engines/iota/engine.py`, `internal/logprocessor/processor.go`, `internal/datalake/writer.go`, `internal/deduplication/deduplicator.go`, `internal/state/state.go`, `cmd/iota/sqs_handler.go`, `internal/bloom/bloom.go`
- Doc: `docs/PERFORMANCE-ROADMAP.md`
