# Proposal: Rule indexing by classifier log type

## Summary

Reduce Python per-event work from **O(events × all rules)** toward **O(events × applicable rules)** by indexing rule modules using the **first directory under `--rules`** (the “pack”) and the canonical **log type** string produced by `internal/logprocessor` (e.g. `AWS.CloudTrail`, `GitHub.Audit`).

## Motivation

The long-lived Python worker removed process startup cost; indexing removes redundant `rule()` evaluations when the full `rules/` tree is loaded (multi-source deployments).

## Non-goals (this change)

- Rewriting rules in Go
- Per-rule metadata files (optional follow-up)
- Automatic profiling of Python hot paths (documented in design; operators use `cProfile` as needed)

## Deliverables

- `engines/iota/log_type_index.py` — pack → canonical log types; inference when `log_types` is absent
- `engines/iota/engine.py` — candidate rule lists per event; request field `log_types`
- `internal/engine` — JSON request includes optional `log_types` parallel to `events`
- `cmd/iota` — EventBridge, S3, and `runOnce` pass classifier `LogType`; watch/s3-poll pass `nil` (inference)
- Tests: Go integration test for pack skipping; Python `unittest` for index helpers
- OpenSpec updates under `openspec/specs/detection-engine` and `performance`

## Rollout / compatibility

- If `log_types` is omitted or length-mismatched, Python falls back to **inference** (best-effort `eventSource` / shape heuristics), then evaluates **all** rules if a pack is unknown (safe default).
