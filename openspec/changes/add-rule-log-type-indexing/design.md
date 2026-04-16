# Design: Rule indexing by log type

## Pack key

The **pack** is the first path component under the configured `rules_dir`, e.g. `rules/github_audit/x.py` → `github_audit`. Files directly under `rules/*.py` are **unindexed** (evaluated for every event) so small test fixtures keep working.

## Canonical log types

Values align with `internal/logprocessor.getParsers()` keys (`AWS.CloudTrail`, `GitHub.Audit`, `GCP.AuditLog`, …). Go sends one string per event in `log_types` when the adaptive classifier has already determined `ProcessedEvent.LogType`.

## Mapping table

`PACK_LOG_TYPES` in `engines/iota/log_type_index.py` maps pack → `frozenset` of log types.

- **AWS CloudTrail-shaped packs** (`aws_cloudtrail`, `aws_iam`, `aws_s3`) map to **`AWS.CloudTrail`** — all are management API records classified as CloudTrail in Go.
- **cloudflare** maps to both **`Cloudflare.Firewall`** and **`Cloudflare.HttpRequest`**.
- **Unknown packs** → unindexed (run on all events).

## Inference (no `log_types`)

Used for CLI modes (`watch`, `s3-poll`) and mismatched arrays. Uses `p_log_type` if present, else `eventSource` / light shape checks (ALB, VPC flow, Bedrock, GCP split, GitHub audit vs webhook).

## Safety

If indexing yields **no** candidate rules (should not happen for known packs + correct log type), the engine **falls back to all rules**.

## Profiling (operators)

For Python CPU hotspots after rules grow: `python3 -m cProfile -o /tmp/prof engines/iota/engine.py` (oneshot) or attach to worker — see `docs/PERFORMANCE-ROADMAP.md`.
