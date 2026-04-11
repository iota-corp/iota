# Proposal: Add detections for Bedrock, GitHub, GCP, Kubernetes, Slack, and Cloudflare

## Why

iota today supports AWS (CloudTrail, VPC Flow, ALB, S3 access, Aurora audit), Okta, Google Workspace, and 1Password, with Python rules under `rules/` mapped to those parsers. The upstream catalog in the mirrored analysis rules tree under `redteamtools` includes **additional log types and rule packs** that organizations already expect from typical cloud SIEM coverage:

| Upstream pack | Primary `LogTypes` in YAML | Approx. Python rules (this mirror) |
|-------------------------|----------------------------|-----------------------------------|
| `aws_bedrockmodelinvocation_rules` | `AWS.BedrockModelInvocation` | 2 |
| `github_rules` | `GitHub.Audit` | ~37 |
| `gcp_audit_rules` | `GCP.AuditLog` | ~56 |
| `gcp_http_lb_rules` | `GCP.HTTPLoadBalancer` | 2 |
| `gcp_k8s_rules` | `GCP.AuditLog` (GKE-style methods) | 9 |
| `kubernetes_rules` | `Amazon.EKS.Audit`, `GCP.AuditLog`, (Azure in upstream) | ~29 |
| `slack_rules` | `Slack.AuditLogs` (and related) | ~22 |
| `cloudflare_rules` | `Cloudflare.HttpRequest` / firewall | 3 |

Without an explicit plan, ports risk **silent mismatch** (wrong field paths, missing ingestion), **unbounded scope** (correlation rules, threshold-only behavior), or **duplicate evaluation cost** when many rule packs share one runtime.

Implementation for parsers, engine unwrap, helper libraries, and Python rule packs has landed in-repo (see `tasks.md`). Remaining follow-ups are infra-specific ingestion docs, optional Azure paths, and OpenSpec archive after staging validation.

## What this change produces

1. **`design.md`** — Canonical log types, envelope mapping, ingestion hypotheses, and out-of-scope items (updated as correlation support landed).
2. **`tasks.md`** — Phased checklist; Phases 1–6 implemented or explicitly deferred in-repo.
3. **Spec updates** — `openspec/specs/log-processing/spec.md` and `openspec/specs/detection-engine/spec.md` describe behavioral requirements; `project.md` lists supported sources and multi-source deployment notes.

## Relationship to other OpenSpec work

- **`openspec/changes/sync-upstream-analysis-daae6f35`** — Established single-event Python porting patterns, `severity(event)`, and **out of scope** items (K8s, thresholds, correlation). This proposal **narrows** “Kubernetes / GCP / GitHub” into **concrete log types and upstream folders** and ties them to **`plan-extended-sources-correlation`** for threshold and correlation dependencies.
- **`openspec/changes/plan-extended-sources-correlation`** — Roadmap for pipelines, correlation, baselines, and thresholds. This proposal **references** it for rules that need **windowed counts** (e.g. Slack `slack_application_dos`, Kubernetes `k8s_secret_access_denied`, Cloudflare high-volume rules) rather than duplicating that roadmap.

## Impact

- **Product**: Clear path to parity with selected upstream categories **without** committing to full mirrored rules coverage in one release.
- **Engineering**: Implementers know **order of operations** (ingest + parse before rules; split threshold-dependent rules).
- **Operators**: Future runbooks can assume documented log types and deployment modes per source.

## Success criteria

- [x] **Phase order** and scope documented in `design.md` / `tasks.md` (Azure and some infra items explicitly deferred).
- [ ] Each upstream pack has a **named ingestion approach** in deployment repos (still tracked in Phase 1 / infra).
- [x] **Out of scope** items explicit in `design.md` (scheduled queries, lookup tables; correlation via `correlation_store.py` where ported).
- [x] Implementation delivered in-repo; further work is **infra, validation, and archive** (see Phase 6 in `tasks.md`).

## References

- Upstream mirror: the analysis rules tree under `redteamtools` — `rules/` packs above; `data_models/`; `indexes/`; `queries/` (reference only; scheduled queries are not iota’s per-event engine today).
- iota: `openspec/specs/log-processing/spec.md`, `openspec/specs/detection-engine/spec.md`, `engines/iota/engine.py`, `internal/logprocessor/parsers/`.
- Related proposals: `openspec/changes/sync-upstream-analysis-daae6f35/proposal.md`, `openspec/changes/plan-extended-sources-correlation/proposal.md`.
