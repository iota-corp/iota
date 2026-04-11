# Design: Extended source detections

## Goals

1. **Name log types consistently** so parsers, metrics, and `rules/<folder>/` layouts match operator expectations and upstream YAML `LogTypes` where practical.
2. **Reuse the existing event envelope** — Today SaaS and non-CloudTrail AWS shapes are carried in `pkg/cloudtrail.Event` with vendor payloads in `RequestParameters` and `eventSource` discriminating unwrap logic in `engines/iota/engine.py`. New sources SHOULD follow the same pattern unless a future ADR introduces a generic `map[string]any` event type.
3. **Minimize false confidence** — Rules that need cross-event state or sliding-window thresholds use `rules/helpers/correlation_store.py` (SQLite, `IOTA_CORRELATION_STATE`). Do not port rules that depend on **scheduled queries** or **lookup tables** until those exist in iota.

## Canonical log types (target)

Align with upstream YAML log type names unless AWS/GCP/Slack export schemas force a prefixed variant. Proposed iota classifier strings:

| Area | Upstream log type | Notes |
|------|------------------------|--------|
| Bedrock | `AWS.BedrockModelInvocation` | Model invocation logs (often S3-delivered JSON); not CloudTrail `eventName` |
| GitHub | `GitHub.Audit` | Org/repo audit stream (after normalization) |
| GCP audit | `GCP.AuditLog` | `cloudaudit.googleapis.com` activity / data access JSON |
| GCP HTTP LB | `GCP.HTTPLoadBalancer` | HTTP(S) load balancing request logs |
| GKE (subset) | Same as `GCP.AuditLog` | Rules filter `serviceName` / `methodName` for `k8s.io` |
| Kubernetes (EKS) | `Amazon.EKS.Audit` | Native Kubernetes audit Event JSON |
| Slack | `Slack.AuditLogs` | Confirm field parity with `LogTypes` in each rule YAML |
| Cloudflare | `Cloudflare.HttpRequest` (and firewall if distinct in YAML) | High-volume HTTP / WAF |

**Azure / AKS** — Upstream `kubernetes_rules` include `Azure.MonitorActivity` test fixtures. Treat **Azure pipeline** as optional phase unless product requires it; port **EKS + GCP** paths first for unified k8s rules.

## Ingestion hypotheses (to validate in implementation spikes)

| Source | Likely path | Risk |
|--------|-------------|------|
| Bedrock model invocation | S3 (AWS-published log files), same account as pipeline | Schema versioning (`schemaType`, `schemaVersion`) |
| GitHub Audit | S3 archive, webhook, or API poller → SQS | Enterprise vs org scope; rate limits |
| GCP logs | GCS bucket notifications, Pub/Sub → subscriber, or cross-cloud export | Project/sink configuration |
| EKS audit | S3 control plane logs (existing AWS path) | Cluster-specific prefixes |
| Slack | EventBridge partner / SCIM / audit API → queue | App installation, OAuth |
| Cloudflare | Logpush to S3 or HTTP | Volume and sampling |

Exact Terraform and queue wiring belong in **`iota-infra` / `iota-deployments`**; this design only requires that **one** supported path exists per source before rules are marked GA.

## Rule porting criteria

**In scope for a Python port in iota** when the log type is implemented:

- `AnalysisType: rule`, `Threshold: 1` (or upstream default), no dependency on `queries/` or `lookup_tables/`.
- Logic expressible as `rule(event)` over **one** normalized payload (after unwrap).

**Defer or stub**:

- **Threshold > 1** for rules not yet wired to `correlation_store.py` — e.g. `k8s_secret_access_denied` (20), `k8s_multiple_403_public_ip` (10). Track under correlation proposals; optionally ship informational variants documented as weaker.
- **`correlation_rules/`** and any `rules/github_rules` patterns that only exist as correlation in `indexes/github.md`.
- **Disabled-by-default upstream** rules — may ship disabled in config or with explicit `Configuration Required` in docs.

## Engine and performance

Today the Python engine evaluates **every** loaded rule against **every** event in a batch. As rule count grows:

- **Short term**: Split deployments or rule subtrees per pipeline so `rules_dir` only contains applicable rules **or** add an optional `applies_to_log_type` guard in Python (future spec).
- **Document** in detection-engine spec that multi-source single-binary deployments may need **filtering** to avoid linear cost growth.

## Testing strategy

- For each new parser: **fixture JSONL** derived from upstream YAML `Tests:` blocks where possible.
- For each ported rule: parity test — same boolean result as upstream `ExpectedResult` on the same fixture (field path adjustments documented when iota envelope differs).

## Exit criteria per phase

1. **Phase A — Parsing**: Classifier recognizes type; sample file processes end-to-end; `log-processing` spec scenarios satisfied for that type.
2. **Phase B — Rules MVP**: At least N rules per pack (agreed N) with tests; no CRITICAL gaps on runbook for those rules.
3. **Phase C — Parity sweep**: Remaining single-event rules; threshold-heavy rules either implemented with new infrastructure or explicitly excluded in README for the pack.
