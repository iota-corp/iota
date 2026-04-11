# Spec diff: add-extended-source-detections

Manual summary for review (regenerate with `/openspec-spec-diff` if the project uses automated annotation).

## `openspec/specs/log-processing/spec.md`

- Added **Requirement: Extended sources (parity track)** with a table of target log types (`AWS.BedrockModelInvocation`, `GitHub.Audit`, `GCP.AuditLog`, `GCP.HTTPLoadBalancer`, `Amazon.EKS.Audit`, `Slack.AuditLogs`, `Cloudflare.HttpRequest`).
- Added scenarios: normalized `cloudtrail.Event` envelope; classifier registration consistent with existing parsers.
- Extended **Current Implementation** with a pointer to this change folder.

## `openspec/specs/detection-engine/spec.md`

- Under **Rule filtering by log type**, added a note that the reference Python engine may evaluate all rules in `rules_dir` and that deployments should restrict paths or add guards when rule count grows.
- Added **Requirement: Extended rule packs** for `rules/<logical_source>/` layout and ported single-event rules from upstream YAML.
- Added **Scenario: Out of scope upstream patterns** for correlation, queries, lookups, and threshold-only behavior (defer to `plan-extended-sources-correlation`).
