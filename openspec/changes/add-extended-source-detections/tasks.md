# Tasks: Add extended source detections

**Status:** Implementation complete through Phase 6 (hardening docs + rule counts). **Next:** build and push the dev image to `security-test`, validate, then archive this change (see Phase 6).

## Phase 0 — Alignment (this change)

- [x] Author `proposal.md`, `design.md`, and this `tasks.md`.
- [x] Update `openspec/specs/log-processing/spec.md` and `openspec/specs/detection-engine/spec.md` with additive requirements for extended sources.
- [x] Add `spec-diff/index.md` (manual summary; regenerate with `/openspec-spec-diff` if desired).
- [ ] Stakeholder sign-off on phase order and deferred items (Azure, threshold-only rules). *(Optional; track outside repo if needed.)*

## Phase 1 — Spikes and infrastructure

- [ ] Per source in `design.md`, document **chosen ingestion** (S3 prefix, queue, EventBridge partner) in `iota-deployments` / `iota-infra` README or module docs (as appropriate).
- [x] Add **fixture samples** (sanitized) for `AWS.BedrockModelInvocation`, `GitHub.Audit`, and `GitHub.Webhook` under `testdata/rulesets/`.
- [x] Implement **adaptive classifier + parser** for `AWS.BedrockModelInvocation`, `GitHub.Audit`, and `GitHub.Webhook` (extend to remaining types per phases below).

## Phase 2 — GCP family

- [x] `GCP.AuditLog` and `GCP.HTTPLoadBalancer` parsers, classifier registration, `testdata/rulesets/gcp_*`, engine unwrap, `lakepath` shorthands.
- [x] Port `gcp_audit_rules`, `gcp_k8s_rules`, and `gcp_http_lb_rules` Python packs (`scripts/port_gcp_rules.py`); `rules/helpers/gcp_helpers.py`; `iota_helpers.deep_walk` / `key_value_list_to_dict`.
- [ ] Validate against upstream YAML `Tests:` fixtures and document field-path deltas.
- [x] Update `openspec/project.md` supported sources table (operator-facing deployment matrix lives in infra repos).

## Phase 3 — AWS Bedrock and Kubernetes

- [x] `AWS.BedrockModelInvocation` parser; port `aws_bedrockmodelinvocation_rules` (ingestion wiring still per deployment).
- [x] `Amazon.EKS.Audit` parser (`eks.amazonaws.com` unwrap), `testdata/rulesets/eks_audit/`, `scripts/smoke-kubernetes.sh`, `lakepath` shorthands (`eks`, …).
- [x] Port `kubernetes_rules` to `rules/kubernetes/` (`scripts/port_kubernetes_rules.py`); `k8s_udm` + `kubernetes_helpers.py` for EKS audit + GCP `k8s.io` audit; README for skipped/deferred/threshold rules.
- [ ] Azure / `Azure.MonitorActivity` k8s paths (optional; not in scope until ingest exists).

## Phase 4 — SaaS: Slack and Cloudflare

- [x] `Slack.AuditLogs` parser (`slack.com` unwrap), `rules/slack_audit/` (`scripts/port_slack_rules.py`), `slack_helpers.py`, fixtures, `scripts/smoke-phase4.sh` (Slack leg).
- [x] `Cloudflare.Firewall` and `Cloudflare.HttpRequest` parsers (`cloudflare.com.firewall` / `cloudflare.com.http_request` unwrap), `rules/cloudflare/` (including threshold rules via `correlation_store.py`), `cloudflare_helpers.py`, fixtures.
- [ ] Ingestion volume / sampling guidance in infra repos (HTTP Logpush).

## Phase 5 — GitHub

- [x] `GitHub.Audit` and `GitHub.Webhook` parsers; unwrap in `engines/iota/engine.py`; fixtures and `scripts/smoke-github.sh`.
- [x] Port `github_rules` to `rules/github_audit/` and `rules/github_webhook/` (including `github_repo_initial_access.py` via `rules/helpers/correlation_store.py`).

## Phase 6 — Hardening (complete)

- [x] **Rule / log-type filtering:** Documented operational pattern (per-pipeline `--rules` path, symlinked subsets). The reference engine still evaluates all rules under `rules_dir`; no code change required for this release.
- [x] **Rule counts:** `openspec/specs/detection-engine/spec.md` and `openspec/project.md` updated to **254** rules (excluding `rules/helpers/`).
- [ ] **Archive:** After successful validation in **security-test** (dev image), run `openspec archive add-extended-source-detections --skip-specs --yes` from the repo root (requires OpenSpec CLI). If you regenerate `spec-diff/`, do so before archiving.

---

**Handoff for dev image / `security-test`**

- Ensure the workload sets `--rules` appropriately; for full integration tests use the full `rules/` tree; for cost-sensitive pipelines narrow the path.
- Mount or persist a volume for `IOTA_CORRELATION_STATE` if correlation rules (Slack DoS, Cloudflare volume, GitHub first repo access) are enabled.
- Smoke scripts: `scripts/smoke-phase4.sh`, `scripts/smoke-github.sh`, `scripts/smoke-kubernetes.sh`, `scripts/smoke-bedrock.sh` (as applicable to what you ingest).
