# iota — developer guide

This document is the **handbook for ongoing work** on iota: how to plan changes (OpenSpec), how to branch and test, how the detection pipeline fits together, and where deployments and infra repos fit. **Coding agents** should start with **[CLAUDE.md](../CLAUDE.md)** for a short reading list.

---

## 1. Repository map

| Area | Role |
|------|------|
| **`cmd/iota`** | CLI entrypoint: SQS mode, EventBridge mode, file/JSONL modes, health server, metrics. |
| **`internal/events`** | SQS / EventBridge processors, S3 notification handling. |
| **`internal/logprocessor`** | Adaptive classifier, parsers (CloudTrail, Okta, etc.), core **`Process(io.Reader)`** path. |
| **`internal/engine`** | Python rules engine subprocess (`--python`, `--engine`, `--rules`). |
| **`pkg/cloudtrail`** | Shared event shape and parsing helpers (many log types normalize into this model). |
| **`rules/`** | Detection rules (Python + metadata); image copies under **`/app/rules`** (see `Dockerfile`). |
| **`deployments/kubernetes`** | Base Deployment manifest; cluster overlays live in **iota-deployments**. |
| **`scripts/attack-sim/`** | End-to-end-ish simulation against real AWS + Prometheus counters. |
| **`openspec/`** | Structured specs and change proposals (see §2). |

**Architecture narrative:** [ARCHITECTURE.md](ARCHITECTURE.md) · **Breaking changes / releases:** [breaking-changes.md](breaking-changes.md) · **Troubleshooting:** [TROUBLESHOOTING.md](TROUBLESHOOTING.md)

---

## 2. Planning and design (OpenSpec)

Structured proposals and **current specs** live under **`openspec/`**. Full workflow for agents and humans: **[openspec/AGENTS.md](../openspec/AGENTS.md)**. Project context (log types, stack): **[openspec/project.md](../openspec/project.md)**.

**When to open a change**

- New capabilities, breaking API/schema changes, architecture shifts, performance work that changes behavior, bulk rule additions.
- **Skip** a formal proposal for: bug fixes restoring intended behavior, typos/formatting, non-breaking dependency bumps, single-rule tweaks, tests only.

**Typical flow**

1. Search existing work: browse **`openspec/changes/`** and **`openspec/specs/`**, or use your OpenSpec CLI if configured (`openspec list`, `openspec list --specs`).
2. Pick a unique **change id** (kebab-case, verb-led: `add-`, `update-`, `refactor-`).
3. Add **`openspec/changes/<id>/proposal.md`**, **`tasks.md`**, and **`design.md`** only when tradeoffs need recording.
4. Edit **canonical specs** in **`openspec/specs/<capability>/spec.md`** (this repo uses the Turo-style workflow: specs are truth on the branch, not only deltas in the change folder).
5. For review, generate or maintain **`spec-diff/`** under the change when your process requires it (see `AGENTS.md`).
6. Get approval before large implementations; implement **`tasks.md`** in order and check items off when done.

Capabilities today include **`log-processing`**, **`detection-engine`**, **`alerting`**, **`deployment`**, **`historical-queries`**, **`transforms`**, etc. Add a new capability folder if you introduce a major new surface area.

---

## 3. Branches, PRs, and merging

**Integration branches**

- **`main`** — Release line. Merges here can trigger the next **`v*.*.*`** tag and **[`.github/workflows/release.yml`](../.github/workflows/release.yml)** (Docker **`bilals12/iota`** with semver tags, **`latest`**, and optional **iota-deployments** bumps for overlays that track releases). Tagging is driven by **`scripts/next-release-version.sh`** and conventional history—not every push to **`main`** necessarily cuts a release.
- **`develop`** — Long-lived branch for work that should land in the repo *before* it is release-ready: OpenSpec-only PRs (**`proposal.md`**, **`tasks.md`**, **`design.md`**), docs, and stacked feature work. **Open PRs against `develop`** when the change should not go straight to a tagged release (for example, Azure design plumbing before implementation).

**Workflow**

- **Branch names:** `feature/<topic>`, `fix/<topic>`, or include the OpenSpec change id (`feature/add-azure-audit-parser`). Branch from **`develop`** for normal work; branch from **`main`** only when you need a hotfix or your team agrees to skip **`develop`**.
- **Pull requests:** Prefer **small, reviewable PRs** with a clear description linking an OpenSpec change when one exists. Rebase or merge from **`develop`** / **`main`** as your team agrees; avoid force-pushing shared branches; use **`--force-with-lease`** only on your feature branch if you must rewrite history.
- **Merging `develop` → `main`:** When a body of work is ready to ship, merge **`develop`** into **`main`** (or merge individual PRs to **`main`** if you use **`develop`** only as a staging area—pick one rhythm and stick to it).
- **Bootstrapping `develop` (iota):** The **`develop`** branch must exist on the remote for integration PRs and for **`.github/workflows/docker-develop.yml`**. If it does not exist yet: `git checkout main && git pull && git checkout -b develop && git push -u origin develop`, then set the default PR base in GitHub for contributor work as needed.

**Conventions:** Use **conventional commits** (`feat:`, `fix:`, `docs:`, `chore:`) so release tooling and release notes stay coherent (see [breaking-changes.md](breaking-changes.md)).

**Before merge:** `go test ./...` and **`./scripts/smoke.sh`** (or **`make ci-local`**) locally; CI must be green. Fork PRs run on GitHub-hosted runners; same-repo PRs use the org’s self-hosted labels—see [TROUBLESHOOTING.md](TROUBLESHOOTING.md) if CI env differs.

**Docs and breaking changes:** Anything that affects operators or detection contracts should be reflected in **`docs/breaking-changes.md`** or the relevant spec when applicable.

**Pre-release Docker images (test clusters)**

- Every push to **`develop`** runs **[`.github/workflows/docker-develop.yml`](../.github/workflows/docker-develop.yml)** on the **`homelab-arc-arm`** runner and pushes **`bilals12/iota:sha-<7>`** (immutable; matches that **iota** commit) plus **`bilals12/iota:develop`** (floating; useful for manual **`docker pull`**, not for GitOps).
- **iota-deployments:** Argo CD apps **`iota-homelab-test`** / **`iota-homelab-k3s-audit`** track branch **`develop`** in that repo. Commit **`newTag: sha-<7>`** there so the cluster runs a known image; see **iota-deployments** **`docs/git-branches.md`**. Release images and prod/lab bumps in **iota-deployments** **`main`** stay on **`v*.*.*`** via **`release.yml`** (see §8).

---

## 4. Local development and test-driven workflow

**Toolchain:** Go **1.25+**, Python **3.11+**, **CGO** enabled (SQLite / DuckDB). On macOS, install Xcode Command Line Tools so `gcc`/`clang` is available.

**Unit and integration tests**

```bash
export CGO_ENABLED=1
go test ./...
```

**TDD pattern for parsers and processors**

- Put **table-driven tests** next to code: e.g. `internal/logprocessor/parsers/*_test.go`, `internal/logprocessor/processor_*_fixtures_test.go` with golden JSONL under **`testdata/`**.
- Extend **fixtures** when you add a log shape; keep samples **minimal and sanitized** (no live secrets).
- Run targeted tests: `go test ./internal/logprocessor/parsers/ -run TestSomething -v`.

**Smoke test (full parse + Python rules on a fixture)**

```bash
make smoke
# or: ./scripts/smoke.sh
# or: SMOKE_JSONL=path/to/file.jsonl ./scripts/smoke.sh
```

**Match CI locally**

```bash
make pre-commit   # test + smoke + build
make ci-local     # fmt, lint, tests, smoke (no Docker)
```

More examples (gunzip pipes, CloudTrail integration tests): **[TESTING.md](../TESTING.md)**.

**In-cluster quick validation**

- **`./scripts/k8s-once-slack-test.sh`** — pipe a fixture through **`--mode=once`** in a pod (see TESTING.md).
- **`scripts/attack-sim/`** — real AWS APIs + CloudTrail delay; use a **lab account** only.

---

## 5. Where to implement a new log source (example: Azure / Microsoft Entra)

Use this as a **checklist**, not exhaustive for every Azure product. Entra / Azure Monitor audit logs differ by export path (Event Hub, storage, Sentinel); adapt ingestion to how you deliver JSON to iota (SQS, file, etc.).

| Layer | What to do |
|-------|------------|
| **Normalized event** | Prefer mapping into **`pkg/cloudtrail.Event`** (or a thin wrapper) so rules and dedupe stay consistent. |
| **Parser** | Add **`internal/logprocessor/parsers/<source>.go`** implementing **`ParserInterface`**: `ParseLog(string) ([]*cloudtrail.Event, error)` and **`LogType() string`** (e.g. `Azure.EntraAudit`). Follow patterns in **`gcp_audit.go`** or **`okta.go`**. |
| **Registration** | Wire the parser in **`internal/logprocessor/processor.go`** → **`getParsers()`** map keys must match **`LogType()`** strings. |
| **Classifier** | The adaptive classifier tries parsers in priority order; weak heuristics should **fail fast** on wrong inputs so penalties stay meaningful. |
| **Tests** | Add **`processor_*_fixtures_test.go`** (or parser unit tests) + JSONL under **`testdata/`**. |
| **Rules** | Add Python rules under **`rules/<pack>/`** and document in the pack README. |
| **OpenSpec** | Update **`openspec/specs/log-processing/spec.md`** (and **`detection-engine`** if rule contracts change); add **`openspec/changes/<id>/`** for non-trivial additions. |
| **Ingestion** | If events arrive on **SQS** (e.g. Lambda forwarder), **`cmd/iota`** and **`internal/events`** already implement queue polling; ensure the **message body** is a line or JSON your parser accepts. |
| **Kubernetes** | Base manifests in **`deployments/kubernetes/base`**; pinned overlays and image tags in **[iota-deployments](https://github.com/iota-corp/iota-deployments)**. |
| **IAM / cloud** | Long-lived AWS IAM for queues/S3 is often in **[iota-infra](https://github.com/iota-corp/iota-infra)**; Azure-side resources are not in this repo—document them in OpenSpec or infra docs. |

For **GCP** or **GitHub** shapes already in-tree, grep for **`GCP.AuditLog`** or **`GitHub.Audit`** and mirror structure.

---

## 6. Detection pipeline (CloudTrail)

**Preferred path — EventBridge → SQS (`--mode=eventbridge`):** CloudTrail emits on the **default event bus**; a rule sends **`AWS API Call via CloudTrail`** events to **SQS**; **`cmd/iota/eventbridge_handler.go`** unmarshals json and runs **logprocessor** + **rules** with spans such as **`process_eventbridge_event`**. **Lower latency** than waiting for **S3 log files**. See **[README.md](../README.md#how-it-works)** for performance notes and EventBridge **rule pattern** pitfalls (`source` is usually the **calling service**, not `aws.cloudtrail`).

**Cost-saving / file path — S3 notifications → SQS (`--mode=sqs`):**

1. **S3** `ObjectCreated` on CloudTrail prefix → **SNS** → **SQS** message with bucket/key.
2. **`cmd/iota/sqs_handler.go`** receives messages, **GetObject**s the body, **gunzips** when the key ends with **`.gz`** or **`Content-Encoding: gzip`** (same idea as **`s3poller`**), passes the stream to **`logprocessor.Processor.Process`**, then runs the **rules engine** on batches.
3. Matches go to **deduplication** and **alert** outputs (Slack, etc.).

**Latency:** For **`sqs`**, most “why did my test wait 10 minutes?” is **CloudTrail → S3 delivery**, not iota. See **[docs/detection-pipeline-checklist.md](detection-pipeline-checklist.md)** for end-to-end vs tunable vs not-yet-wired behavior.

**SQS receive behavior:** **`internal/events/sqs_processor.go`** implements long polling. **`runSQS`** and **`runEventBridge`** use **`MaxMessages: 10`** and **`WaitTime: 20`** by default, overridable with **`IOTA_SQS_MAX_MESSAGES`** (1–10) and **`IOTA_SQS_WAIT_SECONDS`** (0–20).

**Gzip / `.json.gz`:** **`internal/s3poller/s3poller.go`** and the **SQS** path in **`sqs_handler`** both decompress gzip for standard CloudTrail objects (`.gz` suffix or gzip content-encoding).

**Rules scope:** The image bundles rules under **`/app/rules`**. Base Kubernetes args use **`--rules=/app/rules/aws_cloudtrail`** (subset). Narrowing **`--rules`** reduces Python work per event.

---

## 7. Logs and metrics (what to grep for)

- **Detections:** `cmd/iota/match_log.go` logs lines of the form
  **`detection: rule_id=… severity=… eventSource=… eventName=… title="…"`**
  when a rule matches.
- **Batch summary:** Processing logs **`processed N events, M matches`** (and similar) after rule evaluation.
- **Prometheus:** With **`ENABLE_METRICS=true`**, scrape **`/metrics`** (container port **8080** in Kubernetes). Useful series include **`iota_events_processed_total`**, **`iota_alerts_generated_total`**, **`iota_alerts_forwarded_total`** (e.g. **`output_type="slack"`**), and Slack failures via **`status="failure"`**.
- **Rule throughput:** **`iota_rules_evaluated_total{rule_id,result}`** with **`result`** **`match`** or **`no_match`** — incremented from the Python engine’s per-batch aggregates (not one time series per event).
- **State / dedup DB:** **`iota_statedb_operations_total{operation,status}`** and **`iota_statedb_operation_duration_seconds{operation}`** — covers dedup **`update_alert_info`**, **`list_open_alerts_all`**, pipeline cursor **`state_get_last_key`** / **`state_update_last_key`**, and schema init.

**Where incident responders query**

| Need | Tool | Latency expectation |
|------|------|---------------------|
| Open alerts (deduped rows: rule, severity, title, times) | **`iota alerts list --db /path/to/state.db`** (same file as **`--state`**) | Local SQLite; aim for **ms** on typical limits (use **`--limit` / `--offset`**) |
| Raw / historical events in the data lake | **`iota query`** (Athena / DuckDB) | Seconds (S3 + engine), not comparable to the dedup path |

Under pressure, use **`alerts list`** for triage; use **`query`** for hunting. **`scripts/benchmark-alert-query.sh`** runs repeated **`alerts list`** for a rough wall-clock baseline.

**Data lake (so `iota query` has JSON to scan)**

1. Set **`DATA_LAKE_BUCKET`** in **`iota-deployments`** (same bucket as CloudTrail delivery is OK: iota writes under **`logs/<slug>/year=…/hour=…/*.json.gz`**, separate from AWS’s trail object layout). The Deployment passes **`--data-lake-bucket=$(DATA_LAKE_BUCKET)`**; when empty, the writer is off and the lake has nothing to query.
2. **IAM:** the identity in **`iota-aws-prod`** / **`iota-aws-test`** (homelab) or IRSA role (EKS) needs **`s3:PutObject`** (and related) on that bucket. If writes fail, check pod logs and **`iota_processing_errors_total{component="datalake"}`** on **`/metrics`**.
3. **`iota query`** defaults **`--s3-bucket`** from env, first match: **`IOTA_S3_BUCKET`**, **`IOTA_DATA_LAKE_BUCKET`**, **`DATA_LAKE_BUCKET`**. Inside the pod, with **`DATA_LAKE_BUCKET`** set, you can run **`kubectl exec … -- /app/iota query …`** without repeating the bucket name.
4. Lake rows are **normalized CloudTrail-shaped JSON** (see **`pkg/cloudtrail.Event`**): top-level fields such as **`eventName`**, **`eventSource`**, **`sourceIPAddress`**, **`awsRegion`**, **`recipientAccountId`**, plus nested **`userIdentity`**. DuckDB exposes columns from **`read_ndjson`**; filter on top-level fields first, then use **`json()`** / **`->>`** if you need nested paths. Example:

```text
/app/iota query --log-type=cloudtrail --last=24h --output=table \
  --sql="SELECT eventName, eventSource, sourceIPAddress, recipientAccountId FROM {TABLE}
         WHERE eventName = 'ListManagedNotificationEvents'
           AND sourceIPAddress = '173.33.31.53'
         LIMIT 50"
```

Use **`--start`** / **`--end`** (RFC3339) for an alert’s **`created`–`updated`** window; **`--end` is exclusive**, so **`--start=…T19:00:00Z --end=…T20:00:00Z`** scans only the **hour=19** partition (UTC). For Athena instead of DuckDB, set **`IOTA_ATHENA_*`** env vars and **`--force-athena`** when wired.

Use **[docs/detection-pipeline-checklist.md](detection-pipeline-checklist.md)** § Observability for a short checklist.

---

## 8. Kubernetes and GitOps (`iota-deployments`)

The **`iota`** repo ships **base manifests** under **`deployments/kubernetes/base`**. Day-to-day cluster-specific values (image tag, queue URL, bucket, region, optional data lake) live in the separate **`iota-deployments`** repo (overlays such as **`clusters/homelab-prod`**, **`clusters/homelab-test`**, **`clusters/eks-lab`**). **homelab-test** / **homelab-k3s-audit** use **pinned** **`sha-<7>`** tags on **iota-deployments** branch **`develop`** (Argo), not release **`v*.*.*`** bumps — see **`iota-deployments/docs/git-branches.md`** and **`homelab-k3s.md`** (Test: dev images).

**Homelab (k3s on Beelink, Tailscale):**

- **`iota-deployments/docs/homelab-k3s.md`** — kubeconfig over Tailscale, **`tls-san`**, **`iota-aws-prod`** / **`iota-aws-test`**, Argo CD, **kube-prometheus-stack**, and **HTTP Ingress** for Grafana + Argo CD (**`manifests/tailnet-ingress/`**, **`homelab-tailnet-ingress`** Application).
- **Important:** Multi-source Argo apps (e.g. **kube-prometheus-stack**) pull Helm **values from Git**; if something is only in a local clone, **push to the remote `main`** (or whatever **`targetRevision`**) before expecting the cluster to match.

**Release automation:** Pushes that create **`v*.*.*`** tags can bump image tags in **`iota-deployments`** via **`IOTA_DEPLOYMENTS_TOKEN`** (see root **README** § releases & docker image).

**AWS IAM / EKS / queues:** Often defined in **`iota-infra`**; homelab may use IAM users + keys in Secrets instead of IRSA. See **`iota-infra/README.md`** and **`iota-deployments/README.md`** for the split of responsibilities.

---

## 9. Attack simulation (live AWS)

- **`scripts/attack-sim/attack-sim.sh`** — drives **real AWS API** activity (IAM user/role/S3 depending on mode), compares **CloudTrail** visibility to **iota Prometheus** counters.
  - **`ATTACK_SIM_MODE=minimal`** — IAM user create/delete only (fastest).
  - **`ATTACK_SIM_MODE=full`** — IAM + role + S3 (default).
  - Uses **`WAIT_AFTER_SECONDS`** (default **600**) because **CloudTrail batching to S3** dominates delay.
  - Point **`IOTA_METRICS_URL`** at iota’s **`/metrics`** (e.g. port-forward **`svc/iota`** `18080:8080`).

---

## 10. Parallels to [Substation](https://github.com/brexhq/substation) (pipeline mindset)

[Substation](https://github.com/brexhq/substation) is a Go toolkit for **routing, normalizing, and enriching** security and audit logs (similar in spirit to Logstash / Fluentd, AWS-native). Forks such as **[redteamtools/substation](https://github.com/redteamtools/substation)** track the same ideas. None of this is a dependency of iota; the README is a useful **reference for how to think about pipeline engineering** when you extend iota.

| Substation idea | How it relates to iota |
|-----------------|-------------------------|
| **Pipeline of transforms** — ingest → normalize → enrich → ship | iota’s path is **classify → parse (`logprocessor`) → rules engine → dedupe → alerts** (and optional data lake). Keep stages explicit when you add features so metrics and logs stay interpretable. |
| **Routing ≈ transforming** — “data transformation and routing are functionally equivalent” (reorder steps deliberately) | New code should respect **ordering constraints** iota already has (e.g. state/dedup after parse, alerts after matches). Where Substation is maximally flexible, iota trades that for **deterministic detection** — document any new branch that skips or reorders stages. |
| **Declarative, versioned configs** (Jsonnet) + **CLI tests** (`substation test` on examples) | iota uses **Go + YAML/Kustomize + Python rules**. Same discipline: **rules and deployment knobs live in Git**, `go test ./...` and **fixtures** ([TESTING.md](../TESTING.md)) prove parsers and helpers; **`scripts/attack-sim/`** stress-tests the live AWS path. Prefer adding **small reproducible examples** when behavior is config-shaped. |
| **Same behavior everywhere** (laptop, container, Lambda) | Aim for **parity** between **`--jsonl` / file modes** and **SQS mode** for parsing and detection outcomes; **`--mode=once`** with a local file may still use **`gunzip -c`** when your fixture is gzipped. |
| **Target schemas** (ECS, OCSF, “bring your own”) | iota normalizes to internal **`ProcessedEvent`** / **`cloudtrail.Event`** shapes. If you export or integrate with other tools, **naming and field mapping** deserve the same explicit contract Substation gives ECS/OCSF examples. |
| **Optional enrichment via external APIs** | Substation highlights affordable enrichment at scale. iota today is mostly **in-account batch detection**; future enrichment should stay **explicit in IAM and cost** (similar “least privilege + observable” posture as their Terraform stories). |
| **Terraform / in-account deployment** | Substation ships modules; iota uses **`iota-deployments`** / **`iota-infra`**. Same lesson: **reproducible infra**, secrets outside Git, least-privilege IAM. |
| **Dev environment consistency** (e.g. devcontainer in their CONTRIBUTING flow) | Optional for iota: a pinned **Go + Python** environment (Dockerfile, devcontainer, or `mise`/`asdf`) reduces “works on my machine” for rules and integration tests. |

**Further reading:** Substation’s [README](https://github.com/brexhq/substation/blob/main/README.md) (routing examples, Jsonnet snippets, testing section). Use it for **patterns**, not as an implementation spec for iota.

---

## 11. Quick reference — related documents

| Document | Use when |
|----------|----------|
| [CLAUDE.md](../CLAUDE.md) | Short agent entry point and doc index. |
| [detection-pipeline-checklist.md](detection-pipeline-checklist.md) | Tuning SQS behavior, latency expectations, observability checklist. |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Data flow, components, data lake layout. |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | Operational issues. |
| [breaking-changes.md](breaking-changes.md) | Releases and API expectations. |
| [TESTING.md](../TESTING.md) | CLI examples, gunzip pipes, integration tests. |
| `iota-deployments/docs/homelab-k3s.md` | Homelab k3s, Tailscale, Argo, Grafana/Ingress. |
| `iota-deployments/docs/git-branches.md` | **`main`** vs **`develop`**, Argo **`targetRevision`**, pinned **`sha-*`** test images. |
| `iota-deployments/README.md` | How **iota** / **iota-deployments** / **iota-infra** relate. |

---

*Keep this file accurate when you change defaults in **`cmd/iota/sqs_handler.go`**, deployment args, or the detection checklist. Refresh §10 if iota’s pipeline stages or testing story changes materially.*
