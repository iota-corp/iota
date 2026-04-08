# iota — developer guide

This document is the **handbook for ongoing work** on iota: how the detection pipeline fits together, what to tune, how deployments and the homelab GitOps repo relate to this codebase, and where deeper docs live.

---

## 1. Repository map

| Area | Role |
|------|------|
| **`cmd/iota`** | CLI entrypoint: SQS mode, EventBridge mode, file/JSONL modes, health server, metrics. |
| **`internal/events`** | SQS / EventBridge processors, S3 notification handling. |
| **`internal/logprocessor`** | Adaptive classifier, parsers (CloudTrail, Okta, etc.), core **`Process(io.Reader)`** path. |
| **`internal/engine`** | Python rules engine subprocess (`--python`, `--engine`, `--rules`). |
| **`pkg/cloudtrail`** | CloudTrail event types and parsing helpers. |
| **`rules/`** | Detection rules (Python + metadata); image copies under **`/app/rules`** (see `Dockerfile`). |
| **`deployments/kubernetes`** | Base Deployment: `--mode=sqs`, **`--rules=/app/rules/aws_cloudtrail`**, engine path, env placeholders. |
| **`scripts/attack-sim/`** | End-to-end-ish simulation against real AWS + Prometheus counters. |

**Architecture narrative:** [docs/ARCHITECTURE.md](ARCHITECTURE.md) · **Breaking changes / releases:** [docs/breaking-changes.md](breaking-changes.md) · **Troubleshooting:** [docs/TROUBLESHOOTING.md](TROUBLESHOOTING.md)

---

## 2. Detection pipeline (CloudTrail / S3 → SQS)

High level:

1. **S3** `ObjectCreated` on CloudTrail prefix → **SNS** → **SQS** message with bucket/key.
2. **`cmd/iota/sqs_handler.go`** receives messages, **GetObject**s the body, **gunzips** when the key ends with **`.gz`** or **`Content-Encoding: gzip`** (same idea as **`s3poller`**), passes the stream to **`logprocessor.Processor.Process`**, then runs the **rules engine** on batches.
3. Matches go to **deduplication** and **alert** outputs (Slack, etc.).

**Latency:** Most “why did my test wait 10 minutes?” is **CloudTrail → S3 delivery**, not iota. See **[docs/detection-pipeline-checklist.md](detection-pipeline-checklist.md)** for end-to-end vs tunable vs not-yet-wired behavior.

**SQS receive behavior:** **`internal/events/sqs_processor.go`** implements long polling. **`runSQS`** and **`runEventBridge`** use **`MaxMessages: 10`** and **`WaitTime: 20`** by default, overridable with **`IOTA_SQS_MAX_MESSAGES`** (1–10) and **`IOTA_SQS_WAIT_SECONDS`** (0–20).

**Gzip / `.json.gz`:** **`internal/s3poller/s3poller.go`** and the **SQS** path in **`sqs_handler`** both decompress gzip for standard CloudTrail objects (`.gz` suffix or gzip content-encoding).

**Rules scope:** The image bundles rules under **`/app/rules`**. Base Kubernetes args use **`--rules=/app/rules/aws_cloudtrail`** (subset). Narrowing **`--rules`** reduces Python work per event.

---

## 3. Logs and metrics (what to grep for)

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

Use **[docs/detection-pipeline-checklist.md](detection-pipeline-checklist.md)** § Observability for a short checklist.

---

## 4. Kubernetes and GitOps (`iota-deployments`)

The **`iota`** repo ships **base manifests** under **`deployments/kubernetes/base`**. Day-to-day cluster-specific values (image tag, queue URL, bucket, region, optional data lake) live in the separate **`iota-deployments`** repo (overlays such as **`clusters/homelab`**, **`clusters/eks-lab`**).

**Homelab (k3s on Beelink, Tailscale):**

- **`iota-deployments/docs/homelab-k3s.md`** — kubeconfig over Tailscale, **`tls-san`**, **`iota-aws`** secret, Argo CD, **kube-prometheus-stack**, and **HTTP Ingress** for Grafana + Argo CD (**`manifests/tailnet-ingress/`**, **`homelab-tailnet-ingress`** Application).
- **Important:** Multi-source Argo apps (e.g. **kube-prometheus-stack**) pull Helm **values from Git**; if something is only in a local clone, **push to the remote `main`** (or whatever **`targetRevision`**) before expecting the cluster to match.

**Release automation:** Pushes that create **`v*.*.*`** tags can bump image tags in **`iota-deployments`** via **`IOTA_DEPLOYMENTS_TOKEN`** (see root **README** § releases & docker image).

---

## 5. Local testing and attack simulation

- **Unit / integration:** `go test ./...` — see [TESTING.md](../TESTING.md) for real CloudTrail fixture tests and CLI examples.
- **`scripts/attack-sim/attack-sim.sh`** — drives **real AWS API** activity (IAM user/role/S3 depending on mode), compares **CloudTrail** visibility to **iota Prometheus** counters.
  - **`ATTACK_SIM_MODE=minimal`** — IAM user create/delete only (fastest).
  - **`ATTACK_SIM_MODE=full`** — IAM + role + S3 (default).
  - Uses **`WAIT_AFTER_SECONDS`** (default **600**) because **CloudTrail batching to S3** dominates delay.
  - Point **`IOTA_METRICS_URL`** at iota’s **`/metrics`** (e.g. port-forward **`svc/iota`** `18080:8080`).

---

## 6. OpenSpec and product docs

Structured proposals and specs live under **`openspec/`** (see **`openspec/AGENTS.md`** for agents). Use them when changing behavior that affects multiple packages or external contracts.

---

## 7. Parallels to [Substation](https://github.com/brexhq/substation) (pipeline mindset)

[Substation](https://github.com/brexhq/substation) is a Go toolkit for **routing, normalizing, and enriching** security and audit logs (similar in spirit to Logstash / Fluentd, AWS-native). Forks such as **[redteamtools/substation](https://github.com/redteamtools/substation)** track the same ideas. None of this is a dependency of iota; the README is a useful **reference for how to think about pipeline engineering** when you extend iota.

| Substation idea | How it relates to iota |
|-----------------|-------------------------|
| **Pipeline of transforms** — ingest → normalize → enrich → ship | iota’s path is **classify → parse (`logprocessor`) → rules engine → dedupe → alerts** (and optional data lake). Keep stages explicit when you add features so metrics and logs stay interpretable. |
| **Routing ≈ transforming** — “data transformation and routing are functionally equivalent” (reorder steps deliberately) | New code should respect **ordering constraints** iota already has (e.g. state/dedup after parse, alerts after matches). Where Substation is maximally flexible, iota trades that for **deterministic detection** — document any new branch that skips or reorders stages. |
| **Declarative, versioned configs** (Jsonnet) + **CLI tests** (`substation test` on examples) | iota uses **Go + YAML/Kustomize + Python rules**. Same discipline: **rules and deployment knobs live in Git**, `go test ./...` and **fixtures** ([TESTING.md](../TESTING.md)) prove parsers and helpers; **`scripts/attack-sim/`** stress-tests the live AWS path. Prefer adding **small reproducible examples** when behavior is config-shaped. |
| **Same behavior everywhere** (laptop, container, Lambda) | Aim for **parity** between **`--jsonl` / file modes** and **SQS mode** for parsing and detection outcomes; **`--mode=once`** with a local file may still use **`gunzip -c`** when your fixture is gzipped. |
| **Target schemas** (ECS, OCSF, “bring your own”) | iota normalizes to internal **`ProcessedEvent`** / **`cloudtrail.Event`** shapes. If you export or integrate with other tools, **naming and field mapping** deserve the same explicit contract Substation gives ECS/OCSF examples. |
| **Optional enrichment via external APIs** | Substation highlights affordable enrichment at scale. iota today is mostly **in-account batch detection**; future enrichment should stay **explicit in IAM and cost** (similar “least privilege + observable” posture as their Terraform stories). |
| **Terraform / in-account deployment** | Substation ships modules; iota uses **`iota-deployments`** / infra repos. Same lesson: **reproducible infra**, secrets outside Git, least-privilege IAM. |
| **Dev environment consistency** (e.g. devcontainer in their CONTRIBUTING flow) | Optional for iota: a pinned **Go + Python** environment (Dockerfile, devcontainer, or `mise`/`asdf`) reduces “works on my machine” for rules and integration tests. |

**Further reading:** Substation’s [README](https://github.com/brexhq/substation/blob/main/README.md) (routing examples, Jsonnet snippets, testing section). Use it for **patterns**, not as an implementation spec for iota.

---

## 8. Quick reference — related documents

| Document | Use when |
|----------|----------|
| [detection-pipeline-checklist.md](detection-pipeline-checklist.md) | Tuning SQS behavior, latency expectations, observability checklist. |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Data flow, components, data lake layout. |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | Operational issues. |
| [breaking-changes.md](breaking-changes.md) | Releases and API expectations. |
| `iota-deployments/docs/homelab-k3s.md` | Homelab k3s, Tailscale, Argo, Grafana/Ingress. |
| [TESTING.md](../TESTING.md) | CLI examples, gunzip pipes, integration tests. |

---

*Keep this file accurate when you change defaults in **`cmd/iota/sqs_handler.go`**, deployment args, or the detection checklist. Refresh §7 if iota’s pipeline stages or testing story changes materially.*
