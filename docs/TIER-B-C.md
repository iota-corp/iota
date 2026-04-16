# Tier B (performance) and Tier C (ops)

This document tracks **B** (faster paths without new AWS products) and **C** (reliability/operations). Cross-links: **[detection-pipeline-checklist.md](detection-pipeline-checklist.md)**, **[DEVELOPMENT.md](DEVELOPMENT.md)**.

## Environment variables (SQS + EventBridge)

| Variable | Default | Range | Effect |
|----------|---------|-------|--------|
| **`IOTA_SQS_MAX_MESSAGES`** | `10` | 1–10 | `ReceiveMessage` batch size. Higher pulls more messages per poll when backlogged. |
| **`IOTA_SQS_WAIT_SECONDS`** | `20` | 0–20 | Long-poll wait when the queue is empty. **Lower** (e.g. `5`) reduces worst-case delay before the next receive returns; **more** API calls. |
| **`IOTA_SQS_PROCESS_CONCURRENCY`** | `1` | 1–32 | Process **multiple SQS messages from one receive** in parallel (**both** `--mode=sqs` and `--mode=eventbridge`). Requires SQLite **WAL** (enabled in code for state + dedup DBs). Start with **2–4** and watch logs for `database is locked`. |
| **`IOTA_LATENCY_TRACE`** | off | `1`/`true`/`yes` | Per S3 object latency line (SQS path only); see detection-pipeline-checklist. |

**EventBridge path:** the same variables apply—the consumer is still **SQS** `ReceiveMessage`. Tuning **`WAIT_SECONDS`** and **`PROCESS_CONCURRENCY`** affects how quickly bursts drain and how much parallel **rules engine** work runs.

**Further latency (100–200 ms):** dominated by **`engine.Analyze`** (Python). Use **`iota_rules_evaluated_total{rule_id,result}`** to find hot rules; narrow **`--rules`**; increase CPU **limits** on the Deployment if the node allows.

## Tier B — status

| ID | Item | Status |
|----|------|--------|
| **B1** | Document / set `IOTA_SQS_*` in overlays | Homelab overlays set explicit values; this doc + checklist. |
| **B2** | Parallelism | **`IOTA_SQS_PROCESS_CONCURRENCY`** + parallel **SQS messages** per receive. **`--download-workers`** caps parallel **S3 object** handlers when one notification has **multiple `Records`** (same message body). SQLite: **`internal/sqliteutil`** WAL + busy timeout on state/dedup. **`--process-workers`**: not wired (reserved). **Bloom:** **`internal/bloom.Filter`** already uses a mutex around Test/Add — safe with parallel handlers. |
| **B3** | Hot rules / CPU | Operational: Grafana/Prometheus **`iota_rules_evaluated_total`**, **`rule_id`**; bump CPU **limits** if needed. |
| **B4** | Data lake non-blocking | Only if measured: buffer **`datalake.Writer`** after detect so Glue/S3 flush does not block alerts (not implemented by default). |

### Reliability: S3 → SQS message shape

**`ParseS3Notification`** in **`internal/events/sqs_processor.go`** already supports:

- **S3 → SQS direct:** top-level **`Records`** array.
- **S3 → SNS → SQS:** SNS **`Notification`** envelope with **`Message`** containing **`Records`**.

Tests: **`TestParseS3Notification/direct_S3_ObjectCreated_Put_top_level_Records`**.

## Tier C — ops

| ID | Item | Scope |
|----|------|--------|
| **C1** | **DLQ + alarms** | Configure a **dead-letter queue** on the ingestion SQS queue(s); **CloudWatch** alarm on **`ApproximateAgeOfOldestMessage`** and failed deliveries. Implement in **iota-infra** Terraform per environment. |
| **C2** | **Replicas vs queue** | **Multiple replicas** = competing consumers on the **same** standard queue (at-least-once delivery, possible duplicate processing). Prefer **one replica per queue** for deterministic behavior, or **FIFO** + dedup, or **shard** workloads by queue. |

## References

- **[README.md](../README.md#how-it-works)** — CloudTrail EventBridge vs S3/SQS latency framing.
- **`cmd/iota/sqs_handler.go`** — `sqsReceiveConfigFromEnv`, `sqsProcessConcurrencyFromEnv`.
