# Detection pipeline — operations and roadmap checklist

Use this when tuning latency, throughput, or explaining “why is iota idle?” vs other namespaces.

## End-to-end latency (what AWS controls vs iota)

**CloudTrail + EventBridge + SQS (`--mode=eventbridge`) — default for low latency**

- [ ] **CloudTrail → EventBridge → rule → SQS**: Typically **seconds** from API call to message in SQS (plus **SQS** long-poll wait, default **20s** max when empty). iota work per message is **small JSON** → **rules engine**; OTel spans include **`process_eventbridge_event`** (not **`s3.GetObject`**).
- [ ] **Rule pattern**: Must match real **`AWS API Call via CloudTrail`** events ( **`source`** is usually the **originating service**, e.g. `aws.s3`, not only `aws.cloudtrail` ) or the queue stays empty while S3 logging still works.

**CloudTrail + S3 file + SQS (`--mode=sqs`) — cost-saving / batched**

- [ ] **CloudTrail → S3**: AWS batches and delivers log files on a **multi-minute** cadence (often ~5–15 minutes). This dominates “attack-sim waited 600s” style tests; iota cannot shorten CloudTrail’s delivery SLA.
- [ ] **S3 event → SQS → iota**: After an object lands, SQS long polling uses **WaitTimeSeconds** (default **20**). Each receive can wait up to that long when the queue is empty.
- [ ] **Per-object work**: One gzip log file → **GetObject** → parse → one Python **engine** subprocess per batch of events. Large rule sets increase CPU time per batch. OTel spans include **`process_s3_object`**, **`s3.GetObject`**, **`logprocessor.Process`**.

## iota throughput (tunables today)

- [x] **`IOTA_SQS_MAX_MESSAGES`**: SQS receive batch size, **1–10** (default **10**). Higher can pull more notifications per poll when the queue is backlogged. Wired in **`runSQS`** / **`runEventBridge`**.
- [x] **`IOTA_SQS_WAIT_SECONDS`**: Long-poll wait, **0–20** (default **20**). Lower reduces worst-case latency when the queue is empty; slightly more API calls. Wired in **`runSQS`** / **`runEventBridge`**.
- [x] **`IOTA_SQS_PROCESS_CONCURRENCY`**: Process **multiple messages from one receive** in parallel (**1–32**, default **1**). State/dedup SQLite uses **WAL** + busy timeout to reduce lock contention. See **[TIER-B-C.md](TIER-B-C.md)**.
- [ ] **Deployment CPU/memory**: If the **Python** rule engine is CPU-bound, raising CPU **limit** on the iota container can help. Grafana “Kubernetes / Compute Resources / Namespace” is expected to show **security** as small if traffic is low—that is normal; scale up when processing **lags the queue**.

## Not wired yet (known gaps)

- [ ] **`--download-workers` / `--process-workers`**: Parsed in `main` but **not applied** to SQS mode today; processing is effectively **one S3 object at a time** per goroutine path. Parallel object processing is a future improvement.
- [ ] **Rule evaluation cost**: Every event is still evaluated against **all** loaded rules; shrinking `--rules` reduces CPU — metrics now expose **`match`/`no_match`** counts per **`rule_id`** to spot hot rules.

## Data lake (hunting)

- [ ] **`DATA_LAKE_BUCKET`** set in **`iota-deployments`** so **`--data-lake-bucket`** is non-empty and iota writes **`logs/.../*.json.gz`**. Without it, **`iota query`** has no lake objects (only CloudTrail in AWS helps).
- [ ] **IAM:** **`s3:PutObject`** (and list/get as needed) on that bucket for the workload identity.

## Latency profiling (S3 vs SQS vs iota)

- [x] **`IOTA_LATENCY_TRACE`**: Set to `true` / `1` / `yes` on the iota workload. Logs one `latency_trace` line per S3 object with **`s3_last_modified`**, **SQS `SentTimestamp` / `ApproximateFirstReceiveTimestamp` / receive count**, **min/max CloudTrail `eventTime`** in the batch, and **handler wall time**. Compare to manual **`aws s3api head-object`** via **`scripts/aws-latency-correlation.sh`**.

## Observability

- [x] **Logs**: Each match logs a line
  `detection: rule_id=… severity=… eventSource=… eventName=… title="…"`
  (**SQS** and **EventBridge** paths), followed by `processed N events, M matches …`.
- [x] **Prometheus**: `iota_alerts_generated_total` increments per deduped alert; `iota_events_processed_total{log_type="AWS.CloudTrail"}` after traffic.
- [x] **Rule evaluation volume**: `iota_rules_evaluated_total{rule_id,result}` (`result` = `match` | `no_match`) from engine batch aggregates.
- [x] **State DB**: `iota_statedb_operations_total` and `iota_statedb_operation_duration_seconds` for dedup + pipeline state SQLite ops.
- [x] **Slack**: `iota_alerts_forwarded_total{output_type="slack",status="success|failure"}`; failures also surface as forwarder errors in logs.

## Product / positioning

- [ ] **Value proposition**: “Fast SIEM” must be split into **(1) AWS log delivery delay**, **(2) queue + poll latency**, **(3) parse + detect CPU**. iota mainly affects (2)–(3); (1) is fixed by CloudTrail’s design unless you add supplementary APIs (e.g. `LookupEvents` consumers), which is a different architecture.
