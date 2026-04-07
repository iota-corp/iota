# Detection pipeline — operations and roadmap checklist

Use this when tuning latency, throughput, or explaining “why is iota idle?” vs other namespaces.

## End-to-end latency (what AWS controls vs iota)

- [ ] **CloudTrail → S3**: AWS batches and delivers log files on a **multi-minute** cadence (often ~5–15 minutes). This dominates “attack-sim waited 600s” style tests; iota cannot shorten CloudTrail’s delivery SLA.
- [ ] **S3 event → SQS → iota**: After an object lands, SQS long polling uses **WaitTimeSeconds** (default **20**). Each receive can wait up to that long when the queue is empty.
- [ ] **Per-object work**: One gzip log file → parse → one Python **engine** subprocess per batch of events. Large rule sets increase CPU time per batch.

## iota throughput (tunables today)

- [x] **`IOTA_SQS_MAX_MESSAGES`**: SQS receive batch size, **1–10** (default **10**). Higher can pull more notifications per poll when the queue is backlogged. Wired in **`runSQS`** / **`runEventBridge`**.
- [x] **`IOTA_SQS_WAIT_SECONDS`**: Long-poll wait, **0–20** (default **20**). Lower reduces worst-case latency when the queue is empty; slightly more API calls. Wired in **`runSQS`** / **`runEventBridge`**.
- [ ] **Deployment CPU/memory**: If the **Python** rule engine is CPU-bound, raising CPU **limit** on the iota container can help. Grafana “Kubernetes / Compute Resources / Namespace” is expected to show **security** as small if traffic is low—that is normal; scale up when processing **lags the queue**.

## Not wired yet (known gaps)

- [ ] **`--download-workers` / `--process-workers`**: Parsed in `main` but **not applied** to SQS mode today; processing is effectively **one S3 object at a time** per goroutine path. Parallel object processing is a future improvement.
- [ ] **Rule evaluation**: Every event is evaluated against **all** loaded rules; shrinking `--rules` to the directories you need reduces CPU.

## Observability

- [x] **Logs**: Each match logs a line
  `detection: rule_id=… severity=… eventSource=… eventName=… title="…"`
  (**SQS** and **EventBridge** paths), followed by `processed N events, M matches …`.
- [x] **Prometheus**: `iota_alerts_generated_total` increments per deduped alert; `iota_events_processed_total{log_type="AWS.CloudTrail"}` after traffic.
- [x] **Slack**: `iota_alerts_forwarded_total{output_type="slack",status="success|failure"}`; failures also surface as forwarder errors in logs.

## Product / positioning

- [ ] **Value proposition**: “Fast SIEM” must be split into **(1) AWS log delivery delay**, **(2) queue + poll latency**, **(3) parse + detect CPU**. iota mainly affects (2)–(3); (1) is fixed by CloudTrail’s design unless you add supplementary APIs (e.g. `LookupEvents` consumers), which is a different architecture.
