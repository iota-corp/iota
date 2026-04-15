# iota Architecture

> **Contributors:** Start with **[CLAUDE.md](../CLAUDE.md)** and **[DEVELOPMENT.md](DEVELOPMENT.md)** for workflow, OpenSpec, testing, and how **iota**, **iota-deployments**, and **iota-infra** fit together. This document is the **system design reference** (diagrams and component detail).

## Overview

iota is a self-hosted security detection engine with enterprise-grade architecture. It runs entirely within your AWS account, consuming CloudTrail, Okta, Google Workspace, and 1Password logs. All detection logic runs locally. No data leaves your control boundary.

iota supports these ingestion modes:

| Mode flag | Typical source | When to use |
|-----------|----------------|-------------|
| **`eventbridge`** | **CloudTrail** on the default event bus → rule → SQS, or **SaaS** partner buses → SQS | **Default for CloudTrail API detections:** lower end-to-end latency (seconds vs multi-minute log file delivery). |
| **`eventbridge`** | Okta, 1Password, Sailpoint | Partner EventBridge integrations → SQS (same processor path as CloudTrail EventBridge). |
| **`sqs`** | S3 object notifications → SQS (bucket/key) | **Cost-saving / batched:** CloudTrail **`.json.gz`** files in S3; higher latency, fewer per-API downstream events than a broad EventBridge rule. |

**Performance (CloudTrail):** **`eventbridge`** processes **small JSON** messages (often one API call per envelope) — OpenTelemetry spans such as **`process_eventbridge_event`**; CPU is mostly **rules engine**. **`sqs`** downloads **large gzip files**, decompresses, parses **many records** per object — spans such as **`process_s3_object`**, **`s3.GetObject`**, **`logprocessor.Process`**.

## System Architecture

### Mode A: EventBridge → SQS (CloudTrail API events — recommended default)

CloudTrail emits **`AWS API Call via CloudTrail`** on the **account default event bus**. An EventBridge rule (correctly matched on `detail-type`, and typically **not** restricted to `source: aws.cloudtrail` alone) forwards events to SQS. iota **`--mode=eventbridge`** consumes messages and unwraps envelopes; **no S3 GetObject** for that ingestion path.

See **[README.md — how it works](../README.md#how-it-works)** for the performance tradeoff vs S3 file delivery.

### Mode 1: SQS Mode (S3-based logs)

```
┌─────────────────────────────────────────────────────────────┐
│  AWS CloudTrail (Organization Trail)                        │
│  • S3 bucket: CloudTrail logs                               │
│  • Writes .json.gz files every ~5 minutes                   │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  Ingestion: Event-Driven (SNS/SQS)                          │
│  • S3 bucket notifications → SNS Topic                      │
│  • SNS Topic → SQS Queue (with DLQ)                         │
│  • SQS Queue → iota SQS Processor                           │
│  • Downloads .json.gz files from S3                         │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  Log Processor (internal/logprocessor)                      │
│  • Downloads and decompresses .json.gz files              │
│  • Adaptive classifier with penalty-based priority queue  │
│  • Supports CloudTrail, S3, VPC Flow, ALB, Aurora MySQL │
│  • Parses and normalizes events by log type              │
│  • Adds event metadata (EventTime, ParseTime, RowID)       │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  Data Lake Writer (internal/datalake)                      │
│  • Buffers processed events                                │
│  • Writes to S3 with hourly partitioning                   │
│  • Format: logs/{table}/year={Y}/month={M}/day={D}/hour={H}│
│  • Compressed JSON (.json.gz)                              │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  Rules Engine (internal/engine)                             │
│  • Executes Python detection rules                         │
│  • Processes events in batches                             │
│  • Returns rule matches                                    │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  Alert Deduplication (internal/deduplication)              │
│  • SQLite-based deduplication                             │
│  • Groups alerts by rule_id + dedup_string                 │
│  • Tracks alert count and timestamps                       │
│  • Configurable dedup period (default: 60 minutes)         │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  Alert Forwarder (internal/alertforwarder)                 │
│  • Processes deduplicated alerts                           │
│  • Enriches with alert metadata                            │
│  • Routes to configured outputs                            │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  Alert Delivery (internal/alerts)                           │
│  • Slack webhook                                            │
│  • JSON stdout (for piping to other tools)                 │
│  • Extensible output interface                             │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  Health Check Server (internal/api)                         │
│  • HTTP server on port 8080                                │
│  • /health endpoint (liveness probe)                       │
│  • /ready endpoint (readiness probe)                       │
└─────────────────────────────────────────────────────────────┘
```

### Mode 2: EventBridge Mode (Streaming SaaS logs — partner buses)

```
┌─────────────────────────────────────────────────────────────┐
│  SaaS Providers (Okta, 1Password, Sailpoint)                │
│  • Events sent via EventBridge Partner Integration          │
│  • Real-time streaming (no S3 intermediary)                │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  EventBridge Partner Event Bus                              │
│  • aws.partner/okta.com/{org}/...                          │
│  • aws.partner/1password.com/...                           │
│  • aws.partner/sailpoint.com/...                           │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  EventBridge Rule → SQS Queue                               │
│  • Routes events to SQS (no SNS needed)                    │
│  • EventBridge envelope preserved in message               │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  iota EventBridge Processor (internal/events)               │
│  • Receives SQS messages directly                          │
│  • Unwraps EventBridge envelope                            │
│  • Detects log type from source/detail-type               │
│  • No S3 download needed                                   │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
        (continues to Log Processor → Rules Engine → Alerts)
```

## Components

### 1. Log Processor (internal/logprocessor)

Processes raw logs and classifies them using an adaptive classifier.

**Adaptive Classification System**:
- Uses penalty-based priority queue to identify log types
- Parsers that fail receive a penalty, reducing priority for future classifications
- Supports multiple log types: CloudTrail, S3 Server Access, VPC Flow, ALB, Aurora MySQL Audit
- Handles both CloudTrail JSON files (with `Records` array) and line-delimited logs
- Adds event metadata (EventTime, ParseTime, RowID)
- Normalizes event structure

**Supported Log Types**:

AWS Logs (S3-based, SQS mode):
- `AWS.CloudTrail`: CloudTrail API audit logs (JSON format)
- `AWS.S3ServerAccess`: S3 server access logs (CSV format)
- `AWS.VPCFlow`: VPC Flow Logs (CSV format)
- `AWS.ALB`: Application Load Balancer access logs (CSV format)
- `AWS.AuroraMySQLAudit`: Aurora MySQL audit logs (CSV format)

SaaS Logs (EventBridge mode):
- `Okta.SystemLog`: Okta authentication and admin events (JSON)
- `GSuite.Reports`: Google Workspace activity reports (JSON)
- `OnePassword.SignInAttempt`: 1Password sign-in events (JSON)

**Key Types**:
```go
type Processor struct {
    adaptiveClassifier *AdaptiveClassifier
}

type ProcessedEvent struct {
    Event           *cloudtrail.Event
    LogType         string
    EventTime       time.Time
    ParseTime       time.Time
    RowID           string
}

type AdaptiveClassifier struct {
    parsers     *ParserPriorityQueue
    stats       ClassifierStats
    parserStats map[string]*ParserStats
}

type ParserPriorityQueue struct {
    items []*ParserQueueItem
}

type ParserQueueItem struct {
    logType string
    parser  parsers.ParserInterface
    penalty int
    index   int
}
```

**Usage**:
```go
processor := logprocessor.New()
events, errs := processor.Process(ctx, reader)
for event := range events {
    // Processed event with classification
}
```

**How Adaptive Classification Works**:
1. All parsers start with penalty=1 in a min-heap priority queue
2. For each log line, the classifier tries parsers in priority order (lowest penalty first)
3. If a parser fails, it receives penalty+1 and is moved down in the queue
4. If a parser succeeds, its penalty is reset to 0 and it moves to the front
5. This ensures frequently-used parsers are tried first, improving performance

### 2. Data Lake Writer (internal/datalake)

Writes processed events to S3 with partitioning for efficient querying.

**Features**:
- Hourly partitioning (year/month/day/hour)
- Buffered writes (50MB or 1 minute)
- GZIP compression
- S3 key format: `logs/{table}/year={Y}/month={M}/day={D}/hour={H}/{timestamp}-{uuid}.json.gz`

**Key Types**:
```go
type Writer struct {
    s3Client *s3.Client
    bucket   string
    buffer   *EventBuffer
}

func (w *Writer) WriteEvent(ctx context.Context, event *logprocessor.ProcessedEvent) error
func (w *Writer) Flush(ctx context.Context) error
```

**Usage**:
```go
writer := datalake.New(s3Client, "processed-data-bucket", 50*1024*1024, time.Minute)
defer writer.Flush(ctx)

for event := range processedEvents {
    writer.WriteEvent(ctx, event)
}
```

### 3. Alert Deduplication (internal/deduplication)

Deduplicates alerts using SQLite to prevent alert fatigue.

**Features**:
- Groups alerts by `rule_id` + `dedup_string`
- Tracks alert count and creation/update times
- Configurable dedup period (default: 60 minutes)
- Generates unique alert IDs

**Key Types**:
```go
type Deduplicator struct {
    db *sql.DB
}

type AlertInfo struct {
    AlertID           string
    RuleID            string
    DedupKey          string
    AlertCreationTime time.Time
    AlertUpdateTime   time.Time
    ResolvedAt        *time.Time
    Title             string
    Severity         string
}

func (d *Deduplicator) UpdateAlertInfo(ctx context.Context, ruleID, dedup, title, severity string, dedupPeriodMinutes int) (*AlertInfo, error)
```

**Usage**:
```go
dedup, err := deduplication.New("alerts.db")
alertInfo, err := dedup.UpdateAlertInfo(ctx, ruleID, dedupString, title, severity, 60)
```

### 4. Alert Forwarder (internal/alertforwarder)

Processes rule matches and forwards them to configured outputs.

**Features**:
- Integrates with deduplication system
- Enriches alerts with context
- Supports multiple output destinations
- Extensible output interface

**Key Types**:
```go
type Forwarder struct {
    deduplicator *deduplication.Deduplicator
    outputs      []Output
}

type Output interface {
    SendAlert(ctx context.Context, alert *Alert) error
}

type Alert struct {
    AlertID          string
    RuleID           string
    Title            string
    Severity         string
    Event            *cloudtrail.Event
    AlertContext      map[string]interface{}
    AlertCreationTime string
    AlertUpdateTime   string
    DedupKey          string
}
```

**Usage**:
```go
outputs := []alertforwarder.Output{
    alerts.NewSlackOutput(webhookURL),
}
forwarder := alertforwarder.New(deduplicator, outputs)
forwarder.ProcessMatch(ctx, match, 60)
```

### 5. Integration Management (internal/integration)

Manages CloudTrail source integrations.

**Features**:
- Tracks integration configurations
- Monitors last event time
- Tracks event status (ACTIVE, INACTIVE)
- SQLite-based storage

**Key Types**:
```go
type Integration struct {
    ID             string
    Type           string
    Label          string
    AWSAccountID   string
    S3Bucket       string
    S3Prefix      string
    Enabled        bool
    CreatedAt      time.Time
    LastEventTime *time.Time
    EventStatus    string
}

type Manager struct {
    db *sql.DB
}
```

**Usage**:
```go
manager, err := integration.NewManager("integrations.db")
integration := &integration.Integration{
    ID: "integration-1",
    Type: "aws-s3",
    Label: "Production CloudTrail",
    S3Bucket: "cloudtrail-logs",
    S3Prefix: "AWSLogs/",
}
manager.Create(ctx, integration)
```

### 6. Detection Engine (internal/engine)

Orchestrates Python rule execution via subprocess.

**Implementation**:
- Spawns Python subprocess for each batch
- Sends JSON request via stdin
- Receives JSON response via stdout
- Captures stderr for debugging
- Uses context for timeout

**Key Types**:
```go
type Engine struct {
    pythonPath string
    enginePath string
    rulesDir   string
}

type Match struct {
    RuleID   string
    Title    string
    Severity string
    Dedup    string
    Event    *cloudtrail.Event
}
```

### 7. SQS Processor (internal/events)

Processes SQS messages containing S3 event notifications (for S3-based logs).

**Features**:
- Long polling (20 seconds) for efficient message retrieval
- Parses SNS messages containing S3 notifications
- Downloads CloudTrail log files from S3
- Automatic message deletion after successful processing
- Dead letter queue support for failed messages

**Key Types**:
```go
type SQSProcessor struct {
    client      *sqs.Client
    queueURL    string
    handler     func(ctx context.Context, s3Bucket, s3Key string) error
    maxMessages int32
    waitTime    int32
}
```

### 8. EventBridge Processor (internal/events)

Processes EventBridge events directly from SQS (for streaming SaaS logs).

**Features**:
- Receives events directly from SQS (no S3 download)
- Unwraps EventBridge envelope to extract log payload
- Detects log type from EventBridge source/detail-type
- Handles batched events (multiple events per message)
- Long polling for efficient message retrieval

**EventBridge Envelope Detection**:
```go
// Detects log type from EventBridge envelope
func DetectEventSource(envelope *EventBridgeEnvelope) string {
    // Okta: aws.partner/okta.com → Okta.SystemLog
    // 1Password: aws.partner/1password.com → OnePassword.SignInAttempt
    // Sailpoint: aws.partner/sailpoint.com → Sailpoint.Event
    // GSuite: google.workspace → GSuite.Reports
}
```

**Key Types**:
```go
type EventBridgeEnvelope struct {
    Version    string          `json:"version"`
    ID         string          `json:"id"`
    DetailType string          `json:"detail-type"`
    Source     string          `json:"source"`
    Account    string          `json:"account"`
    Time       time.Time       `json:"time"`
    Region     string          `json:"region"`
    Detail     json.RawMessage `json:"detail"`  // The actual log event
}

type EventBridgeProcessor struct {
    client      *sqs.Client
    queueURL    string
    handler     EventHandler
    maxMessages int32
    waitTime    int32
}

type EventHandler func(ctx context.Context, eventJSON []byte, logType string, envelope *EventBridgeEnvelope) error
```

**Usage**:
```go
// EventBridge mode processes events directly (no S3 download)
processor := events.NewEventBridgeProcessor(sqsClient, events.EventBridgeConfig{
    QueueURL: "https://sqs.../okta-events-iota",
    Handler: func(ctx context.Context, eventJSON []byte, logType string, envelope *EventBridgeEnvelope) error {
        // logType = "Okta.SystemLog" (auto-detected from envelope)
        // eventJSON = raw Okta event (unwrapped from envelope)
        return processEvent(ctx, eventJSON, logType)
    },
})
```

### 9. Health Check Server (internal/api)

Provides HTTP endpoints for Kubernetes health checks.

**Features**:
- `/health` endpoint for liveness probes
- `/ready` endpoint for readiness probes
- Graceful shutdown on context cancellation
- Configurable port (default: 8080)

**Key Types**:
```go
type HealthServer struct {
    server *http.Server
}

func NewHealthServer(port string) *HealthServer
func (s *HealthServer) Start(ctx context.Context) error
```

## Data Flow

### SQS Mode Pipeline (S3-based logs)

1. **S3 Notifications**: CloudTrail writes logs to S3, triggering bucket notifications
2. **SNS Topic**: S3 notifications published to SNS topic
3. **SQS Queue**: SNS messages delivered to SQS queue (with DLQ for failures)
4. **SQS Processing**: iota receives SQS messages and extracts S3 bucket/key
5. **Download**: Downloads `.json.gz` files from S3
6. **Log Processing**: Decompresses and parses log files
7. **Adaptive Classification**: Uses penalty-based priority queue to identify log type
8. **Parsing**: Parses events according to identified log type
9. **Data Lake**: Writes processed events to S3 with partitioning (optional)
10. **Rules Engine**: Executes Python detection rules
11. **Deduplication**: Checks for existing alerts within dedup period
12. **Alert Forwarding**: Routes alerts to configured outputs
13. **Delivery**: Sends alerts to Slack, stdout, or other destinations
14. **Health Checks**: HTTP endpoints available for Kubernetes probes

### EventBridge Mode Pipeline (Streaming SaaS logs)

1. **SaaS Provider**: Okta/1Password/Sailpoint sends events to EventBridge
2. **EventBridge Partner Bus**: Receives events from SaaS provider
3. **EventBridge Rule**: Routes events to SQS queue
4. **SQS Queue**: Events delivered to iota queue (no SNS needed)
5. **EventBridge Processing**: iota receives SQS messages directly
6. **Envelope Unwrapping**: Extracts log payload from EventBridge envelope
7. **Log Type Detection**: Identifies log type from envelope source/detail-type
8. **Adaptive Classification**: Uses hinted parser based on detected log type
9. **Parsing**: Parses events according to identified log type
10. **Data Lake**: Writes processed events to S3 with partitioning (optional)
11. **Rules Engine**: Executes Python detection rules
12. **Deduplication**: Checks for existing alerts within dedup period
13. **Alert Forwarding**: Routes alerts to configured outputs
14. **Delivery**: Sends alerts to Slack, stdout, or other destinations
15. **Health Checks**: HTTP endpoints available for Kubernetes probes

## Deployment Model

iota is self-hosted and runs in your AWS environment:

**Compute**: EKS pod, ECS task, Fargate container, or EC2 instance

**Permissions**: IAM role with:

For SQS mode (S3-based logs):
- S3 read access to CloudTrail bucket
- SQS receive/delete message permissions
- KMS decrypt permissions for encrypted logs

For EventBridge mode (SaaS logs):
- SQS receive/delete message permissions (no S3 access needed)

**Network**: VPC with optional egress to alert destinations

**Storage**:
- SQLite databases for state and deduplication
- S3 bucket for processed data lake (optional)

**Infrastructure**: Terraform module for:
- SQS queues (CloudTrail and/or EventBridge sources)
- IAM roles and policies
- SNS subscriptions (for S3 notifications)
- EventBridge rules (for SaaS log routing)

**Health Monitoring**: HTTP endpoints on port 8080 for Kubernetes probes

## Security Boundaries

- Logs never leave your AWS account
- No network calls to external services (unless you configure alerts)
- Python rules run in isolated subprocess
- Read-only access to CloudTrail S3 bucket
- IAM role-based authentication (no stored credentials)
- All iota operations logged via CloudTrail

## Performance Characteristics

**Processing**:
- 10,000-50,000 events/second per instance
- <100ms latency per event
- <500MB memory footprint

**Scalability**:
- Horizontal scaling via multiple replicas
- State databases can be shared via ReadWriteMany volumes
- S3 data lake scales automatically

**Tested With**:
- 100GB+ daily CloudTrail volume
- 50+ concurrent rules
- Real AWS CloudTrail logs from production environments

## Design Decisions

- **Event-Driven**: SNS/SQS for real-time processing with sub-minute latency
- **Adaptive Classifier**: Penalty-based priority queue for efficient multi-log source support
- **SQLite**: Simple state management without additional AWS services
- **Self-Hosted**: Full control, no vendor lock-in, no per-GB costs
- **CLI-Only**: Integrates with existing tooling, no frontend complexity
- **Health Checks**: HTTP endpoints for Kubernetes liveness/readiness probes
- **Terraform Module**: Infrastructure as code for SQS, IAM, and SNS setup

## Implemented Features

- ✅ **EventBridge Integration**: Real-time processing of Okta, 1Password, and Sailpoint logs
- ✅ **SaaS Log Parsers**: Okta.SystemLog, GSuite.Reports, OnePassword.SignInAttempt
- ✅ **Glue Catalog Integration**: Automatic table creation and partition management
- ✅ **Cross-Account Support**: IAM role assumption for multi-account setups
- ✅ **State Tracking**: Resume processing from last processed key per bucket/account/region
- ✅ **Bloom Filter Deduplication**: Cross-trail deduplication for duplicate events
- ✅ **Health Monitoring**: HTTP endpoints for Kubernetes probes, Prometheus metrics
- ✅ **Detection Rules**: 50+ rules across CloudTrail, Okta, GSuite, and 1Password

## Future Enhancements

- **Athena Queries**: Query processed data lake via Athena (schema defined, queries pending)
- **Multiple Outputs**: PagerDuty, webhooks, custom integrations
- **CloudWatch Metrics**: Push metrics to CloudWatch for dashboards
- **Parallel Processing**: Configurable worker pools for concurrent log processing
- **S3 Delimiter Discovery**: Efficient S3 key discovery for large buckets
- **Additional Log Sources**: GuardDuty, CloudWatch Logs, WAF logs
- **Correlation Engine**: Time-windowed event correlation across log types
- **Kinesis Firehose Integration**: Long-term storage path alongside real-time detection

## References

- AWS CloudTrail Log Format: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html
- iota Repository: https://github.com/bilals12/iota
