---
version: 1.0.0
status: active
owner: bilals12
---

# Capability: Log Processing

Adaptive log classification and parsing for multiple log sources.

## Requirements

### Requirement: Adaptive Classification

The system SHALL automatically identify log types using a penalty-based priority queue.

#### Scenario: Successful classification

- **GIVEN** an unknown log line
- **WHEN** the adaptive classifier processes it
- **THEN** it SHALL try parsers in priority order
- **AND** return the first successful parse result
- **AND** promote that parser's priority

#### Scenario: Failed classification attempt

- **GIVEN** a parser that fails to parse the log line
- **WHEN** classification is attempted
- **THEN** that parser SHALL receive a penalty
- **AND** its priority SHALL decrease for future attempts

#### Scenario: Classification with hint

- **GIVEN** a log line with known type hint (e.g., from EventBridge metadata)
- **WHEN** `ClassifyWithHint(line, hint)` is called
- **THEN** the hinted parser SHALL be tried first

### Requirement: CloudTrail Parsing

The system SHALL parse AWS CloudTrail JSON logs.

#### Scenario: CloudTrail file with Records array

- **GIVEN** a JSON file with `{"Records": [...]}`
- **WHEN** the file is processed
- **THEN** each record SHALL be parsed as a CloudTrail event
- **AND** `eventID`, `eventTime`, `eventName` SHALL be extracted

#### Scenario: CloudTrail JSONL format

- **GIVEN** a JSONL file with one event per line
- **WHEN** the file is processed
- **THEN** each line SHALL be parsed independently

### Requirement: VPC Flow Log Parsing

The system SHALL parse AWS VPC Flow Logs in space-delimited format.

#### Scenario: VPC Flow Log v2

- **GIVEN** a VPC Flow Log line
- **WHEN** parsed
- **THEN** fields SHALL be extracted: `srcaddr`, `dstaddr`, `srcport`, `dstport`, `protocol`, `action`

### Requirement: ALB Log Parsing

The system SHALL parse AWS Application Load Balancer logs.

#### Scenario: ALB access log

- **GIVEN** an ALB access log line
- **WHEN** parsed
- **THEN** fields SHALL include: `client_ip`, `target_ip`, `request_url`, `user_agent`, `elb_status_code`

### Requirement: Bedrock model invocation log parsing

The system SHALL parse AWS Bedrock model invocation logs delivered as JSON (`schemaType` `ModelInvocationLog`).

#### Scenario: ModelInvocationLog line

- **GIVEN** a JSON object with `schemaType` `ModelInvocationLog`, `requestId`, and `operation`
- **WHEN** parsed
- **THEN** log type SHALL be `AWS.BedrockModelInvocation`
- **AND** the normalized event SHALL use `eventSource` `aws.bedrock.modelinvocation` with the full object available to rules via `requestParameters` (unwrapped for Python evaluation)

### Requirement: GitHub audit log parsing

The system SHALL parse GitHub audit log events as JSON (explicit `p_log_type` `GitHub.Audit` or audit-like objects with `action`, `created_at`, and no top-level `repository` object).

#### Scenario: GitHub.Audit line

- **GIVEN** a JSON object classified as `GitHub.Audit` with `action` and timing fields
- **WHEN** parsed
- **THEN** log type SHALL be `GitHub.Audit`
- **AND** the normalized event SHALL use `eventSource` `github.com` with the full object in `requestParameters` (unwrapped for Python evaluation)

### Requirement: GitHub webhook payload parsing

The system SHALL parse GitHub webhook delivery payloads (explicit `p_log_type` `GitHub.Webhook` with `repository`, or payloads with `repository` plus `sender`, `pusher`, `workflow_run`, or `pull_request`).

#### Scenario: GitHub.Webhook line

- **GIVEN** a JSON object classified as `GitHub.Webhook` with `action` and `repository`
- **WHEN** parsed
- **THEN** log type SHALL be `GitHub.Webhook`
- **AND** the normalized event SHALL use `eventSource` `github.com.webhook` with the full object in `requestParameters` (unwrapped for Python evaluation)

### Requirement: GCP Cloud Audit log parsing

The system SHALL parse Google Cloud Audit logs (`GCP.AuditLog`) as JSON: explicit `p_log_type`, `protoPayload` (or `protopayload`) with `methodName` / `serviceName`, `logName` containing `cloudaudit.googleapis.com`, or a top-level `methodName` for minimal test shapes.

#### Scenario: GCP.AuditLog line

- **GIVEN** a JSON object classified as `GCP.AuditLog`
- **WHEN** parsed
- **THEN** log type SHALL be `GCP.AuditLog`
- **AND** the normalized event SHALL use `eventSource` `cloudaudit.googleapis.com` with the full object in `requestParameters` (unwrapped for Python evaluation)

### Requirement: GCP HTTP(S) load balancer log parsing

The system SHALL parse HTTP(S) load balancer request logs (`GCP.HTTPLoadBalancer`) as JSON: explicit `p_log_type`, or an `httpRequest` together with `resource.type` `http_load_balancer`, or `logName` containing `/logs/requests`.

#### Scenario: GCP.HTTPLoadBalancer line

- **GIVEN** a JSON object classified as `GCP.HTTPLoadBalancer`
- **WHEN** parsed
- **THEN** log type SHALL be `GCP.HTTPLoadBalancer`
- **AND** the normalized event SHALL use `eventSource` `loadbalancing.googleapis.com` with the full object in `requestParameters` (unwrapped for Python evaluation)

### Requirement: Amazon EKS Kubernetes audit log parsing

The system SHALL parse native Kubernetes audit API objects (`kind` `Event`, `apiVersion` containing `audit.k8s.io`) as `Amazon.EKS.Audit`, including lines tagged with `p_log_type` `Amazon.EKS.Audit`.

#### Scenario: Amazon.EKS.Audit line

- **GIVEN** a JSON object classified as `Amazon.EKS.Audit`
- **WHEN** parsed
- **THEN** log type SHALL be `Amazon.EKS.Audit`
- **AND** the normalized event SHALL use `eventSource` `eks.amazonaws.com` with the full audit object in `requestParameters` (unwrapped for Python evaluation)

### Requirement: Kubernetes audit file tail (on-cluster)

The iota binary SHALL support a run mode that reads newline-delimited Kubernetes audit JSON from a local file (e.g. k3s `audit.log`), advancing a persistent cursor in the state database across restarts.

#### Scenario: audit-tail mode

- **GIVEN** `--mode=audit-tail` and a readable `--audit-log` path
- **WHEN** new complete lines are appended to the file
- **THEN** each line SHALL be classified like other JSONL sources
- **AND** lines matching `Amazon.EKS.Audit` SHALL be evaluated by the rule engine and MAY emit Slack alerts like other long-running modes

Homelab Kubernetes manifests for this mode live in the **`iota-deployments`** repo (`clusters/homelab-k3s-audit`), not under **`iota/deployments/kubernetes`**.

### Requirement: Slack audit log parsing

The system SHALL parse Slack audit log JSON objects as `Slack.AuditLogs` when `p_log_type` indicates Slack audit, or when `action`, `actor`, and `date_create` are present (canonical export shape).

#### Scenario: Slack.AuditLogs line

- **GIVEN** a JSON object classified as `Slack.AuditLogs`
- **WHEN** parsed
- **THEN** log type SHALL be `Slack.AuditLogs`
- **AND** the normalized event SHALL use `eventSource` `slack.com` with the full object in `requestParameters` (unwrapped for Python evaluation)

### Requirement: Cloudflare Firewall event parsing

The system SHALL parse Cloudflare firewall / WAF JSON lines as `Cloudflare.Firewall` when `Kind` is `firewall` or `p_log_type` is `Cloudflare.Firewall`.

#### Scenario: Cloudflare.Firewall line

- **GIVEN** a JSON object classified as `Cloudflare.Firewall`
- **WHEN** parsed
- **THEN** log type SHALL be `Cloudflare.Firewall`
- **AND** the normalized event SHALL use `eventSource` `cloudflare.com.firewall` with the full object in `requestParameters` (unwrapped for Python evaluation)

### Requirement: Cloudflare HTTP request log parsing

The system SHALL parse Cloudflare HTTP request (Logpush) JSON as `Cloudflare.HttpRequest` when `p_log_type` is `Cloudflare.HttpRequest`, or when `EdgeStartTimestamp` or `BotScore` is present and the line is not a firewall event.

#### Scenario: Cloudflare.HttpRequest line

- **GIVEN** a JSON object classified as `Cloudflare.HttpRequest`
- **WHEN** parsed
- **THEN** log type SHALL be `Cloudflare.HttpRequest`
- **AND** the normalized event SHALL use `eventSource` `cloudflare.com.http_request` with the full object in `requestParameters` (unwrapped for Python evaluation)

### Requirement: EventBridge Envelope Unwrapping

The system SHALL extract log payloads from EventBridge envelopes.

#### Scenario: Okta event via EventBridge

- **GIVEN** an EventBridge message with `source: "aws.partner/okta.com"`
- **WHEN** processed
- **THEN** the `detail` field SHALL be extracted as the Okta event
- **AND** log type SHALL be set to `Okta.SystemLog`

#### Scenario: 1Password event via EventBridge

- **GIVEN** an EventBridge message with `detail-type: "1Password SignInAttempt"`
- **WHEN** processed
- **THEN** the `detail` field SHALL be extracted
- **AND** log type SHALL be set to `OnePassword.SignInAttempt`

### Requirement: Supported Log Types

The system SHALL support the following log types:

| Log Type | Format | Source |
|----------|--------|--------|
| GitHub.Audit | JSON | S3 / API / queue (deployment-specific) |
| GitHub.Webhook | JSON | S3 / API / queue (deployment-specific) |
| GCP.AuditLog | JSON | GCS / Pub/Sub / BigQuery export (deployment-specific) |
| GCP.HTTPLoadBalancer | JSON | GCS / Pub/Sub (deployment-specific) |
| Amazon.EKS.Audit | JSON | S3 (EKS control plane audit); on-node audit log file (`audit-tail` mode) |
| Slack.AuditLogs | JSON | API export / SIEM delivery (deployment-specific) |
| Cloudflare.Firewall | JSON | Logpush / SIEM (deployment-specific) |
| Cloudflare.HttpRequest | JSON | Logpush (deployment-specific; high volume) |
| AWS.BedrockModelInvocation | JSON | S3 |
| AWS.CloudTrail | JSON | S3 |
| AWS.VPCFlow | Space-delimited | S3 |
| AWS.ALB | Space-delimited | S3 |
| AWS.S3ServerAccess | Space-delimited | S3 |
| AWS.AuroraMySQLAudit | CSV | S3 |
| Okta.SystemLog | JSON | EventBridge |
| GSuite.Reports | JSON | EventBridge |
| OnePassword.SignInAttempt | JSON | EventBridge |

### Requirement: Extended sources (parity track)

The system SHALL document and implement parsers for additional log types aligned with the mirrored analysis rules tree under `redteamtools`, subject to separate change proposals. Target types include:

| Log Type | Format (expected) | Ingestion mode (typical) |
|----------|-------------------|---------------------------|
| Azure.MonitorActivity | JSON | Azure Monitor / export (TBD per deployment) |

#### Scenario: Normalized envelope for a new type

- **GIVEN** a supported extended-source log line
- **WHEN** parsed
- **THEN** it SHALL be represented as `cloudtrail.Event` with a stable `eventSource` discriminator
- **AND** vendor-specific fields SHALL appear in `RequestParameters` (or agreed fields) so Python rules can use the same unwrap pattern as Okta/GSuite

#### Scenario: Classifier registration

- **GIVEN** a new parser for an extended type
- **WHEN** the classifier is configured
- **THEN** it SHALL expose `LogType()` matching the table above
- **AND** it SHALL participate in adaptive classification like existing parsers

## Current Implementation

- **Location**: `internal/logprocessor/`, `internal/classifier/`
- **Parsers**: `internal/logprocessor/cloudtrail.go`, `internal/logprocessor/vpcflow.go`, etc.
- **Extended sources**: See `openspec/changes/add-extended-source-detections/`
