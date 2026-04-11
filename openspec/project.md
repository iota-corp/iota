# Project Context

## Purpose

iota is a self-hosted security detection engine that mirrors common cloud SIEM capabilities while maintaining data sovereignty. It runs entirely within your AWS account, consuming CloudTrail, Okta, Google Workspace, 1Password, and (when configured) GCP and GitHub log exports.

## Tech Stack

- **Language**: Go 1.24+ (core engine), Python 3.11+ (detection rules)
- **Database**: SQLite (state tracking, alert deduplication)
- **Infrastructure**: Terraform, Kubernetes (EKS/ECS/Fargate)
- **CI/CD**: GitHub Actions, Docker Hub
- **Observability**: OpenTelemetry, Prometheus metrics
- **Message Queue**: AWS SQS (S3 notifications, EventBridge events)

## Architecture

### Dual-Mode Processing

| Mode | Source | Trigger | Use Case |
|------|--------|---------|----------|
| `sqs` | S3-based logs | S3 → SNS → SQS | CloudTrail, VPC Flow, ALB |
| `eventbridge` | SaaS logs | EventBridge → SQS | Okta, 1Password, Sailpoint |

### Core Components

- **Adaptive Classifier**: Penalty-based priority queue for log type detection
- **Log Processor**: Type-specific parsers (CloudTrail, VPC Flow, ALB, Okta, etc.)
- **Rules Engine**: Python detection rules with severity levels
- **Deduplication**: SQLite + Bloom filter for alert deduplication
- **Transform Pipeline**: Substation-inspired message/condition/transform abstractions

## Project Conventions

### Code Style

- **Go**: Follow standard Go conventions, `gofmt`, `golangci-lint`
- **Python**: Ruff linter, no unused imports
- **Terraform**: Pin provider versions, outputs in `outputs.tf`
- **No Comments**: Avoid unnecessary comments in code
- **DRY**: Follow existing patterns and abstractions

### Detection Rules

Rules are Python files in `rules/{log_type}/`:

```python
def rule(event):
    """Return True if event matches detection logic"""
    return event.get("eventName") == "ConsoleLogin"

def title(event):
    """Return alert title string"""
    return f"Console login from {event.get('sourceIPAddress')}"

def severity(event):
    """Return CRITICAL/HIGH/MEDIUM/LOW/INFO"""
    return "HIGH"
```

### Git Workflow

- **Commit Messages**: Conventional commits (`feat:`, `fix:`, `docs:`, etc.)
- **Branch Naming**: `feature/<change-id>`, `fix/<change-id>`
- **Force Push**: Use `--force-with-lease`

## Domain Context

### Log Sources Supported

**AWS (S3-based)**:
- AWS.BedrockModelInvocation - Model invocation logs (JSON lines, `schemaType` ModelInvocationLog)
- Amazon.EKS.Audit - Kubernetes API audit events (`audit.k8s.io/v1` JSON)
- AWS.CloudTrail - API audit logs
- AWS.S3ServerAccess - S3 access logs
- AWS.VPCFlow - Network flow logs
- AWS.ALB - Load balancer access logs
- AWS.AuroraMySQLAudit - Database audit logs

**GCP (exports / GCS / Pub/Sub — deployment-specific)**:
- GCP.AuditLog - Admin Activity / Data Access audit JSON
- GCP.HTTPLoadBalancer - HTTP(S) LB request logs (incl. Cloud Armor fields in `jsonPayload`)

**SaaS (EventBridge)**:
- Okta.SystemLog - Authentication and admin events
- GSuite.Reports - Google Workspace activity
- OnePassword.SignInAttempt - Sign-in events

**SaaS / edge (export or Logpush — deployment-specific)**:
- Slack.AuditLogs - Workspace audit API exports
- Cloudflare.Firewall / Cloudflare.HttpRequest - Logpush JSON (HTTP logs are typically high volume)

### Detection Coverage

254 production rules (Python under `rules/`, excluding `helpers`) covering:
- CloudTrail and related AWS (IAM, EC2, S3, Lambda, Bedrock model invocation, etc.)
- GCP audit logs, GKE-related audit detections, and HTTP(S) load balancer / Cloud Armor
- Unified Kubernetes (EKS audit + GKE k8s.io audit) under `rules/kubernetes`
- GitHub audit and webhook
- Okta system log
- Google Workspace
- 1Password sign-in

Additional upstream rules from optional mirrors are ported selectively. Log types not yet ingested (e.g. Azure Monitor k8s audit), query-backed baselines, and upstream-only correlation packs are tracked in OpenSpec under `openspec/changes/`.

### Multi-source deployments

The Python subprocess loads every `*.py` rule under the `--rules` directory. For lower CPU cost at scale, run separate workloads or images with `--rules` set to one pack (e.g. `rules/slack_audit`) or a symlinked aggregate, rather than the full tree. Rules that use sliding windows or first-seen keys read state from `IOTA_CORRELATION_STATE` (default `~/.cache/iota/correlation.sqlite`); set `IOTA_CORRELATION=0` only for debugging. Correlation state must persist on disk for the pod if those rules are enabled.

### Performance Characteristics

Tested with real CloudTrail logs:
- **Throughput**: ~13-16K events/sec
- **Memory**: Handles 2.6GB JSON files
- **Latency**: ~5-6 min end-to-end (bounded by CloudTrail delivery)

## Important Constraints

- **Data Sovereignty**: Logs never leave customer AWS account
- **No Telemetry**: No phone-home behavior
- **Python Subprocess**: Rules run in isolated Python process
- **IAM Roles**: No credential storage, uses IRSA
