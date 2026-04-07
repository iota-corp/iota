# iota

<div align="center">

![iota logo](docs/assets/iotaBlack.png)

<sub>art by [fdkubba](https://www.faisalkubba.com/reels)</sub>

**self-hosted security detection engine**

runs entirely within your aws account. consumes cloudtrail, okta, google workspace, and 1password logs. applies detection logic locally, emits alerts to your existing tooling. no telemetry exfiltration.

</div>

## why iota?

stuck with legacy siems that can't keep up? tired of paying per-gb for detection-as-a-service? need full control over your security detections?

iota gives you:

- **data sovereignty**: logs never leave your control boundary
- **auditability**: open source, verify no phone-home behavior
- **customization**: modify detection rules without vendor release cycles
- **simplicity**: fork, deploy to your infra, point at your logs

## how it works

### cloudtrail mode (s3-based)

```
cloudtrail (s3) → s3 notifications → sns topic → sqs queue → iota processor → adaptive classifier → log processor → data lake (s3) → rules engine → deduplication → alert forwarder → alerts
```

### eventbridge mode (real-time saas logs)

```
okta/1password/sailpoint → eventbridge partner bus → sqs queue → iota processor → adaptive classifier → log processor → data lake (s3) → rules engine → deduplication → alert forwarder → alerts
```

**cloudtrail mode** (file-based):

1. **cloudtrail** writes logs to s3 bucket
2. **s3 notifications** trigger sns topic on new object creation
3. **sns → sqs** delivers notifications to sqs queue
4. **iota sqs processor** receives notifications and downloads log files
5. **adaptive classifier** uses penalty-based priority queue to identify log type
6. **log processor** parses and normalizes events by log type
7. **data lake** stores processed events in s3 with partitioning (optional)
8. **rules engine** executes python detection rules
9. **deduplication** prevents alert fatigue
10. **alert forwarder** routes alerts to slack, stdout, or other outputs

**eventbridge mode** (streaming):

1. **saas provider** (okta, 1password, sailpoint) sends events to eventbridge partner bus
2. **eventbridge rule** routes events to sqs queue
3. **iota eventbridge processor** receives events directly (no s3 download)
4. **envelope unwrapper** extracts log payload from eventbridge envelope
5. **adaptive classifier** identifies log type from envelope metadata
6. **log processor** parses and normalizes events
7. steps 7-10 same as cloudtrail mode

## quick start

### prerequisites

- go 1.24+
- python 3.11+
- aws credentials with cloudtrail s3 read access

### installation

```bash
# clone repo
git clone https://github.com/bilals12/iota.git
cd iota

# build
go build -o bin/iota ./cmd/iota

# test with sample data
./bin/iota \
  --jsonl testdata/events/root-login.jsonl \
  --rules rules/aws_cloudtrail \
  --python python3 \
  --engine engines/iota/engine.py
```

### deployment

iota runs in your aws environment:

**compute**: eks, ecs, fargate, or ec2
**permissions**: s3 read access to cloudtrail bucket, sqs receive/delete messages
**network**: vpc with egress to alert destinations
**storage**: local disk for state database and alert deduplication

The official container image includes bundled rules under `/app/rules` (see the `Dockerfile`). You normally point `--rules` at a subdirectory such as `/app/rules/aws_cloudtrail` or `/app/rules/okta` and do **not** mount a ConfigMap for rules.

example eks deployment (cloudtrail mode):

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: iota-cloudtrail
spec:
  replicas: 2
  template:
    spec:
      serviceAccountName: iota
      containers:
        - name: iota
          image: your-registry/iota:latest
          args:
            - --mode=sqs
            - --sqs-queue-url=$(SQS_QUEUE_URL)
            - --s3-bucket=$(S3_BUCKET)
            - --aws-region=$(AWS_REGION)
            - --rules=/app/rules/aws_cloudtrail
            - --state=/data/state.db
          env:
            - name: SQS_QUEUE_URL
              value: "https://sqs.us-east-1.amazonaws.com/123456789012/iota-cloudtrail-queue"
            - name: S3_BUCKET
              value: "your-cloudtrail-bucket"
            - name: AWS_REGION
              value: "us-east-1"
          ports:
            - name: health
              containerPort: 8080
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
          readinessProbe:
            httpGet:
              path: /ready
              port: 8080
          volumeMounts:
            - name: state
              mountPath: /data
      volumes:
        - name: state
          persistentVolumeClaim:
            claimName: iota-state
```

example eks deployment (eventbridge mode for okta):

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: iota-okta
spec:
  replicas: 1
  template:
    spec:
      serviceAccountName: iota
      containers:
        - name: iota
          image: your-registry/iota:latest
          args:
            - --mode=eventbridge
            - --sqs-queue-url=$(SQS_QUEUE_URL)
            - --aws-region=$(AWS_REGION)
            - --rules=/app/rules/okta
            - --state=/data/state.db
          env:
            - name: SQS_QUEUE_URL
              value: "https://sqs.us-east-1.amazonaws.com/123456789012/okta-events-iota"
            - name: AWS_REGION
              value: "us-east-1"
          ports:
            - name: health
              containerPort: 8080
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
          readinessProbe:
            httpGet:
              path: /ready
              port: 8080
          volumeMounts:
            - name: state
              mountPath: /data
      volumes:
        - name: state
          persistentVolumeClaim:
            claimName: iota-state
```

iam policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::your-cloudtrail-bucket",
        "arn:aws:s3:::your-cloudtrail-bucket/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "sqs:ReceiveMessage",
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes",
        "sqs:GetQueueUrl"
      ],
      "Resource": "arn:aws:sqs:us-east-1:123456789012:iota-cloudtrail-queue"
    },
    {
      "Effect": "Allow",
      "Action": ["kms:Decrypt", "kms:DescribeKey"],
      "Resource": "arn:aws:kms:us-east-1:123456789012:key/your-kms-key-id"
    }
  ]
}
```

## log sources

iota supports multiple log types via an adaptive classifier:

**aws logs (s3-based)**:

- **AWS.CloudTrail**: CloudTrail API audit logs (JSON)
- **AWS.S3ServerAccess**: S3 server access logs (CSV)
- **AWS.VPCFlow**: VPC Flow Logs (CSV)
- **AWS.ALB**: Application Load Balancer access logs (CSV)
- **AWS.AuroraMySQLAudit**: Aurora MySQL audit logs (CSV)

**saas logs (eventbridge)**:

- **Okta.SystemLog**: Okta authentication and admin events
- **GSuite.Reports**: Google Workspace activity reports
- **OnePassword.SignInAttempt**: 1Password sign-in events

the adaptive classifier uses a penalty-based priority queue to automatically identify log types. parsers that fail receive a penalty, reducing their priority for future classifications. this ensures efficient log type detection across mixed log sources.

for eventbridge sources, iota automatically unwraps the eventbridge envelope and detects the log type from the `source` and `detail-type` fields.

## detection rules

iota ships with **50+ production-grade detection rules** across multiple log sources:

**aws cloudtrail** (39 rules):

- **4 Critical** severity rules (root access, public snapshots)
- **18 High** severity rules (IAM backdoors, security logging disabled, data deletion)
- **15 Medium** severity rules (MFA bypasses, unusual access patterns)
- **2 Info/Low** severity rules (failed logins, secret access tracking)

**okta** (5 rules):

- Admin role assignment detection
- API key creation alerts
- MFA factor reset monitoring
- Brute force detection by IP
- Okta support access alerts

**google workspace** (4 rules):

- Admin role assignment
- User suspension monitoring
- 2-Step Verification disabled
- Brute force detection by IP

**1password** (3 rules):

- Unusual client detection
- Brute force login attempts
- Login from unexpected country

rules are python files in `rules/{log_type}/`:

```python
# rules/aws_cloudtrail/aws_console_root_login.py
def rule(event):
    """detect root account console logins"""
    return (
        event.get("eventName") == "ConsoleLogin"
        and event.get("userIdentity", {}).get("type") == "Root"
    )

def title(event):
    """alert title"""
    return f"root console login from {event.get('sourceIPAddress')}"

def severity():
    """alert severity"""
    return "CRITICAL"
```

see [rules/aws_cloudtrail/README.md](rules/aws_cloudtrail/README.md) for complete rule catalog.

rule structure:

- `rule(event)`: returns true if event matches detection logic
- `title(event)`: returns alert title string
- `severity()`: returns severity level (INFO, LOW, MEDIUM, HIGH, CRITICAL)
- `alert_context(event)`: optional additional context for analysts

## integration

alerts output as json to stdout. pipe to your existing tools:

```bash
# send to slack
./bin/iota ... | jq -r '.title' | slack-notify

# send to pagerduty
./bin/iota ... | pagerduty-alert --severity HIGH

# send to siem
./bin/iota ... | fluent-bit -c /etc/fluent-bit/siem.conf
```

## rule updates

pull upstream detection rules:

```bash
# update rules repo
cd rules/aws_cloudtrail
git pull origin main

# restart iota to reload rules
kubectl rollout restart deployment/iota
```

or maintain your own fork:

```bash
# fork this repo
gh repo fork bilals12/iota

# add your custom rules
echo "def rule(event): return event.get('eventName') == 'DeleteBucket'" > rules/aws_cloudtrail/my_rule.py

# deploy your fork
kubectl set image deployment/iota iota=your-registry/iota:custom
```

### threat coverage

rules cover all 14 MITRE ATT&CK tactics:

- Initial Access (console logins, failed attempts)
- Persistence (IAM users, EC2 modifications, SSM sessions)
- Privilege Escalation (admin policy attachments, role assumptions)
- Defense Evasion (logging disabled, unusual user agents)
- Credential Access (EC2 user data, secrets access)
- Discovery (reconnaissance via AccessDenied)
- Execution (SSM Run Command, Lambda modifications)
- Lateral Movement (security groups, network ACLs, routes)
- Collection (logging disabled, user data access)
- Exfiltration (public snapshots, gateway changes)
- Impact (data deletion, KMS key deletion)

## architecture

see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed architecture.

key components:

- **adaptive classifier**: penalty-based priority queue for multi-log source support
- **log processor**: parses and normalizes events by log type
- **data lake writer**: s3-based storage with hourly partitioning
- **rules engine**: orchestrates python rule execution
- **deduplication**: sqlite-based alert deduplication
- **alert forwarder**: routes alerts to configured outputs
- **health check server**: http endpoints for kubernetes probes

## releases & docker image

Pushes to **`main`** can create the next **`v*.*.*`** tag automatically (see [`docs/breaking-changes.md`](docs/breaking-changes.md)). That tag triggers **[`.github/workflows/release.yml`](.github/workflows/release.yml)**: linux binaries on the GitHub release, a **linux/amd64** **`bilals12/iota`** push to Docker Hub with both **`0.x.y`** and **`vx.x.y`** tags (so **`newTag:`** can match the git tag), and a manifest sync on `main`. Locally, run `./scripts/next-release-version.sh`, then `git tag` / `git push origin <tag>` (see **`make release-help`**).

**Secrets:** **`RELEASE_PLEASE_TOKEN`** (PAT, **contents: write**) so tag pushes trigger publish jobs. **`DOCKERHUB_USERNAME`** / **`DOCKERHUB_PASSWORD`** must be able to push **`bilals12/iota`**. **optional — bump [`iota-deployments`](https://github.com/iota-corp/iota-deployments):** add **`IOTA_DEPLOYMENTS_TOKEN`** (PAT: **contents: read and write** on **`iota-corp/iota-deployments`**). The workflow sets **`newTag:`** to the release git tag (e.g. **`v0.7.1`**). For org PAT **403**s, see **[docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)**.

## development

see [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for development setup.

```bash
# run tests
go test ./...

# build
go build -o bin/iota ./cmd/iota

# add integration test
go test ./internal/reader -run TestReaderWithRealCloudTrail -v
```

## security considerations

- **no network egress required** (optional for alerting)
- **read-only cloudtrail access**
- **rules run in isolated python subprocess**
- **no credential storage** (uses iam roles)
- **audit logs** via cloudtrail (iota operations logged)

## license

mit license. see LICENSE file.

## support

- issues: https://github.com/bilals12/iota/issues
- security: report via github security advisories

---

**status**: beta - core detection engine working, event-driven processing with SNS/SQS and EventBridge, adaptive classifier with multi-log source support, data lake and deduplication implemented

**architecture**: dual-mode processing - SNS/SQS for S3-based logs, EventBridge for streaming SaaS logs. adaptive classifier with penalty-based priority queue, health check endpoints, terraform module for infrastructure

**compatibility**:

- aws logs: cloudtrail, s3 server access, vpc flow, alb, aurora mysql audit
- saas logs: okta systemlog, google workspace reports, 1password signinattempt
- delivery: s3 event notifications (cloudtrail), eventbridge partner buses (okta, 1password, sailpoint)
