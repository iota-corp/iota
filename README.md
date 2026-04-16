# iota

<div align="center">

![iota logo](docs/assets/iotaBlack.png)

<sub>art by [fdkubba](https://www.faisalkubba.com/reels)</sub>

**self-hosted security detection engine**

runs entirely within your aws account. consumes cloudtrail, okta, google workspace, and 1password logs. applies detection logic locally, emits alerts to your existing tooling. no telemetry exfiltration.

**contributing:** **[CLAUDE.md](CLAUDE.md)** (index for humans and coding agents) · **[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)** (openspec, branches/prs, testing, parsers/rules)

</div>

## why iota?

stuck with legacy siems that can't keep up? tired of paying per-gb for detection-as-a-service? need full control over your security detections?

iota gives you:

- **data sovereignty**: logs never leave your control boundary
- **auditability**: open source, verify no phone-home behavior
- **customization**: modify detection rules without vendor release cycles
- **simplicity**: fork, deploy to your infra, point at your logs

## how it works

### aws cloudtrail — default: `--mode=eventbridge` (recommended)

**use this** when you want **low detection latency** and **per-api-call** processing. cloudtrail emits **`AWS API Call via CloudTrail`** on the **default event bus**; an eventbridge rule forwards matching events to **sqs**; iota reads the queue and unwraps small json payloads (**no s3 download** for this path).

```
cloudtrail → eventbridge (default bus) → rule → sqs → iota (--mode=eventbridge) → log processor → rules engine → deduplication → alerts
```

rough performance profile (typical lab/prod):

| aspect               | cloudtrail + eventbridge + sqs                                                                 |
| -------------------- | ---------------------------------------------------------------------------------------------- |
| **delivery**         | seconds after the api call (eventbridge + queue + poll)                                        |
| **per-message work** | small json → parse → **rules engine** dominates cpu (~hundreds of ms per event in many setups) |
| **observability**    | otel spans such as **`process_eventbridge_event`**; no **`s3.GetObject`** on this path         |

**important:** eventbridge rules must match **`detail-type: AWS API Call via CloudTrail`** using the **originating service** as `source` (e.g. `aws.s3`, `aws.iam`) — **not** only `aws.cloudtrail`, or you will match almost nothing except cloudtrail’s own control-plane apis.

### aws cloudtrail — cost-saving: `--mode=sqs` (s3 notifications)

**use this** when you want to **avoid high eventbridge invocation volume** and can tolerate **multi-minute** end-to-end delay. cloudtrail still writes **batched `.json.gz` log files** to s3; **s3 object notifications** (often via **sns**) drive an **sqs** queue of bucket/key pointers; iota **downloads and parses** each file.

```
cloudtrail (s3) → s3 notifications → sns topic → sqs queue → iota (--mode=sqs) → s3 getobject → gunzip → log processor → rules engine → deduplication → alerts
```

rough performance profile:

| aspect              | s3 file path + sqs                                                                                                                                    |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| **delivery**        | dominated by **cloudtrail → s3** batching (**often ~5–15+ minutes**) before a new object exists to notify on                                          |
| **per-object work** | **s3 getobject** + decompress + parse **many records** per file → higher wall time per **`process_s3_object`** span than a single eventbridge message |
| **cost tradeoff**   | fewer “per-api” downstream events than a broad eventbridge rule; you still pay for **s3** storage and **sqs** polling                                 |

same downstream stages after parse: **data lake** (optional) → **rules engine** → **deduplication** → **alert forwarder**.

### saas logs — `--mode=eventbridge` (partner event buses)

```
okta / 1password / sailpoint → eventbridge partner bus → rule → sqs → iota (--mode=eventbridge) → envelope unwrap → log processor → rules engine → …
```

1. **saas** sends events to a **partner** event bus
2. **eventbridge rule** routes to **sqs**
3. **iota** unwraps the envelope, classifies **log type**, runs **rules**
4. same **deduplication** and **alerts** as above

## quick start

### prerequisites

- go 1.25+
- python 3.11+
- aws credentials: **sqs** receive/delete; **s3** read on the cloudtrail bucket only if you use **`--mode=sqs`** (see [how it works](#how-it-works))

**cli default:** **`--mode`** defaults to **`eventbridge`**. Use **`--mode=sqs`** explicitly for the s3 log-file / notification path. Running with no mode flags requires **`--sqs-queue-url`** (and aws config) suitable for your eventbridge-fed queue.

### installation

```bash
git clone https://github.com/iota-corp/iota.git
cd iota

go build -o bin/iota ./cmd/iota

./bin/iota \
  --jsonl testdata/events/root-login.jsonl \
  --rules rules/aws_cloudtrail \
  --python python3 \
  --engine engines/iota/engine.py
```

### related repositories

| repo                                                                  | role                                                                |
| --------------------------------------------------------------------- | ------------------------------------------------------------------- |
| **[iota](https://github.com/iota-corp/iota)** (this repo)             | application, rules, `Dockerfile`, CI, `deployments/kubernetes/base` |
| **[iota-deployments](https://github.com/iota-corp/iota-deployments)** | kustomize overlays per cluster, image tags, argo cd apps            |
| **[iota-infra](https://github.com/iota-corp/iota-infra)**             | terraform: iam, eks, queues, etc. (environment-specific)            |

### deployment

production manifests and per-cluster settings live in **iota-deployments** (kustomize overlays, secrets, queue urls). base kubernetes yaml is maintained in this repo under **`deployments/kubernetes/base`** and vendored/synced there—see **iota-deployments** `README.md`.

**compute:** eks, k3s, ecs, fargate, or ec2 · **permissions:** **sqs** receive/delete on the ingestion queue; **`--mode=sqs`** also needs **s3** get/list on the cloudtrail bucket (downloads **`.json.gz`** log files). **`--mode=eventbridge`** for cloudtrail **api** events ingests **json from sqs** (no per-detection s3 log file download) · **storage:** persistent disk for sqlite state/dedup

the official container image includes bundled rules under `/app/rules` (see the `dockerfile`). point `--rules` at a subdirectory such as `/app/rules/aws_cloudtrail` or `/app/rules/okta`; you normally do **not** mount a configmap for rules.

example eks deployment (**cloudtrail via eventbridge** — default for aws api detections):

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: iota-cloudtrail-eb
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
            - --s3-bucket=$(S3_BUCKET)
            - --aws-region=$(AWS_REGION)
            - --rules=/app/rules/aws_cloudtrail
            - --state=/data/state.db
          env:
            # queue fed by eventbridge rule (not s3 object notifications)
            - name: SQS_QUEUE_URL
              value: "https://sqs.us-east-1.amazonaws.com/123456789012/cloudtrail-eventbridge-to-iota"
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

use a **distinct** `OTEL_SERVICE_NAME` (e.g. `iota-eventbridge`) if you run this **alongside** the s3/sqs deployment so traces stay separable.

example eks deployment (**cloudtrail via s3 notifications + sqs** — cost-saving / higher latency):

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: iota-cloudtrail-s3
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
              value: "https://sqs.us-east-1.amazonaws.com/123456789012/iota-cloudtrail-s3-notify-queue"
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

example eks deployment (eventbridge mode for **okta** / saas):

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

- **[CLAUDE.md](CLAUDE.md)** — doc index and minimum commands for coding agents
- **[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)** — OpenSpec workflow, branch/pr conventions, TDD, repo map, GitOps
- **[docs/TIER-B-C.md](docs/TIER-B-C.md)** — SQS/EventBridge env tuning, parallelism, Tier C ops (DLQ, replicas)
- **[TESTING.md](TESTING.md)** — fixtures, integration tests, smoke, attack-sim
- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — detailed architecture

```bash
export CGO_ENABLED=1
go test ./...
./scripts/smoke.sh
# or: make ci-local
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

**architecture**: **cloudtrail api detections:** prefer **`--mode=eventbridge`** (low latency); optional **`--mode=sqs`** for s3 file notifications (cost / volume tradeoffs). **saas:** eventbridge partner buses → sqs. adaptive classifier with penalty-based priority queue, health check endpoints; infra examples in **iota-infra** / **iota-deployments**

**compatibility**:

- aws logs: cloudtrail, s3 server access, vpc flow, alb, aurora mysql audit
- saas logs: okta systemlog, google workspace reports, 1password signinattempt
- delivery: **cloudtrail:** eventbridge → sqs (recommended), or s3 notifications → sqs; **saas:** eventbridge partner buses (okta, 1password, sailpoint)
