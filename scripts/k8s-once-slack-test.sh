#!/usr/bin/env bash
# Pipe a CloudTrail JSON fixture into iota --mode=once inside the running Deployment.
# Exercises parsing, Python rules, and Slack (uses pod env SLACK_WEBHOOK_URL if set).
#
# Prerequisites: kubectl configured; iota running in cluster; optional iota-slack-webhook secret.
#
# Usage:
#   ./scripts/k8s-once-slack-test.sh
#   ./scripts/k8s-once-slack-test.sh /path/to/other.json
#
# Env:
#   K8S_NAMESPACE   default security
#   IOTA_DEPLOY     default iota
#   IOTA_RULES      default /app/rules (match your Deployment --rules)
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEFAULT_FIXTURE="${ROOT}/testdata/cloudtrail-logs/655631470870_CloudTrail_us-east-1_20250603T0000Z_7H1LZgDVaQGQP5h6.json"
FIXTURE="${1:-$DEFAULT_FIXTURE}"
NS="${K8S_NAMESPACE:-security-test}"
DEPLOY="${IOTA_DEPLOY:-iota}"
RULES="${IOTA_RULES:-/app/rules}"

if [[ ! -f "$FIXTURE" ]]; then
	echo "Fixture not found: $FIXTURE" >&2
	exit 1
fi

echo "Using fixture: $FIXTURE"
echo "kubectl exec -n ${NS} deploy/${DEPLOY} (rules=${RULES})"

kubectl exec -n "${NS}" "deploy/${DEPLOY}" -i -- sh -c "
  exec /app/iota \
    --mode=once \
    --jsonl=/dev/stdin \
    --rules=${RULES} \
    --python=python3 \
    --engine=/app/engines/iota/engine.py \
    --slack-webhook=\"\${SLACK_WEBHOOK_URL}\"
" <"${FIXTURE}"
