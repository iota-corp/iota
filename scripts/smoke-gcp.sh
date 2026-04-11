#!/usr/bin/env bash
# Smoke: iota once mode over GCP fixture JSONL (audit + HTTP LB rule dirs).
# Usage: from repo root, ./scripts/smoke-gcp.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export CGO_ENABLED=1
export GOCACHE="${GOCACHE:-$ROOT/.gocache}"
export GOMODCACHE="${GOMODCACHE:-$ROOT/.gomodcache}"
mkdir -p "$GOCACHE" "$GOMODCACHE"

need() {
	command -v "$1" >/dev/null 2>&1 || {
		echo "smoke-gcp: missing required command: $1" >&2
		exit 1
	}
}

need go
need python3

AUDIT_JSONL="${SMOKE_GCP_AUDIT_JSONL:-testdata/rulesets/gcp_auditlog/samples.jsonl}"
HTTPLB_JSONL="${SMOKE_GCP_HTTPLB_JSONL:-testdata/rulesets/gcp_httploadbalancer/samples.jsonl}"

for f in "$AUDIT_JSONL" "$HTTPLB_JSONL"; do
	if [[ ! -f "$f" ]]; then
		echo "smoke-gcp: fixture not found: $f" >&2
		exit 1
	fi
done

echo "smoke-gcp: building bin/iota (CGO_ENABLED=1)..."
mkdir -p bin
go build -o bin/iota ./cmd/iota

echo "smoke-gcp: GCP.AuditLog rules ($AUDIT_JSONL)..."
./bin/iota \
	--mode=once \
	--jsonl="$AUDIT_JSONL" \
	--rules=rules/gcp_audit \
	--python=python3 \
	--engine=engines/iota/engine.py

echo "smoke-gcp: GCP.HTTPLoadBalancer rules ($HTTPLB_JSONL)..."
./bin/iota \
	--mode=once \
	--jsonl="$HTTPLB_JSONL" \
	--rules=rules/gcp_http_lb \
	--python=python3 \
	--engine=engines/iota/engine.py

echo "smoke-gcp: OK"
