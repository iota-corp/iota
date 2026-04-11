#!/usr/bin/env bash
# Smoke: Slack audit + Cloudflare firewall + HTTP fixtures (Phase 4).
# Usage: from repo root, ./scripts/smoke-phase4.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export CGO_ENABLED=1
export GOCACHE="${GOCACHE:-$ROOT/.gocache}"
export GOMODCACHE="${GOMODCACHE:-$ROOT/.gomodcache}"
mkdir -p "$GOCACHE" "$GOMODCACHE"

need() {
	command -v "$1" >/dev/null 2>&1 || {
		echo "smoke-phase4: missing required command: $1" >&2
		exit 1
	}
}

need go
need python3

for f in \
	testdata/rulesets/slack_audit/samples.jsonl \
	testdata/rulesets/cloudflare_firewall/samples.jsonl \
	testdata/rulesets/cloudflare_http/samples.jsonl; do
	if [[ ! -f "$f" ]]; then
		echo "smoke-phase4: fixture not found: $f" >&2
		exit 1
	fi
done

echo "smoke-phase4: building bin/iota..."
mkdir -p bin
go build -o bin/iota ./cmd/iota

echo "smoke-phase4: Slack.AuditLogs..."
./bin/iota --mode=once --jsonl=testdata/rulesets/slack_audit/samples.jsonl \
	--rules=rules/slack_audit --python=python3 --engine=engines/iota/engine.py

echo "smoke-phase4: Cloudflare.Firewall..."
./bin/iota --mode=once --jsonl=testdata/rulesets/cloudflare_firewall/samples.jsonl \
	--rules=rules/cloudflare --python=python3 --engine=engines/iota/engine.py

echo "smoke-phase4: Cloudflare.HttpRequest (rules dir has only firewall log rule; expect 0 matches OK)..."
./bin/iota --mode=once --jsonl=testdata/rulesets/cloudflare_http/samples.jsonl \
	--rules=rules/cloudflare --python=python3 --engine=engines/iota/engine.py

echo "smoke-phase4: OK"
