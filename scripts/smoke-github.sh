#!/usr/bin/env bash
# Smoke: iota once mode over GitHub fixture JSONL with audit and webhook rule dirs.
# Usage: from repo root, ./scripts/smoke-github.sh
# Env:   SMOKE_AUDIT_JSONL, SMOKE_WEBHOOK_JSONL (defaults under testdata/rulesets/)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export CGO_ENABLED=1
export GOCACHE="${GOCACHE:-$ROOT/.gocache}"
export GOMODCACHE="${GOMODCACHE:-$ROOT/.gomodcache}"
mkdir -p "$GOCACHE" "$GOMODCACHE"

need() {
	command -v "$1" >/dev/null 2>&1 || {
		echo "smoke-github: missing required command: $1" >&2
		exit 1
	}
}

need go
need python3

AUDIT_JSONL="${SMOKE_AUDIT_JSONL:-testdata/rulesets/github_audit/samples.jsonl}"
WEBHOOK_JSONL="${SMOKE_WEBHOOK_JSONL:-testdata/rulesets/github_webhook/samples.jsonl}"

for f in "$AUDIT_JSONL" "$WEBHOOK_JSONL"; do
	if [[ ! -f "$f" ]]; then
		echo "smoke-github: fixture not found: $f" >&2
		exit 1
	fi
done

echo "smoke-github: building bin/iota (CGO_ENABLED=1)..."
mkdir -p bin
go build -o bin/iota ./cmd/iota

echo "smoke-github: audit rules ($AUDIT_JSONL)..."
./bin/iota \
	--mode=once \
	--jsonl="$AUDIT_JSONL" \
	--rules=rules/github_audit \
	--python=python3 \
	--engine=engines/iota/engine.py

echo "smoke-github: webhook rules ($WEBHOOK_JSONL)..."
./bin/iota \
	--mode=once \
	--jsonl="$WEBHOOK_JSONL" \
	--rules=rules/github_webhook \
	--python=python3 \
	--engine=engines/iota/engine.py

echo "smoke-github: OK"
