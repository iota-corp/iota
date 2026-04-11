#!/usr/bin/env bash
# End-to-end smoke: build iota with CGO, run once mode over fixture JSONL (log pipeline + Python rules).
# Usage: from repo root, ./scripts/smoke.sh
# Env:   SMOKE_JSONL=path override fixture (default: testdata/sample.jsonl)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export CGO_ENABLED=1
export GOCACHE="${GOCACHE:-$ROOT/.gocache}"
export GOMODCACHE="${GOMODCACHE:-$ROOT/.gomodcache}"
mkdir -p "$GOCACHE" "$GOMODCACHE"

need() {
	command -v "$1" >/dev/null 2>&1 || {
		echo "smoke: missing required command: $1" >&2
		exit 1
	}
}

need go
need python3

JSONL="${SMOKE_JSONL:-testdata/sample.jsonl}"
if [[ ! -f "$JSONL" ]]; then
	echo "smoke: fixture not found: $JSONL" >&2
	exit 1
fi

echo "smoke: building bin/iota (CGO_ENABLED=1)..."
mkdir -p bin
go build -o bin/iota ./cmd/iota

echo "smoke: running once mode (rules=rules/aws_cloudtrail, jsonl=$JSONL)..."
./bin/iota \
	--mode=once \
	--jsonl="$JSONL" \
	--rules=rules/aws_cloudtrail \
	--python=python3 \
	--engine=engines/iota/engine.py

echo "smoke: OK"
