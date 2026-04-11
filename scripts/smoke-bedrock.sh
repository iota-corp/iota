#!/usr/bin/env bash
# Smoke: Bedrock model-invocation fixtures + Bedrock rules only.
# Usage: from repo root, ./scripts/smoke-bedrock.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export CGO_ENABLED=1
export GOCACHE="${GOCACHE:-$ROOT/.gocache}"
export GOMODCACHE="${GOMODCACHE:-$ROOT/.gomodcache}"
mkdir -p "$GOCACHE" "$GOMODCACHE"

JSONL="${SMOKE_BEDROCK_JSONL:-testdata/rulesets/aws_bedrockmodelinvocation/samples.jsonl}"
if [[ ! -f "$JSONL" ]]; then
	echo "smoke-bedrock: fixture not found: $JSONL" >&2
	exit 1
fi

need() { command -v "$1" >/dev/null 2>&1 || {
	echo "smoke-bedrock: missing $1" >&2
	exit 1
}; }
need go
need python3

echo "smoke-bedrock: building bin/iota..."
mkdir -p bin
go build -o bin/iota ./cmd/iota

echo "smoke-bedrock: once mode (rules=rules/aws_bedrockmodelinvocation, jsonl=$JSONL)..."
./bin/iota \
	--mode=once \
	--jsonl="$JSONL" \
	--rules=rules/aws_bedrockmodelinvocation \
	--python=python3 \
	--engine=engines/iota/engine.py

echo "smoke-bedrock: OK"
