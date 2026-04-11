#!/usr/bin/env bash
# Smoke: iota once mode over EKS audit fixture JSONL with unified kubernetes rules.
# Usage: from repo root, ./scripts/smoke-kubernetes.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export CGO_ENABLED=1
export GOCACHE="${GOCACHE:-$ROOT/.gocache}"
export GOMODCACHE="${GOMODCACHE:-$ROOT/.gomodcache}"
mkdir -p "$GOCACHE" "$GOMODCACHE"

need() {
	command -v "$1" >/dev/null 2>&1 || {
		echo "smoke-kubernetes: missing required command: $1" >&2
		exit 1
	}
}

need go
need python3

JSONL="${SMOKE_EKS_JSONL:-testdata/rulesets/eks_audit/samples.jsonl}"
if [[ ! -f "$JSONL" ]]; then
	echo "smoke-kubernetes: fixture not found: $JSONL" >&2
	exit 1
fi

echo "smoke-kubernetes: building bin/iota (CGO_ENABLED=1)..."
mkdir -p bin
go build -o bin/iota ./cmd/iota

echo "smoke-kubernetes: rules/kubernetes ($JSONL)..."
./bin/iota \
	--mode=once \
	--jsonl="$JSONL" \
	--rules=rules/kubernetes \
	--python=python3 \
	--engine=engines/iota/engine.py

echo "smoke-kubernetes: OK"
