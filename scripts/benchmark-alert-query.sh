#!/usr/bin/env bash
# Latency check for `iota alerts list` (dedup SQLite). Same code path as interactive IR listing.
#
# From repo root:
#   CGO_ENABLED=1 go build -o bin/iota ./cmd/iota
#   ./scripts/benchmark-alert-query.sh                    # uses ./iota.db (must exist)
#   ./scripts/benchmark-alert-query.sh /path/to/state.db  # e.g. copy from k8s: /data/state.db
#
# If ./iota.db is missing, create an empty DB (schema only, fine for latency smoke test).
# Use the binary you just built under this repo (not /bin/iota — that may be an old image):
#   ./bin/iota alerts list --db ./iota.db --limit 1 --timing=false >/dev/null
#
# Raw log search at scale: use `iota query` (data lake). This path is for open-alert triage (fast, structured rows).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DB="${1:-${ROOT}/iota.db}"
RUNS="${RUNS:-5}"

if [[ ! -f "$DB" ]]; then
	echo "DB not found: $DB" >&2
	echo "" >&2
	echo "iota only creates this file after it has run with --state (or when you list alerts against it)." >&2
	echo "Create a local file for benchmarking (empty alerts table is OK):" >&2
	echo "  cd \"$ROOT\" && CGO_ENABLED=1 go build -o bin/iota ./cmd/iota && \\" >&2
	echo "    ./bin/iota alerts list --db \"$DB\" --limit 1 --timing=false >/dev/null" >&2
	echo "(Use ./bin/iota from this repo; /bin/iota is often a different build.)" >&2
	echo "" >&2
	echo "Or pass your real state file, e.g. from the pod: /data/state.db -> kubectl cp ..." >&2
	exit 1
fi

BIN="${ROOT}/bin/iota"
if [[ ! -x "$BIN" ]]; then
	echo "Build iota first: go build -o bin/iota ./cmd/iota" >&2
	exit 1
fi

TIMEFORMAT=$'real %3R sec\n'
export TIMEFORMAT

echo "Running $RUNS times: $BIN alerts list --db $DB --limit 5000 --json"
echo ""

for i in $(seq 1 "$RUNS"); do
	echo -n "run $i: "
	{ time "$BIN" alerts list --db "$DB" --limit 5000 --json --timing=false >/dev/null; } 2>&1 | tr -d '\n'
	echo ""
done
