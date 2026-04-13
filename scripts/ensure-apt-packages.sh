#!/usr/bin/env bash
# Install Debian packages via apt when passwordless sudo is available (GitHub-hosted
# runners); otherwise verify packages are already installed (typical self-hosted).
# Usage: ./scripts/ensure-apt-packages.sh gcc g++ libc6-dev libsqlite3-dev
set -euo pipefail

if [[ $# -lt 1 ]]; then
	echo "usage: $0 <deb-package>..." >&2
	exit 1
fi

if sudo -n true 2>/dev/null; then
	sudo apt-get update
	sudo apt-get install -y --no-install-recommends "$@"
	exit 0
fi

missing=()
for p in "$@"; do
	if ! dpkg -s "$p" >/dev/null 2>&1; then
		missing+=("$p")
	fi
done
if [[ ${#missing[@]} -gt 0 ]]; then
	echo "::error::Self-hosted runner is missing: ${missing[*]}. Install on the host: sudo apt-get install -y ${missing[*]}" >&2
	exit 1
fi
