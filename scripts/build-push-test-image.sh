#!/usr/bin/env bash
# Build (linux/amd64) and push an image tag for homelab-test / security-test.
# Matches clusters/homelab-test kustomization default pattern — override tag per iteration.
#
# Usage:
#   ./scripts/build-push-test-image.sh
#   ./scripts/build-push-test-image.sh iota-dev-myfeature
#   IOTA_IMAGE_REPO=ghcr.io/org/iota ./scripts/build-push-test-image.sh sha-abc1234
set -euo pipefail

TAG="${1:-iota-dev-x}"
REPO="${IOTA_IMAGE_REPO:-bilals12/iota}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

cd "$ROOT"
docker build --platform linux/amd64 -t "${REPO}:${TAG}" .
docker push "${REPO}:${TAG}"
echo "Pushed ${REPO}:${TAG}"
echo "Next: ensure iota-deployments clusters/homelab-test uses this tag, then sync Argo or run iota-deployments/scripts/deploy-homelab-test-image.sh ${TAG}"
