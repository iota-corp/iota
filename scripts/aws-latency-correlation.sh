#!/usr/bin/env bash
# Manual correlation helpers for CloudTrail → S3 → SQS → iota latency.
# Use alongside iota logs when IOTA_LATENCY_TRACE=true (grep "latency_trace").
#
# Requires: aws CLI, jq (optional), credentials for the account.
#
# Example — S3 object metadata (compare to latency_trace s3_last_modified):
#   ./scripts/aws-latency-correlation.sh head-object my-bucket 'AWSLogs/123/CloudTrail/.../file.json.gz'
#
# Example — queue backlog / oldest message age (CloudWatch or CLI):
#   aws sqs get-queue-attributes --queue-url "$SQS_QUEUE_URL" \
#     --attribute-names ApproximateNumberOfMessages ApproximateAgeOfOldestMessage

set -euo pipefail

usage() {
	sed -n '1,20p' "$0"
}

cmd="${1:-}"
case "$cmd" in
head-object)
	bucket="${2:?bucket name}"
	key="${3:?object key}"
	region="${4:-${AWS_REGION:-us-east-1}}"
	aws s3api head-object --bucket "$bucket" --key "$key" --region "$region" \
		--query '{LastModified:LastModified,ContentLength:ContentLength,ETag:ETag}' \
		--output json
	;;
-h | --help | help | "")
	usage
	;;
*)
	echo "unknown command: $cmd" >&2
	usage
	exit 1
	;;
esac
