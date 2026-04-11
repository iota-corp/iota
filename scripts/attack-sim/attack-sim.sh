#!/usr/bin/env bash
# Attack simulation: compare CloudTrail-visible API activity vs iota Prometheus counters.
#
# Rule coverage (synthetic events, no AWS calls): python3 scripts/attack-sim/trigger_all_rules.py
# HIGH/CRITICAL aws_cloudtrail rules (real API → CloudTrail → iota): scripts/attack-sim/soak-aws-cloudtrail-high-critical.sh
#
# Prerequisites: aws CLI (configured), curl, jq, date with GNU/BSD compatibility where noted.
#
# iota serves /metrics on container port 8080 (same as /health). Port-forward:
#   kubectl -n security port-forward svc/iota 18080:8080 &
#
# Modes:
#   ATTACK_SIM_MODE=minimal  — IAM user create/delete only (fastest)
#   ATTACK_SIM_MODE=full     — IAM user + access keys, IAM role + attach policy, S3 bucket/object (default)
#
set -euo pipefail

AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
if [[ -z "${AWS_REGION}" ]]; then
	echo "Set AWS_REGION or AWS_DEFAULT_REGION" >&2
	exit 1
fi

IOTA_METRICS_URL="${IOTA_METRICS_URL:-http://127.0.0.1:18080/metrics}"
WAIT_AFTER_SECONDS="${WAIT_AFTER_SECONDS:-600}"
PRE_WINDOW_SECONDS="${PRE_WINDOW_SECONDS:-120}"
# minimal | full
ATTACK_SIM_MODE="${ATTACK_SIM_MODE:-full}"

SIM_ID="iota-sim-$(date -u +%Y%m%dT%H%M%SZ)-$$"
IAM_USER_NAME="${IAM_USER_NAME:-${SIM_ID}}"
# IAM role name max 64 chars
ROLE_NAME="${SIM_ID}-role"
ROLE_NAME="${ROLE_NAME:0:64}"
# S3 bucket: global DNS; lowercase [a-z0-9.-]; <= 63 chars; include SIM_ID substring for CloudTrail correlation
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "")"
SAN_SIM=$(printf '%s' "$SIM_ID" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9-' | cut -c1-40)
[[ -z "$SAN_SIM" ]] && SAN_SIM="sim${RANDOM}"
S3_BUCKET_NAME=""
if [[ -n "$ACCOUNT_ID" ]]; then
	S3_BUCKET_NAME="iota-sim-${ACCOUNT_ID}-${SAN_SIM}"
	S3_BUCKET_NAME="${S3_BUCKET_NAME:0:63}"
fi

usage() {
	cat <<'EOF'
Usage: attack-sim.sh

Environment:
  AWS_REGION / AWS_DEFAULT_REGION  Required
  IOTA_METRICS_URL                 Default http://127.0.0.1:18080/metrics
  WAIT_AFTER_SECONDS               Default 600 (CloudTrail → S3 batch delay)
  PRE_WINDOW_SECONDS               Extra seconds before CT lookup start
  IAM_USER_NAME                    IAM user for minimal + full IAM user phase (default: SIM_ID)
  ATTACK_SIM_MODE                  minimal = IAM user create/delete only; full = IAM + role + S3 (default)

Example:
  kubectl -n security port-forward svc/iota 18080:8080 &
  export AWS_REGION=us-east-1
  ATTACK_SIM_MODE=full ./attack-sim.sh
EOF
}

sum_metric_lines() {
	local url="$1"
	local prefix="$2"
	curl -sf "$url" | grep "^${prefix}" | awk '{sum += $NF} END {print sum + 0}'
}

# Count CloudTrail events: eventName in want[] AND (event contains SIM_ID OR optional S3 bucket name).
# S3 bucket names use a DNS-safe form and may not include the exact SIM_ID string.
cloudtrail_count_simulation_events() {
	local start="$1"
	local end="$2"
	local token="$3"
	local s3_bucket="${4:-}"
	shift 4
	local -a want=("$@")
	local want_json
	want_json=$(printf '%s\n' "${want[@]}" | jq -R . | jq -s .)
	local total=0
	local next=""

	while true; do
		local args=(cloudtrail lookup-events --region "$AWS_REGION" --start-time "$start" --end-time "$end" --max-results 50)
		if [[ -n "$next" ]]; then
			args+=(--next-token "$next")
		fi
		local resp
		resp=$(aws "${args[@]}" --output json) || return 1

		local page_count
		page_count=$(echo "$resp" | jq --arg tok "$token" --arg bkt "$s3_bucket" --argjson names "$want_json" '
      [.Events[]?
        | try (.CloudTrailEvent | fromjson) catch empty
        | select(type == "object")
        | select($names | index(.eventName) != null)
        | select(
            (. | tostring | contains($tok))
            or (($bkt | length) > 0 and (. | tostring | contains($bkt)))
          )
      ] | length
    ')
		total=$((total + page_count))

		next=$(echo "$resp" | jq -r '.NextToken // empty')
		if [[ -z "$next" ]]; then
			break
		fi
	done
	echo "$total"
}

# Event names we attempt to produce (subset may fail if IAM/S3 denies).
expected_event_names() {
	case "$ATTACK_SIM_MODE" in
	minimal)
		echo CreateUser DeleteUser
		;;
	full | *)
		echo CreateUser CreateAccessKey DeleteAccessKey DeleteUser \
			CreateRole AttachRolePolicy DetachRolePolicy DeleteRole \
			CreateBucket PutObject DeleteObject DeleteBucket
		;;
	esac
}

run_scenario_minimal() {
	echo "[minimal] IAM user ${IAM_USER_NAME}"
	aws iam create-user --region "$AWS_REGION" --user-name "$IAM_USER_NAME" >/dev/null
	aws iam delete-user --region "$AWS_REGION" --user-name "$IAM_USER_NAME" >/dev/null
}

run_scenario_full() {
	run_scenario_minimal

	echo "[full] IAM access key lifecycle for ${IAM_USER_NAME}"
	set +e
	aws iam create-user --region "$AWS_REGION" --user-name "${IAM_USER_NAME}-keyed" >/dev/null
	if aws iam create-access-key --region "$AWS_REGION" --user-name "${IAM_USER_NAME}-keyed" --output json >/tmp/ak-$$.json 2>/dev/null; then
		AK=$(jq -r '.AccessKey.AccessKeyId' /tmp/ak-$$.json)
		aws iam delete-access-key --region "$AWS_REGION" --user-name "${IAM_USER_NAME}-keyed" --access-key-id "$AK" >/dev/null
	else
		echo "  (warn) create-access-key skipped or failed — delete keyed user if present" >&2
	fi
	aws iam delete-user --region "$AWS_REGION" --user-name "${IAM_USER_NAME}-keyed" >/dev/null 2>&1
	rm -f /tmp/ak-$$.json
	set -e

	echo "[full] IAM role + managed policy attach/detach: ${ROLE_NAME}"
	set +e
	TRUST=$(mktemp)
	printf '%s' '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}' >"$TRUST"
	aws iam create-role --region "$AWS_REGION" --role-name "$ROLE_NAME" --assume-role-policy-document "file://$TRUST" >/dev/null
	aws iam attach-role-policy --region "$AWS_REGION" --role-name "$ROLE_NAME" --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess >/dev/null
	aws iam detach-role-policy --region "$AWS_REGION" --role-name "$ROLE_NAME" --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess >/dev/null
	aws iam delete-role --region "$AWS_REGION" --role-name "$ROLE_NAME" >/dev/null
	rm -f "$TRUST"
	set -e

	if [[ -z "$S3_BUCKET_NAME" ]]; then
		echo "[full] skip S3 (could not determine account id for bucket name)" >&2
		return 0
	fi

	echo "[full] S3 bucket + object: ${S3_BUCKET_NAME}"
	set +e
	if [[ "$AWS_REGION" == "us-east-1" ]]; then
		aws s3api create-bucket --region "$AWS_REGION" --bucket "$S3_BUCKET_NAME" >/dev/null
	else
		aws s3api create-bucket --region "$AWS_REGION" --bucket "$S3_BUCKET_NAME" \
			--create-bucket-configuration "LocationConstraint=${AWS_REGION}" >/dev/null
	fi && {
		echo "iota-attack-sim" | aws s3 cp - "s3://${S3_BUCKET_NAME}/iota-sim-key.txt" --region "$AWS_REGION" >/dev/null
		aws s3api delete-object --region "$AWS_REGION" --bucket "$S3_BUCKET_NAME" --key iota-sim-key.txt >/dev/null
		aws s3api delete-bucket --region "$AWS_REGION" --bucket "$S3_BUCKET_NAME" >/dev/null
	} || echo "  (warn) S3 create-bucket failed — check s3:CreateBucket permission" >&2
	set -e
}

run_scenarios() {
	echo "Simulation id (embedded in resource names): ${SIM_ID}"
	echo "Mode: ${ATTACK_SIM_MODE}"
	case "$ATTACK_SIM_MODE" in
	minimal) run_scenario_minimal ;;
	full) run_scenario_full ;;
	*)
		echo "Unknown ATTACK_SIM_MODE=$ATTACK_SIM_MODE (use minimal or full)" >&2
		exit 1
		;;
	esac
}

main() {
	echo "=== iota attack-sim ==="
	echo "Region: ${AWS_REGION}"
	echo "Metrics: ${IOTA_METRICS_URL}"
	echo "Wait after scenario (s): ${WAIT_AFTER_SECONDS}"
	echo ""

	echo "Baseline metrics (before scenario)..."
	local ev0 al0 sq0
	ev0=$(sum_metric_lines "$IOTA_METRICS_URL" "iota_events_processed_total")
	al0=$(sum_metric_lines "$IOTA_METRICS_URL" "iota_alerts_generated_total")
	sq0=$(sum_metric_lines "$IOTA_METRICS_URL" "iota_sqs_messages_processed_total")
	echo "  iota_events_processed_total (sum): ${ev0}"
	echo "  iota_alerts_generated_total (sum): ${al0}"
	echo "  iota_sqs_messages_processed_total (sum): ${sq0}"

	local t0 t1
	t0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
	sleep 1

	run_scenarios

	t1=$(date -u +%Y-%m-%dT%H:%M:%SZ)
	echo ""
	echo "Scenario window (API): ${t0} .. ${t1}"
	echo "Waiting ${WAIT_AFTER_SECONDS}s for CloudTrail → S3 → SQS → iota..."
	sleep "$WAIT_AFTER_SECONDS"

	echo ""
	echo "Post-run metrics..."
	local ev1 al1 sq1
	ev1=$(sum_metric_lines "$IOTA_METRICS_URL" "iota_events_processed_total")
	al1=$(sum_metric_lines "$IOTA_METRICS_URL" "iota_alerts_generated_total")
	sq1=$(sum_metric_lines "$IOTA_METRICS_URL" "iota_sqs_messages_processed_total")

	local d_ev d_al d_sq
	d_ev=$(awk -v a="$ev1" -v b="$ev0" 'BEGIN { printf "%.0f", a - b }')
	d_al=$(awk -v a="$al1" -v b="$al0" 'BEGIN { printf "%.0f", a - b }')
	d_sq=$(awk -v a="$sq1" -v b="$sq0" 'BEGIN { printf "%.0f", a - b }')

	echo "  iota_events_processed_total Δ: ${d_ev}"
	echo "  iota_alerts_generated_total Δ: ${d_al}"
	echo "  iota_sqs_messages_processed_total Δ: ${d_sq}"

	local start_lookup end_lookup start_ts
	start_ts=$(($(date -u +%s) - PRE_WINDOW_SECONDS))
	if ! start_lookup=$(date -u -d "@$start_ts" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null); then
		start_lookup=$(date -u -r "$start_ts" +%Y-%m-%dT%H:%M:%SZ)
	fi
	end_lookup=$(date -u +%Y-%m-%dT%H:%M:%SZ)

	# shellcheck disable=SC2207
	EXPECTED_ARR=($(expected_event_names))

	echo ""
	echo "CloudTrail lookup-events window: ${start_lookup} .. ${end_lookup}"
	echo "  Match: eventName in (${EXPECTED_ARR[*]}) AND event body contains SIM_ID token"
	local ct_count
	ct_count=$(cloudtrail_count_simulation_events "$start_lookup" "$end_lookup" "$SIM_ID" "${S3_BUCKET_NAME:-}" "${EXPECTED_ARR[@]}")
	echo "  Matching simulation-tagged events: ${ct_count}"

	echo ""
	echo "=== Summary ==="
	echo "AWS CloudTrail (simulation-tagged, expected API names): ${ct_count}"
	echo "iota events processed (counter Δ):     ${d_ev}"
	echo "iota SQS messages processed (counter Δ): ${d_sq}"
	echo "iota alerts generated (counter Δ):     ${d_al}"
	echo ""
	echo "Note: Not every rule in rules/ can be fired from one shell script (EC2, RDS, KMS, etc.)."
	echo "This run exercises additional IAM + S3 paths in full mode. For more coverage, add"
	echo "scoped API calls here or use trigger_all_rules.py for offline logic checks."
}

case "${1:-}" in
-h | --help | help)
	usage
	exit 0
	;;
*) main ;;
esac
