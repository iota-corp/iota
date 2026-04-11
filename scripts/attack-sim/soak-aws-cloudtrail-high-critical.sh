#!/usr/bin/env bash
#
# Soak-test: emit real CloudTrail API activity intended to match each HIGH/CRITICAL rule
# under rules/aws_cloudtrail (live pipeline: CT → S3 → SQS → iota).
#
# Prereqs: aws CLI, credentials for a lab account/role, AWS_REGION set.
# Many steps are destructive or security-sensitive — do not run against production.
#
# On exit (success or failure), runs cleanup to revert created resources where possible.
# Irreversible steps (e.g. deleted snapshots, removed flow logs) are noted in cleanup output.
#
# Usage:
#   export AWS_PROFILE=iota-lab
#   export AWS_REGION=us-east-1
#   export SOAK_INSTANCE_ID=i-xxx
#   export SOAK_TRAIL_NAME=...
#   ./scripts/attack-sim/soak-aws-cloudtrail-high-critical.sh
#
set -uo pipefail

SOAK_TAG="${SOAK_TAG:-iota-soak-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
_SAVED_AKI="${AWS_ACCESS_KEY_ID:-}"
_SAVED_ASK="${AWS_SECRET_ACCESS_KEY:-}"
_SAVED_ST="${AWS_SESSION_TOKEN:-}"

# Tracked for cleanup (set as resources are created/touched)
BUCKET=""
U_SOAK=""
U_TARGET=""
U_BACKDOOR=""
ROLE_SOAK=""
KEY_ID=""
RECORDER_NAME=""
RECORDER_WAS_STOPPED="0"
DET_ID=""
SOAK_SG_INGRESS_ADDED="0"
_BUCKET_EXISTS="0"
_SAVED_USER_DATA_B64=""
CLEANUP_RAN="0"
FAILURES=0

ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
if [[ -z "$REGION" ]]; then
	echo "Set AWS_REGION or AWS_DEFAULT_REGION" >&2
	exit 1
fi

soak_step() {
	local num="$1" title="$2"
	shift 2
	echo "[${num}] ${title}"
	local err
	err="$(mktemp)"
	set +e
	(
		"$@"
	) >"$err" 2>&1
	local ec=$?
	if [[ $ec -eq 0 ]]; then
		echo "  status: SUCCESS"
		rm -f "$err"
		return 0
	fi
	echo "  status: FAILURE (exit ${ec})"
	# One line for logs; trim whitespace
	local reason
	reason="$(sed 's/^[[:space:]]*//;s/[[:space:]]*$//' "$err" | tr '\n' ' ' | head -c 900)"
	echo "  reason: ${reason}"
	rm -f "$err"
	FAILURES=$((FAILURES + 1))
	return "$ec"
}

soak_skip() {
	local num="$1" title="$2" reason="$3"
	echo "[${num}] ${title}"
	echo "  status: SKIPPED — ${reason}"
}

# Remove every object version and delete marker so DeleteBucket succeeds (versioned buckets).
s3_empty_bucket_all_versions() {
	local bucket="$1"
	local json del_json n
	while true; do
		json="$(aws s3api list-object-versions --bucket "$bucket" --output json 2>/dev/null)" || return 0
		n="$(echo "$json" | jq '(.Versions // []) + (.DeleteMarkers // []) | length')"
		[[ "${n:-0}" -eq 0 ]] && return 0
		del_json="$(echo "$json" | jq -c '{Objects: ((.Versions // []) + (.DeleteMarkers // []) | map({Key: .Key, VersionId: .VersionId}) | .[0:1000]), Quiet: true}')"
		aws s3api delete-objects --bucket "$bucket" --delete "$del_json" >/dev/null 2>&1 || return 1
	done
}

# shellcheck disable=SC2329 # invoked from cleanup_soak (registered on EXIT trap)
iam_delete_user_all() {
	local u="$1"
	[[ -z "$u" ]] && return 0
	local keys k p
	keys="$(aws iam list-access-keys --user-name "$u" --query 'AccessKeyMetadata[].AccessKeyId' --output text 2>/dev/null || true)"
	for k in $keys; do
		[[ -z "$k" || "$k" == "None" ]] && continue
		aws iam delete-access-key --user-name "$u" --access-key-id "$k" 2>/dev/null || true
	done
	while read -r p; do
		[[ -z "$p" || "$p" == "None" ]] && continue
		aws iam detach-user-policy --user-name "$u" --policy-arn "$p" 2>/dev/null || true
	done < <(aws iam list-attached-user-policies --user-name "$u" --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null | tr '\t' '\n')
	aws iam delete-user --user-name "$u" 2>/dev/null || true
}

# shellcheck disable=SC2329 # invoked via trap EXIT, not static call graph
cleanup_soak() {
	[[ "$CLEANUP_RAN" -eq 1 ]] && return 0
	CLEANUP_RAN=1

	echo ""
	echo "=== Reverting soak changes (best-effort) ==="

	if [[ -n "${U_BACKDOOR:-}" ]]; then
		echo "  Removing IAM user ${U_BACKDOOR}..."
		iam_delete_user_all "$U_BACKDOOR"
	fi

	if [[ -n "${ROLE_SOAK:-}" ]]; then
		echo "  Removing IAM role ${ROLE_SOAK}..."
		aws iam detach-role-policy --role-name "$ROLE_SOAK" \
			--policy-arn arn:aws:iam::aws:policy/IAMFullAccess 2>/dev/null || true
		aws iam delete-role --role-name "$ROLE_SOAK" 2>/dev/null || true
	fi

	if [[ -n "${U_TARGET:-}" ]]; then
		echo "  Removing IAM user ${U_TARGET}..."
		iam_delete_user_all "$U_TARGET"
	fi

	if [[ -n "${U_SOAK:-}" ]]; then
		echo "  Removing IAM user ${U_SOAK}..."
		iam_delete_user_all "$U_SOAK"
	fi

	if [[ -n "${KEY_ID:-}" ]]; then
		echo "  Canceling KMS key deletion for ${KEY_ID} (key remains — delete in console if unwanted)..."
		aws kms cancel-key-deletion --key-id "$KEY_ID" 2>/dev/null || true
	fi

	if [[ "$RECORDER_WAS_STOPPED" == "1" && -n "${RECORDER_NAME:-}" ]]; then
		echo "  Starting AWS Config recorder ${RECORDER_NAME}..."
		aws configservice start-configuration-recorder \
			--configuration-recorder-name "$RECORDER_NAME" 2>/dev/null || true
	fi

	if [[ "$SOAK_SG_INGRESS_ADDED" == "1" && -n "${SOAK_SG_ID:-}" ]]; then
		echo "  Revoking test security group ingress on ${SOAK_SG_ID}..."
		aws ec2 revoke-security-group-ingress --group-id "$SOAK_SG_ID" --protocol tcp --port 22 \
			--cidr 0.0.0.0/0 2>/dev/null || true
	fi

	if [[ -n "${SOAK_INSTANCE_ID:-}" && -n "${_SAVED_USER_DATA_B64:-}" && "${_SAVED_USER_DATA_B64}" != "None" ]]; then
		echo "  Restoring EC2 userData for ${SOAK_INSTANCE_ID}..."
		aws ec2 modify-instance-attribute --instance-id "$SOAK_INSTANCE_ID" \
			--user-data "Value=${_SAVED_USER_DATA_B64}" 2>/dev/null ||
			echo "  (warn) Could not restore instance userData — revert manually if needed."
	fi

	if [[ "$_BUCKET_EXISTS" == "1" && -n "${BUCKET:-}" ]]; then
		echo "  Removing S3 bucket ${BUCKET}..."
		s3_empty_bucket_all_versions "$BUCKET" || true
		aws s3api delete-bucket --bucket "$BUCKET" --region "$REGION" 2>/dev/null ||
			aws s3 rb "s3://${BUCKET}" --force --region "$REGION" 2>/dev/null || true
	fi

	echo ""
	echo "  Note: Irreversible by this script: deleted EBS/RDS snapshots, deleted VPC flow logs,"
	echo "  modified Lambda code (if SOAK_LAMBDA_NAME was set), and any manual-only steps."
	echo "=== Cleanup finished ==="
}

trap cleanup_soak EXIT

echo "=== iota soak: aws_cloudtrail HIGH/CRITICAL ==="
if [[ -n "${AWS_PROFILE:-}" ]]; then
	echo "AWS_PROFILE: ${AWS_PROFILE}"
fi
echo "Account: ${ACCOUNT_ID}  Region: ${REGION}  Tag: ${SOAK_TAG}"
echo ""

SAN="$(printf '%s' "$SOAK_TAG" | tr '[:upper:]' '[:lower:]')"
SAN="${SAN//[^a-z0-9-]/}"
SAN="${SAN:0:40}"
[[ -z "$SAN" ]] && SAN="soak${RANDOM}"
BUCKET="iota-soak-${ACCOUNT_ID}-${SAN}"
BUCKET="${BUCKET:0:63}"
export BUCKET REGION ACCOUNT_ID SOAK_TAG

# --- [1]–[6] S3 ---
soak_step 1 "aws_s3_bucket_public_access (HIGH) — create bucket + weaken public access block" bash -c "
  if [[ \"\$REGION\" == \"us-east-1\" ]]; then
    aws s3api create-bucket --bucket \"\$BUCKET\" --region \"\$REGION\"
  else
    aws s3api create-bucket --bucket \"\$BUCKET\" --region \"\$REGION\" \
      --create-bucket-configuration LocationConstraint=\"\$REGION\"
  fi
  aws s3api put-public-access-block --bucket \"\$BUCKET\" --public-access-block-configuration \
    BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false
" || true
if aws s3api head-bucket --bucket "$BUCKET" 2>/dev/null; then
	_BUCKET_EXISTS=1
else
	_BUCKET_EXISTS=0
fi

soak_step 2 "aws_s3_ransomware_note_upload (HIGH)" bash -c "
  echo ransomware-note-test | aws s3 cp - \"s3://\${BUCKET}/HOW_TO_DECRYPT_FILES.txt\" --region \"\${REGION}\"
" || true

soak_step 3 "aws_s3_versioning_suspended (HIGH)" \
	aws s3api put-bucket-versioning --bucket "$BUCKET" --versioning-configuration Status=Suspended || true

soak_step 4 "aws_s3_mfa_delete_disabled (HIGH)" \
	aws s3api put-bucket-versioning --bucket "$BUCKET" \
	--versioning-configuration Status=Enabled,MFADelete=Disabled || true

# Object Lock can only be toggled on buckets created with Object Lock; otherwise AWS returns
# MalformedXML / InvalidBucketState. Do not count that as a soak failure.
echo "[5] aws_s3_object_lock_disabled (HIGH) — PutObjectLockConfiguration"
OL_ERR="$(mktemp)"
set +e
aws s3api put-object-lock-configuration --bucket "$BUCKET" \
	--object-lock-configuration '{"ObjectLockEnabled":"Disabled"}' >"$OL_ERR" 2>&1
OL_EC=$?
set -e
if [[ "$OL_EC" -eq 0 ]]; then
	echo "  status: SUCCESS"
	rm -f "$OL_ERR"
else
	reason="$(tr '\n' ' ' <"$OL_ERR" | head -c 500)"
	rm -f "$OL_ERR"
	if echo "$reason" | grep -qE 'MalformedXML|InvalidBucketState|ObjectLockConfigurationNotFound|not supported'; then
		echo "  status: SKIPPED — bucket was not created with Object Lock (PutObjectLockConfiguration not applicable in this soak path)"
	else
		echo "  status: FAILURE (exit ${OL_EC})"
		echo "  reason: ${reason}"
		FAILURES=$((FAILURES + 1))
	fi
fi

soak_step 6 "aws_s3_public_access_block_deleted (HIGH)" \
	aws s3api delete-public-access-block --bucket "$BUCKET" || true

# --- [7]–[8] IAM users ---
U_SOAK="${SOAK_TAG:0:32}"
U_TARGET="${U_SOAK}-tgt"
export U_SOAK U_TARGET

soak_step 7 "aws_iam_attach_admin_user_policy (HIGH)" bash -c "
  aws iam create-user --user-name \"\$U_SOAK\"
  aws iam attach-user-policy --user-name \"\$U_SOAK\" \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
" || true

soak_step 8 "aws_iam_user_key_created (HIGH)" bash -c "
  aws iam create-user --user-name \"\$U_TARGET\"
  aws iam create-access-key --user-name \"\$U_TARGET\"
" || true

# --- [9] Config ---
RECORDER_NAME="$(aws configservice describe-configuration-recorders --query 'ConfigurationRecorders[0].name' --output text 2>/dev/null || echo "")"
if [[ -n "$RECORDER_NAME" && "$RECORDER_NAME" != "None" ]]; then
	if soak_step 9 "aws_config_service_disabled (HIGH)" \
		aws configservice stop-configuration-recorder --configuration-recorder-name "$RECORDER_NAME"; then
		RECORDER_WAS_STOPPED=1
	fi
else
	soak_skip 9 "aws_config_service_disabled (HIGH)" "no configuration recorder in this account/region"
fi

# --- [10] GuardDuty ---
DET_ID="$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text 2>/dev/null || echo "")"
export DET_ID
if [[ -n "$DET_ID" && "$DET_ID" != "None" ]]; then
	soak_step 10 "aws_guardduty_disabled (HIGH) — toggle off then on" bash -c "
    aws guardduty update-detector --detector-id \"\$DET_ID\" --no-enable
    aws guardduty update-detector --detector-id \"\$DET_ID\" --enable
  " || true
else
	soak_skip 10 "aws_guardduty_disabled (HIGH)" "no detector in this region"
fi

# --- [11] KMS ---
if KEY_ID="$(aws kms create-key --description "iota soak ${SOAK_TAG}" --query KeyMetadata.KeyId --output text 2>/dev/null)"; then
	soak_step 11 "aws_kms_key_disabled_or_scheduled_deletion (HIGH)" \
		aws kms schedule-key-deletion --key-id "$KEY_ID" --pending-window-in-days 7 || true
else
	soak_skip 11 "aws_kms_key_disabled_or_scheduled_deletion (HIGH)" "create-key failed"
	KEY_ID=""
fi

# --- [12] CloudTrail ---
export SOAK_TRAIL_NAME="${SOAK_TRAIL_NAME:-}"
if [[ -n "${SOAK_TRAIL_NAME:-}" ]]; then
	soak_step 12 "aws_cloudtrail_stopped (HIGH)" bash -c "
    aws cloudtrail stop-logging --name \"\$SOAK_TRAIL_NAME\"
    aws cloudtrail start-logging --name \"\$SOAK_TRAIL_NAME\"
  " || true
else
	soak_skip 12 "aws_cloudtrail_stopped (HIGH)" "SOAK_TRAIL_NAME not set"
fi

# --- [13] Flow logs ---
if [[ -n "${SOAK_FLOW_LOG_ID:-}" ]]; then
	soak_step 13 "aws_vpc_flow_logs_disabled (HIGH)" \
		aws ec2 delete-flow-logs --flow-log-ids "$SOAK_FLOW_LOG_ID" || true
	echo "  note: Flow log was deleted — recreate manually if needed."
else
	soak_skip 13 "aws_vpc_flow_logs_disabled (HIGH)" "SOAK_FLOW_LOG_ID not set"
fi

# --- [14] SG ---
if [[ -n "${SOAK_SG_ID:-}" ]]; then
	if soak_step 14 "aws_ec2_security_group_modified (HIGH)" \
		aws ec2 authorize-security-group-ingress --group-id "$SOAK_SG_ID" --protocol tcp --port 22 --cidr 0.0.0.0/0; then
		SOAK_SG_INGRESS_ADDED=1
	fi
else
	soak_skip 14 "aws_ec2_security_group_modified (HIGH)" "SOAK_SG_ID not set"
fi

# --- [15]–[16] EC2 user data ---
export SOAK_INSTANCE_ID="${SOAK_INSTANCE_ID:-}"
if [[ -n "${SOAK_INSTANCE_ID:-}" ]]; then
	_SAVED_USER_DATA_B64="$(aws ec2 describe-instance-attribute --instance-id "$SOAK_INSTANCE_ID" --attribute userData \
		--query 'UserData.Value' --output text 2>/dev/null || echo "")"
	soak_step 15 "aws_ec2_download_instance_user_data + startup_script_changed (HIGH)" bash -c "
    aws ec2 describe-instance-attribute --instance-id \"\$SOAK_INSTANCE_ID\" --attribute userData
    aws ec2 modify-instance-attribute --instance-id \"\$SOAK_INSTANCE_ID\" \
      --user-data Value=\$(echo -n '# iota soak' | base64)
  " || true
else
	soak_skip 15 "EC2 user data / startup script (HIGH)" "SOAK_INSTANCE_ID not set"
fi

# --- [17] SSM ---
if [[ -n "${SOAK_INSTANCE_ID:-}" ]]; then
	soak_step 17 "aws_ssm_send_command (HIGH)" \
		aws ssm send-command --instance-ids "$SOAK_INSTANCE_ID" \
		--document-name AWS-RunShellScript \
		--parameters commands="echo iota-soak" --comment "iota soak" || true
else
	soak_skip 17 "aws_ssm_send_command (HIGH)" "SOAK_INSTANCE_ID not set"
fi

# --- [18] Lambda ---
if [[ -n "${SOAK_LAMBDA_NAME:-}" ]]; then
	LDIR="$(mktemp -d)"
	TMPZIP="$(mktemp /tmp/iota-soak-lambda.XXXXXX.zip)"
	printf '%s\n' 'def lambda_handler(e,c): return {}' >"${LDIR}/lambda_soak.py"
	(cd "$LDIR" && zip -q "$TMPZIP" lambda_soak.py)
	rm -rf "$LDIR"
	soak_step 18 "aws_lambda_function_modified + lambda_update_code_interactive_identity (HIGH)" \
		aws lambda update-function-code --function-name "$SOAK_LAMBDA_NAME" --zip-file "fileb://${TMPZIP}" || true
	rm -f "$TMPZIP"
	echo "  note: Lambda code was replaced — redeploy prior version manually if needed."
else
	soak_skip 18 "Lambda code update (HIGH)" "SOAK_LAMBDA_NAME not set"
fi

# --- [19]–[22] Snapshots / RDS ---
if [[ -n "${SOAK_SNAPSHOT_ID:-}" ]]; then
	soak_step 19 "aws_ebs_snapshot_deleted (HIGH)" aws ec2 delete-snapshot --snapshot-id "$SOAK_SNAPSHOT_ID" || true
else
	soak_skip 19 "aws_ebs_snapshot_deleted (HIGH)" "SOAK_SNAPSHOT_ID not set"
fi

export SOAK_SNAPSHOT_ID_2="${SOAK_SNAPSHOT_ID_2:-}"
if [[ -n "${SOAK_SNAPSHOT_ID_2:-}" ]]; then
	soak_step 20 "aws_ec2_snapshot_made_public (CRITICAL)" bash -c "
    aws ec2 modify-snapshot-attribute --snapshot-id \"\$SOAK_SNAPSHOT_ID_2\" \
      --attribute createVolumePermission --operation-type add --group-names all
    aws ec2 modify-snapshot-attribute --snapshot-id \"\$SOAK_SNAPSHOT_ID_2\" \
      --attribute createVolumePermission --operation-type remove --group-names all
  " || true
else
	soak_skip 20 "aws_ec2_snapshot_made_public (CRITICAL)" "SOAK_SNAPSHOT_ID_2 not set"
fi

if [[ -n "${SOAK_RDS_SNAPSHOT:-}" ]]; then
	soak_step 21 "aws_rds_snapshot_deleted (HIGH)" \
		aws rds delete-db-snapshot --db-snapshot-identifier "$SOAK_RDS_SNAPSHOT" || true
else
	soak_skip 21 "aws_rds_snapshot_deleted (HIGH)" "SOAK_RDS_SNAPSHOT not set"
fi

export SOAK_RDS_SNAPSHOT_2="${SOAK_RDS_SNAPSHOT_2:-}"
if [[ -n "${SOAK_RDS_SNAPSHOT_2:-}" ]]; then
	soak_step 22 "aws_rds_snapshot_shared_publicly (CRITICAL)" bash -c "
    aws rds modify-db-snapshot-attribute --db-snapshot-identifier \"\$SOAK_RDS_SNAPSHOT_2\" \
      --attribute-name restore --values-to-add all
    aws rds modify-db-snapshot-attribute --db-snapshot-identifier \"\$SOAK_RDS_SNAPSHOT_2\" \
      --attribute-name restore --values-to-remove all
  " || true
else
	soak_skip 22 "aws_rds_snapshot_shared_publicly (CRITICAL)" "SOAK_RDS_SNAPSHOT_2 not set"
fi

# --- [23] Delete bucket (triggers rule). Versioning/MFA steps leave versions — empty all before DeleteBucket.
if [[ "$_BUCKET_EXISTS" == "1" ]]; then
	echo "[23] aws_s3_bucket_deleted (HIGH)"
	B23_ERR="$(mktemp)"
	set +e
	s3_empty_bucket_all_versions "$BUCKET"
	aws s3api delete-bucket --bucket "$BUCKET" --region "$REGION" >"$B23_ERR" 2>&1
	B23_EC=$?
	if [[ "$B23_EC" -ne 0 ]]; then
		aws s3 rb "s3://${BUCKET}" --force --region "$REGION" >>"$B23_ERR" 2>&1
		B23_EC=$?
	fi
	set -e
	if [[ "$B23_EC" -eq 0 ]]; then
		echo "  status: SUCCESS"
		_BUCKET_EXISTS=0
	else
		reason="$(tr '\n' ' ' <"$B23_ERR" | head -c 900)"
		echo "  status: FAILURE (exit ${B23_EC})"
		echo "  reason: ${reason}"
		FAILURES=$((FAILURES + 1))
	fi
	rm -f "$B23_ERR"
fi

# --- [24] IAM backdoor ---
TRUST="$(mktemp)"
cat >"$TRUST" <<EOF
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::${ACCOUNT_ID}:root"},"Action":"sts:AssumeRole"}]}
EOF
ROLE_SOAK="${SOAK_TAG:0:60}"
U_BACKDOOR="${U_SOAK}-bd"
export ROLE_SOAK TRUST

assume_role_with_retry() {
	local arn="$1" out
	local _
	for _ in $(seq 1 30); do
		out="$(aws sts assume-role --role-arn "$arn" --role-session-name iota-soak --output json 2>/dev/null)" || {
			sleep 2
			continue
		}
		echo "$out"
		return 0
	done
	echo "assume-role failed after retries" >&2
	return 1
}

if soak_step 24a "aws_iam_backdoor_users (HIGH) — create role" bash -c "
  aws iam create-role --role-name \"\$ROLE_SOAK\" --assume-role-policy-document \"file://\$TRUST\"
  aws iam attach-role-policy --role-name \"\$ROLE_SOAK\" --policy-arn arn:aws:iam::aws:policy/IAMFullAccess
"; then
	CREDS_JSON="$(assume_role_with_retry "arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_SOAK}")" || CREDS_JSON=""
	if [[ -n "$CREDS_JSON" ]]; then
		AWS_ACCESS_KEY_ID="$(echo "$CREDS_JSON" | jq -r '.Credentials.AccessKeyId')"
		export AWS_ACCESS_KEY_ID
		AWS_SECRET_ACCESS_KEY="$(echo "$CREDS_JSON" | jq -r '.Credentials.SecretAccessKey')"
		export AWS_SECRET_ACCESS_KEY
		AWS_SESSION_TOKEN="$(echo "$CREDS_JSON" | jq -r '.Credentials.SessionToken')"
		export AWS_SESSION_TOKEN
		soak_step 24b "aws_iam_backdoor_users (HIGH) — CreateUser as AssumedRole" \
			aws iam create-user --user-name "$U_BACKDOOR" || true
		if [[ -n "${_SAVED_AKI:-}" ]]; then export AWS_ACCESS_KEY_ID="$_SAVED_AKI"; else unset AWS_ACCESS_KEY_ID; fi
		if [[ -n "${_SAVED_ASK:-}" ]]; then export AWS_SECRET_ACCESS_KEY="$_SAVED_ASK"; else unset AWS_SECRET_ACCESS_KEY; fi
		if [[ -n "${_SAVED_ST:-}" ]]; then export AWS_SESSION_TOKEN="$_SAVED_ST"; else unset AWS_SESSION_TOKEN; fi
	else
		echo "[24b] aws_iam_backdoor_users — CreateUser as AssumedRole"
		echo "  status: FAILURE — could not assume role (IAM propagation)"
		FAILURES=$((FAILURES + 1))
	fi
else
	echo "  note: Role creation failed; skipping assume-role / CreateUser."
fi
rm -f "$TRUST"

soak_skip 25 "aws_s3_cross_account_copy (HIGH)" "requires second account — run CopyObject manually"

soak_skip 26 "aws_console_root_login (CRITICAL)" "manual console sign-in as root only"

soak_skip 27 "aws_root_access_key_created (CRITICAL)" "do not automate root access keys"

echo ""
echo "=== soak steps finished (failures in API steps: ${FAILURES}) ==="
# trap EXIT runs cleanup_soak before the process exits

if [[ "$FAILURES" -gt 0 ]]; then
	exit 1
fi
exit 0
