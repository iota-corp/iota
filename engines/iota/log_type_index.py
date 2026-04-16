"""
Map rule packs (first directory under --rules) to canonical classifier log types.

Canonical names match internal/logprocessor getParsers() keys (e.g. AWS.CloudTrail, GitHub.Audit).
Used to skip rule modules that cannot apply to an event's log type.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, FrozenSet, Optional

# Pack name (top-level directory under rules/) -> log types this pack's rules accept.
# Unknown packs default to "all types" (no skipping) for safety.
PACK_LOG_TYPES: Dict[str, FrozenSet[str]] = {
    "aws_alb": frozenset({"AWS.ALB"}),
    "aws_bedrockmodelinvocation": frozenset({"AWS.BedrockModelInvocation"}),
    # CloudTrail management events (IAM, S3, Lambda, …) share AWS.CloudTrail as classifier output.
    "aws_cloudtrail": frozenset({"AWS.CloudTrail"}),
    "aws_iam": frozenset({"AWS.CloudTrail"}),
    "aws_s3": frozenset({"AWS.CloudTrail"}),
    "aws_vpcflow": frozenset({"AWS.VPCFlow"}),
    "cloudflare": frozenset({"Cloudflare.Firewall", "Cloudflare.HttpRequest"}),
    "gcp_audit": frozenset({"GCP.AuditLog"}),
    "gcp_http_lb": frozenset({"GCP.HTTPLoadBalancer"}),
    "gcp_k8s": frozenset({"GCP.AuditLog"}),
    "github_audit": frozenset({"GitHub.Audit"}),
    "github_webhook": frozenset({"GitHub.Webhook"}),
    "gsuite": frozenset({"GSuite.Reports"}),
    "kubernetes": frozenset({"Amazon.EKS.Audit"}),
    "okta": frozenset({"Okta.SystemLog"}),
    "onepassword": frozenset({"OnePassword.SignInAttempt"}),
    "slack_audit": frozenset({"Slack.AuditLogs"}),
}


def pack_for_rule_file(rules_dir: str, rule_path: Path) -> str:
    """First path segment under rules_dir (e.g. github_audit). Empty if not nested."""
    try:
        root = Path(rules_dir).resolve()
        rel = Path(rule_path).resolve().relative_to(root)
    except ValueError:
        return ""
    parts = rel.parts
    if not parts:
        return ""
    first = parts[0]
    if first.endswith(".py"):
        return ""
    return first


def applicable_log_types_for_pack(pack: str) -> Optional[FrozenSet[str]]:
    """
    Returns None => rule is not indexed (applies to all log types — unknown or missing pack).
    """
    if not pack:
        return None
    if pack not in PACK_LOG_TYPES:
        return None
    return PACK_LOG_TYPES[pack]


def infer_log_type_from_event(event: Dict) -> str:
    """
    Best-effort classifier when Go did not send log_types (CLI modes, legacy callers).
    Prefer matching internal/logprocessor parser outputs.
    """
    if not isinstance(event, dict):
        return "AWS.CloudTrail"

    hint = event.get("p_log_type")
    if isinstance(hint, str) and hint:
        return hint

    es = event.get("eventSource") or ""
    if es == "okta.com":
        return "Okta.SystemLog"
    if es == "gsuite.google.com":
        return "GSuite.Reports"
    if es == "1password.com":
        return "OnePassword.SignInAttempt"
    if es == "github.com.webhook":
        return "GitHub.Webhook"
    if es == "github.com":
        return "GitHub.Audit"
    if es == "loadbalancing.googleapis.com":
        return "GCP.HTTPLoadBalancer"
    if es == "cloudaudit.googleapis.com":
        return "GCP.AuditLog"
    if es == "eks.amazonaws.com":
        return "Amazon.EKS.Audit"
    if es == "cloudflare.com.http_request":
        return "Cloudflare.HttpRequest"
    if es == "cloudflare.com.firewall":
        return "Cloudflare.Firewall"
    if es == "slack.com":
        return "Slack.AuditLogs"
    if event.get("operation") in ("InvokeModel", "Converse") and event.get("modelId"):
        return "AWS.BedrockModelInvocation"

    en = event.get("eventName") or ""
    if es == "vpcflowlogs.amazonaws.com" or en == "VPCFlow":
        return "AWS.VPCFlow"
    if (
        es == "elasticloadbalancing.amazonaws.com"
        and isinstance(en, str)
        and en.startswith("ALB")
    ):
        return "AWS.ALB"

    # Default AWS API management events delivered as CloudTrail records (S3 file or EventBridge).
    if isinstance(es, str) and es.endswith(".amazonaws.com"):
        return "AWS.CloudTrail"

    return "AWS.CloudTrail"
