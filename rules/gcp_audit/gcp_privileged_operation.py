import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from gcp_helpers import gcp_alert_context

PRIVILEGED_OPERATIONS = [
    "iam.serviceAccounts.getAccessToken",
    "orgpolicy.policy.set",
    "storage.hmacKeys.create",
    "serviceusage.apiKeys.create",
    "serviceusage.apiKeys.list",
]


def rule(event):
    method_name = deep_get(event, "protoPayload", "methodName", default="")
    return (
        method_name.endswith("setIamPolicy")
        or method_name.endswith("setIamPermissions")
        or method_name in PRIVILEGED_OPERATIONS
    )


def title(event):
    principal = deep_get(
        event,
        "protoPayload",
        "authenticationInfo",
        "principalEmail",
        default="<UNKNOWN>",
    )
    method = deep_get(event, "protoPayload", "methodName", default="<UNKNOWN>")
    return f"GCP Privileged Operation by {principal} - {method}"


def alert_context(event):
    return gcp_alert_context(event)
