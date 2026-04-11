import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from gcp_helpers import gcp_alert_context


def rule(event):
    enum_iam_tags = [
        "GetIamPolicy",
        "TagKeys.ListTagKeys",
        "TagKeys.ListTagValues",
        "TagBindings.ListEffectiveTags",
    ]

    method_name = deep_get(event, "protoPayload", "methodName", default="")
    return any(tag in method_name for tag in enum_iam_tags)


def title(event):
    principal = deep_get(
        event,
        "protoPayload",
        "authenticationInfo",
        "principalEmail",
        default="<UNKNOWN>",
    )
    method = deep_get(event, "protoPayload", "methodName", default="<UNKNOWN>")
    return f"GCP IAM and Tag Enumeration by {principal} - {method}"


def alert_context(event):
    return gcp_alert_context(event)
