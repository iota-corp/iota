import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from gcp_helpers import gcp_alert_context


def rule(event):
    method_name = deep_get(event, "protoPayload", "methodName", default="")
    return method_name.endswith("TagBindings.CreateTagBinding")


def title(event):
    principal = deep_get(
        event,
        "protoPayload",
        "authenticationInfo",
        "principalEmail",
        default="<UNKNOWN>",
    )
    resource = deep_get(event, "protoPayload", "resourceName", default="<UNKNOWN>")
    return f"GCP Tag Binding Creation by {principal} - {resource}"


def alert_context(event):
    return gcp_alert_context(event)
