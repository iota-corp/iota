import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_walk
from gcp_helpers import gcp_alert_context


def rule(event):
    reason = deep_walk(event, "protoPayload", "status", "details", "reason", default="")
    return reason == "IAM_PERMISSION_DENIED"


def title(event):
    actor = deep_walk(
        event,
        "protoPayload",
        "authenticationInfo",
        "principalEmail",
        default="<ACTOR_NOT_FOUND>",
    )
    return f"[GCP]: [{actor}] performed multiple requests resulting in [IAM_PERMISSION_DENIED]"


def alert_context(event):
    return gcp_alert_context(event)
