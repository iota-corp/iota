import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from gcp_helpers import gcp_alert_context

EXPECTED_DOMAIN = "@your-domain.tld"


def rule(event):
    if deep_get(event, "protoPayload", "response", "error"):
        return False

    method = deep_get(event, "protoPayload", "methodName", default="METHOD_NOT_FOUND")
    if method != "v1.compute.snapshots.insert":
        return False

    email = deep_get(
        event, "protoPayload", "authenticationInfo", "principalEmail", default=""
    )
    if not email.endswith(EXPECTED_DOMAIN):
        return True

    return False


def title(event):
    actor = deep_get(
        event,
        "protoPayload",
        "authenticationInfo",
        "principalEmail",
        default="<ACTOR_NOT_FOUND>",
    )
    project = deep_get(
        event, "resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>"
    )
    return (
        f"[GCP]: Unexpected domain [{actor}] created a snapshot on project [{project}]"
    )


def alert_context(event):
    return gcp_alert_context(event)
