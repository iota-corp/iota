import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from gcp_helpers import gcp_alert_context

RULE_MODIFIED_PARTS = [
    ".Firewall.Update",
    ".compute.firewalls.patch",
    ".compute.firewalls.update",
]


def rule(event):
    method = deep_get(event, "protoPayload", "methodName", default="")
    return any(part in method for part in RULE_MODIFIED_PARTS)


def title(event):
    actor = deep_get(
        event,
        "protoPayload",
        "authenticationInfo",
        "principalEmail",
        default="<ACTOR_NOT_FOUND>",
    )
    resource = deep_get(
        event, "protoPayload", "resourceName", default="<RESOURCE_NOT_FOUND>"
    )
    return f"[GCP]: [{actor}] modified firewall rule on [{resource}]"


def dedup(event):
    actor = deep_get(
        event,
        "protoPayload",
        "authenticationInfo",
        "principalEmail",
        default="<ACTOR_NOT_FOUND>",
    )
    return actor


def alert_context(event):
    return gcp_alert_context(event)
