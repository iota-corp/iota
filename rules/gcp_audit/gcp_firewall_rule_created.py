import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from gcp_helpers import gcp_alert_context

RULE_CREATED_PARTS = [
    ".Firewall.Create",
    ".compute.firewalls.insert",
]


def rule(event):
    method = deep_get(event, "protoPayload", "methodName", default="")
    return any(part in method for part in RULE_CREATED_PARTS)


def title(event):
    actor = deep_get(
        event,
        "protoPayload",
        "authenticationInfo",
        "principalEmail",
        default="<ACTOR_NOT_FOUND>",
    )
    resource = deep_get(
        event,
        "protoPayload",
        "resourceName",
        default="<RESOURCE_NOT_FOUND>",
    )
    resource_id = deep_get(
        event,
        "resource",
        "labels",
        "firewall_rule_id",
        default="<RESOURCE_ID_NOT_FOUND>",
    )
    if resource_id != "<RESOURCE_ID_NOT_FOUND>":
        return (
            f"[GCP]: [{actor}] created firewall rule with resource ID [{resource_id}]"
        )
    return f"[GCP]: [{actor}] created firewall rule for resource [{resource}]"


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
