import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from gcp_helpers import gcp_alert_context


def rule(event):
    methods = (
        "dns.changes.create",
        "dns.managedZones.delete",
        "dns.managedZones.patch",
        "dns.managedZones.update",
    )
    return deep_get(event, "protoPayload", "methodName", default="") in methods


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
    return f"[GCP]: [{actor}] modified managed DNS zone [{resource}]"


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
