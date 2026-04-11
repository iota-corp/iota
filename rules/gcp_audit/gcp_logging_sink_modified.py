import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
import re

from iota_helpers import deep_get
from gcp_helpers import gcp_alert_context


def rule(event):
    method_pattern = r"(?:\w+\.)*v\d\.(?:ConfigServiceV\d\.(?:UpdateSink))"
    match = re.search(
        method_pattern, deep_get(event, "protoPayload", "methodName", default="")
    )
    return match is not None


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
    return f"[GCP]: [{actor}] updated logging sink [{resource}]"


def alert_context(event):
    return gcp_alert_context(event)
