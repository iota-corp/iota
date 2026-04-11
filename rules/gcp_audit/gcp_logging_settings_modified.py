import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get


def rule(event):
    return all(
        [
            deep_get(event, "protoPayload", "serviceName", default="")
            == "logging.googleapis.com",
            "Update" in deep_get(event, "protoPayload", "methodName", default=""),
        ]
    )


def title(event):
    resource = deep_get(
        event, "protoPayload", "resourceName", default="<RESOURCE_NOT_FOUND>"
    )
    actor = deep_get(
        event,
        "protoPayload",
        "authenticationInfo",
        "principalEmail",
        default="<ACTOR_NOT_FOUND>",
    )
    return f"GCP [{resource}] logging settings modified by [{actor}]."


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
    return {
        "resource": deep_get(
            event, "protoPayload", "resourceName", default="<RESOURCE_NOT_FOUND>"
        ),
        "actor": deep_get(
            event,
            "protoPayload",
            "authenticationInfo",
            "principalEmail",
            default="<ACTOR_NOT_FOUND>",
        ),
        "method": deep_get(
            event, "protoPayload", "methodName", default="<METHOD_NOT_FOUND>"
        ),
    }
