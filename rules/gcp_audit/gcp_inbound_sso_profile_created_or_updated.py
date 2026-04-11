import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, deep_walk

METHODS = [
    "google.admin.AdminService.inboundSsoProfileCreated",
    "google.admin.AdminService.inboundSsoProfileUpdated",
]


def rule(event):
    return deep_get(event, "protoPayload", "methodName", default="") in METHODS


def title(event):
    actor = deep_get(
        event,
        "protoPayload",
        "authenticationInfo",
        "principalEmail",
        default="<ACTOR_NOT_FOUND>",
    )
    event_name = deep_walk(
        event,
        "protoPayload",
        "metadata",
        "event",
        "eventName",
        default="<EVENT_NAME_NOT_FOUND>",
    )

    resource = organization_id = deep_walk(
        event, "protoPayload", "resourceName", default="<RESOURCE_NOT_FOUND>"
    ).split("/")

    organization_id = resource[resource.index("organizations") + 1]

    return f"GCP: [{actor}] performed {event_name} in organization {organization_id}"


def alert_context(event):
    return {
        "resourceName": deep_get(
            event, "protoPayload", "resourceName", default="<RESOURCE_NOT_FOUND>"
        ),
        "serviceName": deep_get(
            event, "protoPayload", "serviceName", default="<SERVICE_NOT_FOUND>"
        ),
    }
