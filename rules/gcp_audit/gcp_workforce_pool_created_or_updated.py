import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get

METHODS = [
    "google.iam.admin.v1.WorkforcePools.CreateWorkforcePool",
    "google.iam.admin.v1.WorkforcePools.UpdateWorkforcePool",
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
    workforce_pool = deep_get(
        event, "protoPayload", "request", "workforcePool", "name", default=""
    ).split("/")[-1]

    resource = organization_id = event.get("logName", "<LOG_NAME_NOT_FOUND>").split("/")

    organization_id = resource[resource.index("organizations") + 1]

    return (
        f"GCP: [{actor}] created or updated workforce pool "
        f"[{workforce_pool}] in organization [{organization_id}]"
    )


def alert_context(event):
    return deep_get(event, "protoPayload", "request", "workforcePool", default={})
