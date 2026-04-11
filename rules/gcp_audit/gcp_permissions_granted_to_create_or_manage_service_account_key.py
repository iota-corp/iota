import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, deep_walk

SERVICE_ACCOUNT_MANAGE_ROLES = [
    "roles/iam.serviceAccountTokenCreator",
    "roles/iam.serviceAccountUser",
]


def rule(event):
    if "SetIAMPolicy" in deep_get(event, "protoPayload", "methodName", default=""):
        role = deep_walk(
            event,
            "protoPayload",
            "serviceData",
            "policyDelta",
            "bindingDeltas",
            "role",
            default="",
            return_val="last",
        )
        action = deep_walk(
            event,
            "protoPayload",
            "serviceData",
            "policyDelta",
            "bindingDeltas",
            "action",
            default="",
            return_val="last",
        )
        return role in SERVICE_ACCOUNT_MANAGE_ROLES and action == "ADD"
    return False


def title(event):
    actor = deep_get(
        event,
        "protoPayload",
        "authenticationInfo",
        "principalEmail",
        default="<ACTOR_NOT_FOUND>",
    )
    target = deep_get(event, "resource", "labels", "email_id") or deep_get(
        event, "resource", "labels", "project_id", default="<TARGET_NOT_FOUND>"
    )
    return f"GCP: [{actor}] granted permissions to create or manage service account keys to [{target}]"


def alert_context(event):
    return {
        "resource": event.get("resource"),
        "serviceData": deep_get(event, "protoPayload", "serviceData"),
    }
