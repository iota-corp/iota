import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, deep_walk
from gcp_helpers import gcp_alert_context


def rule(event):
    if event.get("severity") == "ERROR":
        return False

    method_name = deep_get(event, "protoPayload", "methodName", default="")
    if not method_name.endswith("Services.CreateService"):
        return False

    authorization_info = deep_walk(event, "protoPayload", "authorizationInfo")
    if not authorization_info:
        return False

    for auth in authorization_info:
        if (
            auth.get("permission") == "run.services.create"
            and auth.get("granted") is True
        ):
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
    project_id = deep_get(
        event, "resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>"
    )

    return f"[GCP]: [{actor}] created new Run Service in project [{project_id}]"


def alert_context(event):
    context = gcp_alert_context(event)
    context["service_account"] = deep_get(
        event,
        "protoPayload",
        "request",
        "service",
        "spec",
        "template",
        "spec",
        default="<SERVICE_ACCOUNT_NOT_FOUND>",
    )
    return context
