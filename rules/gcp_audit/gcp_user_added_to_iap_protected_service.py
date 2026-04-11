import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get


def rule(event):
    return (
        deep_get(event, "protoPayload", "methodName", default="")
        == "google.cloud.iap.v1.IdentityAwareProxyAdminService.SetIamPolicy"
    )


def title(event):
    actor = deep_get(
        event,
        "protoPayload",
        "authenticationInfo",
        "principalEmail",
        default="<ACTOR_NOT_FOUND>",
    )
    service = deep_get(
        event, "protoPayload", "request", "resource", default="<RESOURCE_NOT_FOUND>"
    )
    return f"GCP: [{actor}] modified user access to IAP Protected Service [{service}]"


def alert_context(event):
    bindings = deep_get(
        event, "protoPayload", "request", "policy", "bindings", default=[{}]
    )

    return {"bindings": bindings}
