import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from gcp_helpers import gcp_alert_context


def rule(event):
    if deep_get(event, "protoPayload", "response", "error"):
        return False

    method = deep_get(event, "protoPayload", "methodName", default="METHOD_NOT_FOUND")
    if method != "InsertProjectOwnershipInvite":
        return False

    authenticated = deep_get(
        event, "protoPayload", "authenticationInfo", "principalEmail", default=""
    )
    expected_domain = authenticated.split("@")[-1]

    if deep_get(
        event, "protoPayload", "request", "member", default="MEMBER_NOT_FOUND"
    ).endswith(f"@{expected_domain}"):
        return False

    return True


def title(event):
    member = deep_get(
        event, "protoPayload", "request", "member", default="<MEMBER_NOT_FOUND>"
    )
    project = deep_get(
        event, "protoPayload", "resourceName", default="<PROJECT_NOT_FOUND>"
    )
    return (
        f"[GCP]: External user [{member}] was invited as owner to project [{project}]"
    )


def alert_context(event):
    return gcp_alert_context(event)
