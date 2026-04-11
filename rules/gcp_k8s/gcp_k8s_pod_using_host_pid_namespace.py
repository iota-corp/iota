import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from gcp_helpers import (
    gcp_alert_context,
    is_gke_system_namespace,
    is_gke_system_principal,
)

METHODS_TO_CHECK = [
    "io.k8s.core.v1.pods.create",
    "io.k8s.core.v1.pods.update",
    "io.k8s.core.v1.pods.patch",
]


def rule(event):
    method = deep_get(event, "protoPayload", "methodName")
    request_host_pid = deep_get(event, "protoPayload", "request", "spec", "hostPID")
    response_host_pid = deep_get(event, "protoPayload", "response", "spec", "hostPID")
    if not (
        (request_host_pid is True or response_host_pid is True)
        and method in METHODS_TO_CHECK
    ):
        return False

    # Check if this is a known GKE system service account
    principal_email = deep_get(
        event, "protoPayload", "authenticationInfo", "principalEmail", default=""
    )
    if is_gke_system_principal(principal_email):
        return False

    # Check if this is in a system namespace
    resource_name = deep_get(event, "protoPayload", "resourceName", default="")
    if is_gke_system_namespace(resource_name):
        return False

    return True


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

    return (
        f"[GCP]: [{actor}] created or modified pod using the host PID namespace "
        f"in project [{project_id}]"
    )


def alert_context(event):
    return gcp_alert_context(event)
