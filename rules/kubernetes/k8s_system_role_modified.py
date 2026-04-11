import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from kubernetes_helpers import k8s_udm
from kubernetes_helpers import is_failed_request, is_system_principal, k8s_alert_context

# System roles that are expected to change during normal operations
# Users can extend this list for their environment
ALLOWED_SYSTEM_ROLE_MODIFICATIONS = {
    "system:coredns",
    "system:managed-certificate-controller",
}


def rule(event):
    verb = k8s_udm(event, "verb")
    resource = k8s_udm(event, "resource")
    username = k8s_udm(event, "username")
    response_status = k8s_udm(event, "responseStatus")
    name = k8s_udm(event, "name") or ""

    # Only check role/clusterrole modification/deletion events
    if verb not in {"update", "patch", "delete"} or resource not in {
        "roles",
        "clusterroles",
    }:
        return False

    # Skip failed requests
    if is_failed_request(response_status):
        return False

    # Exclude system principals to reduce false positives
    if is_system_principal(username):
        return False

    # Check if role name starts with "system:" or "eks:" (EKS system roles)
    if not (name.startswith("system:") or name.startswith("eks:")):
        return False

    # Exclude roles that are expected to change
    if name in ALLOWED_SYSTEM_ROLE_MODIFICATIONS:
        return False

    return True


def title(event):
    username = k8s_udm(event, "username") or "<UNKNOWN_USER>"
    verb = k8s_udm(event, "verb") or "<UNKNOWN_VERB>"
    resource = k8s_udm(event, "resource") or "<UNKNOWN_RESOURCE>"
    name = k8s_udm(event, "name") or "<UNKNOWN_ROLE>"
    namespace = k8s_udm(event, "namespace") or "<CLUSTER_SCOPED>"

    role_type = "ClusterRole" if resource == "clusterroles" else "Role"
    action = "deleted" if verb == "delete" else "modified"

    if namespace != "<CLUSTER_SCOPED>":
        return f"[{username}] {action} system {role_type} [{namespace}/{name}]"

    return f"[{username}] {action} system {role_type} [{name}]"


def dedup(event):
    username = k8s_udm(event, "username") or "<UNKNOWN_USER>"
    name = k8s_udm(event, "name") or "<UNKNOWN_ROLE>"
    return f"k8s_system_role_{username}_{name}"


def alert_context(event):
    return k8s_alert_context(
        event,
        extra_fields={
            "role_name": k8s_udm(event, "name"),
            "role_type": k8s_udm(event, "resource"),
            "modification_type": k8s_udm(event, "verb"),
        },
    )
