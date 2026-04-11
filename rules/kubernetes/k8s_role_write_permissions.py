import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from kubernetes_helpers import k8s_udm
from kubernetes_helpers import is_failed_request, is_system_principal, k8s_alert_context

# Write-related verbs that modify cluster state
WRITE_VERBS = {
    "create",
    "update",
    "patch",
    "delete",
    "deletecollection",
}


def rule(event):
    verb = k8s_udm(event, "verb")
    resource = k8s_udm(event, "resource")
    username = k8s_udm(event, "username")
    response_status = k8s_udm(event, "responseStatus")

    # Only check Role/ClusterRole creation events
    if verb != "create" or resource not in {"roles", "clusterroles"}:
        return False

    # Skip failed requests
    if is_failed_request(response_status):
        return False

    # Exclude system principals to reduce noise from legitimate operators
    if is_system_principal(username):
        return False

    # Check if role grants write permissions
    request_object = k8s_udm(event, "requestObject") or {}
    rules = request_object.get("rules") or []

    for rule_entry in rules:
        verbs = rule_entry.get("verbs") or []
        # Check if any write verb is present
        if any(verb in WRITE_VERBS for verb in verbs):
            return True

    return False


def title(event):
    username = k8s_udm(event, "username") or "<UNKNOWN_USER>"
    resource = k8s_udm(event, "resource") or "<UNKNOWN_RESOURCE>"
    name = k8s_udm(event, "name") or "<UNKNOWN_ROLE>"
    namespace = k8s_udm(event, "namespace") or "<CLUSTER_SCOPED>"

    role_type = "ClusterRole" if resource == "clusterroles" else "Role"

    if namespace != "<CLUSTER_SCOPED>":
        return (
            f"[{username}] created {role_type} [{namespace}/{name}] with write "
            f"permissions"
        )

    return f"[{username}] created {role_type} [{name}] with write permissions " f""


def dedup(event):
    username = k8s_udm(event, "username") or "<UNKNOWN_USER>"
    resource = k8s_udm(event, "resource") or "<UNKNOWN_RESOURCE>"
    name = k8s_udm(event, "name") or "<UNKNOWN_ROLE>"
    return f"k8s_role_write_{username}_{resource}_{name}"


def severity(event):
    """Increase severity for dangerous combinations of write permissions."""
    request_object = k8s_udm(event, "requestObject") or {}
    rules = request_object.get("rules") or []
    resource = k8s_udm(event, "resource") or ""

    # Check for high-risk resource + write verb combinations
    for rule_entry in rules:
        resources_list = rule_entry.get("resources") or []
        verbs = rule_entry.get("verbs") or []

        # Critical: Write access to secrets or RBAC resources
        sensitive_resources = {
            "secrets",
            "clusterroles",
            "clusterrolebindings",
            "roles",
            "rolebindings",
        }
        if any(res in sensitive_resources for res in resources_list) and any(
            v in {"create", "update", "patch", "delete"} for v in verbs
        ):
            return "CRITICAL"

        # High: ClusterRole with write to pods or nodes
        if resource == "clusterroles" and any(
            res in {"pods", "nodes", "persistentvolumes"} for res in resources_list
        ):
            if any(v in {"create", "update", "patch", "delete"} for v in verbs):
                return "HIGH"

    # Medium: ClusterRole with general write permissions
    if resource == "clusterroles":
        return "MEDIUM"

    # Low: Namespaced Role with write permissions (common/expected)
    return "LOW"


def alert_context(event):
    request_object = k8s_udm(event, "requestObject") or {}
    rules = request_object.get("rules") or []

    # Extract only the rules that contain write verbs
    write_rules = []
    for rule_entry in rules:
        verbs = rule_entry.get("verbs") or []
        if any(verb in WRITE_VERBS for verb in verbs):
            write_rules.append(rule_entry)

    return k8s_alert_context(
        event,
        extra_fields={
            "role_name": k8s_udm(event, "name"),
            "role_type": k8s_udm(event, "resource"),
            "write_rules": write_rules,
        },
    )
