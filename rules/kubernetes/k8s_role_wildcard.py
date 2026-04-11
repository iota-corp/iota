import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from kubernetes_helpers import k8s_udm
from kubernetes_helpers import is_failed_request, is_system_principal, k8s_alert_context


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

    # Exclude system principals to reduce false positives from legitimate operators
    if is_system_principal(username):
        return False

    # Check if role grants wildcard permissions
    request_object = k8s_udm(event, "requestObject") or {}
    rules = request_object.get("rules") or []

    for rule_entry in rules:
        resources = rule_entry.get("resources") or []
        verbs = rule_entry.get("verbs") or []

        # Check for wildcard in resources or verbs
        if "*" in resources or "*" in verbs:
            return True

    return False


def title(event):
    username = k8s_udm(event, "username") or "<UNKNOWN_USER>"
    resource = k8s_udm(event, "resource") or "<UNKNOWN_RESOURCE>"
    name = k8s_udm(event, "name") or "<UNKNOWN_ROLE>"
    namespace = k8s_udm(event, "namespace") or "<CLUSTER_SCOPED>"

    role_type = "ClusterRole" if resource == "clusterroles" else "Role"

    if namespace != "<CLUSTER_SCOPED>":
        return f"[{username}] created {role_type} [{namespace}/{name}] with wildcard permissions"

    return f"[{username}] created {role_type} [{name}] with wildcard permissions "


def dedup(event):
    username = k8s_udm(event, "username") or "<UNKNOWN_USER>"
    resource = k8s_udm(event, "resource") or "<UNKNOWN_RESOURCE>"
    name = k8s_udm(event, "name") or "<UNKNOWN_ROLE>"
    return f"k8s_role_wildcard_{username}_{resource}_{name}"


def severity(event):
    """ClusterRoles with wildcards are more dangerous than namespaced Roles."""
    resource = k8s_udm(event, "resource") or ""

    # Critical for ClusterRole (cluster-wide wildcard permissions)
    if resource == "clusterroles":
        return "CRITICAL"

    # High for namespaced Role (namespace-scoped wildcard permissions)
    return "HIGH"


def alert_context(event):
    request_object = k8s_udm(event, "requestObject") or {}
    rules = request_object.get("rules") or []

    # Extract only the rules that contain wildcards
    wildcard_rules = []
    for rule_entry in rules:
        resources = rule_entry.get("resources") or []
        verbs = rule_entry.get("verbs") or []
        if "*" in resources or "*" in verbs:
            wildcard_rules.append(rule_entry)

    return k8s_alert_context(
        event,
        extra_fields={
            "role_name": k8s_udm(event, "name"),
            "role_type": k8s_udm(event, "resource"),
            "wildcard_rules": wildcard_rules,
        },
    )
