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

    # Only check role/clusterrole creation events
    if verb != "create" or resource not in {"roles", "clusterroles"}:
        return False

    # Skip failed requests
    if is_failed_request(response_status):
        return False

    # Exclude system principals to reduce false positives
    if is_system_principal(username):
        return False

    # Check request object for node/proxy permissions
    request_object = k8s_udm(event, "requestObject") or {}
    rules = request_object.get("rules") or []

    for rule_config in rules:
        resources = rule_config.get("resources") or []
        verbs = rule_config.get("verbs") or []

        # Check for nodes/proxy or nodes/* permissions
        # These allow accessing the kubelet API through the API server proxy
        if "nodes/proxy" in resources or ("nodes/*" in resources and verbs):
            return True

        # Also check for wildcard on nodes with specific verbs that enable proxy access
        if "nodes" in resources and "*" in resources:
            return True

    return False


def title(event):
    username = k8s_udm(event, "username") or "<UNKNOWN_USER>"
    resource = k8s_udm(event, "resource") or "<UNKNOWN_RESOURCE>"
    name = k8s_udm(event, "name") or "<UNKNOWN_ROLE>"

    role_type = "ClusterRole" if resource == "clusterroles" else "Role"

    return f"[{username}] created {role_type} [{name}] with node proxy permissions"


def dedup(event):
    username = k8s_udm(event, "username") or "<UNKNOWN_USER>"
    name = k8s_udm(event, "name") or "<UNKNOWN_ROLE>"
    return f"k8s_node_proxy_{username}_{name}"


def alert_context(event):
    request_object = k8s_udm(event, "requestObject") or {}
    rules = request_object.get("rules") or []

    # Extract rules with node/proxy permissions
    dangerous_rules = []
    for rule_config in rules:
        resources = rule_config.get("resources") or []
        if "nodes/proxy" in resources or "nodes/*" in resources or "nodes" in resources:
            dangerous_rules.append(rule_config)

    return k8s_alert_context(
        event,
        extra_fields={
            "role_name": k8s_udm(event, "name"),
            "role_type": k8s_udm(event, "resource"),
            "dangerous_rules": dangerous_rules,
        },
    )
