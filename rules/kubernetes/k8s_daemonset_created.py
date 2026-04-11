import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from kubernetes_helpers import k8s_udm
from kubernetes_helpers import (
    is_failed_request,
    is_system_namespace,
    is_system_principal,
    k8s_alert_context,
)


def rule(event):
    verb = k8s_udm(event, "verb")
    resource = k8s_udm(event, "resource")
    response_status = k8s_udm(event, "responseStatus")
    namespace = k8s_udm(event, "namespace")
    username = k8s_udm(event, "username")

    # Check for DaemonSet create operation
    if verb == "create" and resource == "daemonsets":
        # Only alert on successful operations
        if is_failed_request(response_status):
            return False

        # Exclude system controllers creating DaemonSets in system namespaces
        if is_system_namespace(namespace) and is_system_principal(username):
            return False

        return True

    return False


def title(event):
    username = k8s_udm(event, "username") or "<UNKNOWN_USER>"
    namespace = k8s_udm(event, "namespace") or "<UNKNOWN_NAMESPACE>"
    daemonset_name = k8s_udm(event, "name") or "<UNKNOWN>"

    return f"[{username}] created DaemonSet [{namespace}/{daemonset_name}]"


def dedup(event):
    username = k8s_udm(event, "username") or "<UNKNOWN_USER>"
    namespace = k8s_udm(event, "namespace") or "<UNKNOWN_NAMESPACE>"
    return f"k8s_daemonset_{username}_{namespace}"


def alert_context(event):
    return k8s_alert_context(
        event,
        extra_fields={
            "daemonset_name": k8s_udm(event, "name"),
            "requestObject": k8s_udm(event, "requestObject"),
        },
    )
