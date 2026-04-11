import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from kubernetes_helpers import k8s_udm
from kubernetes_helpers import (
    get_pod_context_fields,
    get_pod_name,
    is_failed_request,
    is_system_namespace,
    is_system_principal,
    k8s_alert_context,
)


def rule(event):
    verb = k8s_udm(event, "verb")
    resource = k8s_udm(event, "resource")
    namespace = k8s_udm(event, "namespace")
    username = k8s_udm(event, "username")
    response_status = k8s_udm(event, "responseStatus")

    # Only check pod creation events
    if verb != "create" or resource != "pods":
        return False

    # Skip failed requests
    if is_failed_request(response_status):
        return False

    # Exclude system principals creating pods in system namespaces (legitimate)
    # but alert on system principals in user namespaces (malicious Deployments)
    # and alert on user-created pods in system namespaces (suspicious)
    if is_system_principal(username) and is_system_namespace(namespace):
        return False

    # Check if hostIPC is enabled
    host_ipc = k8s_udm(event, "hostIPC")
    if host_ipc is True:
        return True

    return False


def title(event):
    username = k8s_udm(event, "username") or "<UNKNOWN_USER>"
    namespace = k8s_udm(event, "namespace") or "<UNKNOWN_NAMESPACE>"
    name = get_pod_name(event)

    return f"[{username}] created pod [{namespace}/{name}] with host IPC enabled "


def dedup(event):
    username = k8s_udm(event, "username") or "<UNKNOWN_USER>"
    namespace = k8s_udm(event, "namespace") or "<UNKNOWN_NAMESPACE>"
    return f"k8s_host_ipc_{username}_{namespace}"


def alert_context(event):
    return k8s_alert_context(event, extra_fields=get_pod_context_fields(event))
