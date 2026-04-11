import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from kubernetes_helpers import k8s_udm
from kubernetes_helpers import (
    get_hostpath_paths,
    get_pod_context_fields,
    get_pod_name,
    has_hostpath_volume,
    is_failed_request,
    is_sensitive_hostpath,
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

    # Check for hostPath volumes
    volumes = k8s_udm(event, "volumes") or []
    if has_hostpath_volume(volumes):
        return True

    return False


def severity(event):
    volumes = k8s_udm(event, "volumes") or []
    paths = get_hostpath_paths(volumes)

    for path in paths:
        if is_sensitive_hostpath(path):
            return "HIGH"

    return "MEDIUM"


def title(event):
    username = k8s_udm(event, "username") or "<UNKNOWN_USER>"
    namespace = k8s_udm(event, "namespace") or "<UNKNOWN_NAMESPACE>"
    name = get_pod_name(event)

    volumes = k8s_udm(event, "volumes") or []
    paths = get_hostpath_paths(volumes)
    paths_str = ", ".join(paths) if paths else "unknown"

    return (
        f"[{username}] created pod [{namespace}/{name}] with hostPath volume mount "
        f"[{paths_str}]"
    )


def dedup(event):
    username = k8s_udm(event, "username") or "<UNKNOWN_USER>"
    namespace = k8s_udm(event, "namespace") or "<UNKNOWN_NAMESPACE>"
    return f"hostpath_volume_{username}_{namespace}"


def alert_context(event):
    volumes = k8s_udm(event, "volumes") or []
    pod_context = get_pod_context_fields(event)

    return k8s_alert_context(
        event,
        extra_fields={
            **pod_context,
            "hostpath_paths": get_hostpath_paths(volumes),
        },
    )
