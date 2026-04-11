import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from kubernetes_helpers import k8s_udm
from kubernetes_helpers import (
    get_pod_context_fields,
    get_pod_name,
    is_failed_request,
    is_system_namespace,
    is_system_principal,
    k8s_alert_context,
)

# Dangerous Linux capabilities that enable privilege escalation or container escape
DANGEROUS_CAPABILITIES = {
    "SYS_ADMIN",  # Most powerful
    "NET_ADMIN",  # Network manipulation
    "BPF",  # eBPF programs
    "SYS_PTRACE",  # Process tracing
    "SYS_MODULE",  # Load kernel modules
    "DAC_READ_SEARCH",  # Bypass file read permission checks
    "DAC_OVERRIDE",  # Bypass file permission checks
}


def has_dangerous_capabilities(containers):
    """Check if any container has dangerous Linux capabilities."""
    if not containers:
        return []

    dangerous_caps_found = []

    for container in containers:
        added_caps = deep_get(
            container, "securityContext", "capabilities", "add", default=[]
        )

        if added_caps:
            # Check for intersection with dangerous capabilities
            dangerous = set(added_caps) & DANGEROUS_CAPABILITIES
            if dangerous:
                dangerous_caps_found.extend(list(dangerous))

    return dangerous_caps_found


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

    # Exclude system namespaces and system principals to reduce false positives
    if is_system_namespace(namespace) or is_system_principal(username):
        return False

    # Check for dangerous capabilities
    containers = k8s_udm(event, "containers") or []
    dangerous_caps = has_dangerous_capabilities(containers)

    if dangerous_caps:
        return True

    return False


def title(event):
    username = k8s_udm(event, "username") or "<UNKNOWN_USER>"
    namespace = k8s_udm(event, "namespace") or "<UNKNOWN_NAMESPACE>"
    name = get_pod_name(event)

    containers = k8s_udm(event, "containers") or []
    dangerous_caps = has_dangerous_capabilities(containers)
    caps_str = ", ".join(sorted(set(dangerous_caps)))

    return (
        f"[{username}] created pod [{namespace}/{name}] with dangerous capabilities "
        f"[{caps_str}]"
    )


def dedup(event):
    username = k8s_udm(event, "username") or "<UNKNOWN_USER>"
    namespace = k8s_udm(event, "namespace") or "<UNKNOWN_NAMESPACE>"
    return f"k8s_dangerous_caps_{username}_{namespace}"


def alert_context(event):
    containers = k8s_udm(event, "containers") or []
    dangerous_caps = has_dangerous_capabilities(containers)

    context_fields = get_pod_context_fields(event)
    context_fields["dangerous_capabilities"] = sorted(set(dangerous_caps))
    return k8s_alert_context(event, extra_fields=context_fields)
