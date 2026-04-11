import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from kubernetes_helpers import k8s_udm
from kubernetes_helpers import k8s_alert_context


def rule(event):
    verb = k8s_udm(event, "verb")
    resource = k8s_udm(event, "resource")
    subresource = k8s_udm(event, "subresource")

    # Check for exec action on pods
    if verb in ("create", "get") and resource == "pods" and subresource == "exec":
        return True

    return False


def title(event):
    username = k8s_udm(event, "username") or "<UNKNOWN_USER>"
    namespace = k8s_udm(event, "namespace") or "<UNKNOWN_NAMESPACE>"
    pod_name = k8s_udm(event, "name") or "<UNKNOWN>"

    return f"[{username}] executed into pod [{namespace}/{pod_name}]"


def dedup(event):
    username = k8s_udm(event, "username") or "<UNKNOWN_USER>"
    namespace = k8s_udm(event, "namespace") or "<UNKNOWN_NAMESPACE>"
    pod_name = k8s_udm(event, "name") or "<UNKNOWN_POD>"
    return f"k8s_exec_{username}_{namespace}_{pod_name}"


def alert_context(event):
    return k8s_alert_context(
        event,
        extra_fields={"pod_name": k8s_udm(event, "name")},
    )
