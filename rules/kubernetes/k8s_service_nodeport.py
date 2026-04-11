import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from kubernetes_helpers import k8s_udm
from kubernetes_helpers import is_failed_request, k8s_alert_context


def rule(event):
    verb = k8s_udm(event, "verb")
    resource = k8s_udm(event, "resource")
    response_status = k8s_udm(event, "responseStatus")

    # Only check service creation events
    if verb != "create" or resource != "services":
        return False

    # Skip failed requests
    if is_failed_request(response_status):
        return False

    # Check if service type is NodePort
    service_type = k8s_udm(event, "serviceType") or ""
    if service_type == "NodePort":
        return True

    return False


def title(event):
    username = k8s_udm(event, "username") or "<UNKNOWN_USER>"
    namespace = k8s_udm(event, "namespace") or "<UNKNOWN_NAMESPACE>"
    name = k8s_udm(event, "name") or "<UNKNOWN>"

    return f"[{username}] deployed NodePort service [{namespace}/{name}]"


def alert_context(event):
    return k8s_alert_context(
        event,
        extra_fields={
            "service_name": k8s_udm(event, "name"),
            "service_type": k8s_udm(event, "serviceType"),
        },
    )
