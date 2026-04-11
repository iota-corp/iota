import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
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
    namespace = k8s_udm(event, "namespace")
    username = k8s_udm(event, "username")
    response_status = k8s_udm(event, "responseStatus")

    # Only check ingress creation events
    if verb != "create" or resource != "ingresses":
        return False

    # Skip failed requests
    if is_failed_request(response_status):
        return False

    # Exclude system namespaces and system principals to reduce false positives
    if is_system_namespace(namespace) or is_system_principal(username):
        return False

    # Check if ingress has TLS configuration
    tls = deep_get(k8s_udm(event, "requestObject"), "spec", "tls")

    # Alert if TLS is not configured (missing or empty)
    if not tls:
        return True

    return False


def title(event):
    username = k8s_udm(event, "username") or "<UNKNOWN_USER>"
    namespace = k8s_udm(event, "namespace") or "<UNKNOWN_NAMESPACE>"
    name = k8s_udm(event, "name") or "<UNKNOWN_INGRESS>"

    return f"[{username}] created Ingress [{namespace}/{name}] without TLS certificate"


def dedup(event):
    namespace = k8s_udm(event, "namespace") or "<UNKNOWN_NAMESPACE>"
    name = k8s_udm(event, "name") or "<UNKNOWN_INGRESS>"
    return f"k8s_ingress_no_tls_{namespace}_{name}"


def severity(event):
    """Increase severity based on ingress annotations and rules."""
    request_object = k8s_udm(event, "requestObject") or {}
    metadata = request_object.get("metadata", {})
    annotations = metadata.get("annotations", {})

    # Check if this is an external-facing ingress (has external annotations)
    external_annotations = [
        "kubernetes.io/ingress.class",
        "cert-manager.io/cluster-issuer",
        "external-dns.alpha.kubernetes.io/hostname",
    ]

    if any(key in annotations for key in external_annotations):
        return "MEDIUM"

    return "DEFAULT"


def alert_context(event):
    request_object = k8s_udm(event, "requestObject") or {}
    spec = request_object.get("spec", {})
    rules = spec.get("rules", [])
    metadata = request_object.get("metadata", {})
    annotations = metadata.get("annotations", {})

    # Extract hosts from ingress rules
    hosts = []
    for rule_entry in rules:
        host = rule_entry.get("host")
        if host:
            hosts.append(host)

    return k8s_alert_context(
        event,
        extra_fields={
            "ingress_name": k8s_udm(event, "name"),
            "ingress_hosts": hosts,
            "annotations": annotations,
            "has_tls": False,
        },
    )
