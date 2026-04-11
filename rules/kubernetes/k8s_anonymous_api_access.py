import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from kubernetes_helpers import k8s_udm
from kubernetes_helpers import k8s_alert_context


def is_system_access(event):
    # Skip localhost and health check traffic
    # nosec: Fallback to empty list is safe - we check for localhost separately
    src_ip = k8s_udm(event, "sourceIPs") or []
    if src_ip == ["127.0.0.1"]:
        return True

    user_agent = k8s_udm(event, "userAgent") or ""

    # AWS EKS: Exclude ELB health checker from internal IPs
    if (
        user_agent == "ELB-HealthChecker/2.0"
        and src_ip
        and src_ip[0].startswith("10.0.")
    ):
        return True

    system_user_agents = (
        "kube-probe/",
        "GoogleHC/",
    )
    # GCP GKE & Azure AKS: Exclude kube-probe (Kubernetes liveness/readiness probes)
    # GCP GKE: Exclude Google Cloud Load Balancer health checks

    if any(user_agent.startswith(pattern) for pattern in system_user_agents):
        return True
    return False


def is_health_check(event):
    request_uri = k8s_udm(event, "requestURI") or ""
    health_patterns = (
        "/healthz",
        "/readyz",
        "/livez",
        "/apis/healthz",
        "/apis/readyz",
        "/apis/livez",
    )
    if any(request_uri.startswith(pattern) for pattern in health_patterns):
        return True
    return False


def rule(event):
    if k8s_udm(event, "username") == "system:anonymous":
        if not is_system_access(event) and not is_health_check(event):
            return True
    return False


def title(event):
    # For failed attempts or /version endpoint, use generic titles
    annotations = k8s_udm(event, "annotations") or {}
    if annotations.get("authorization.k8s.io/decision") != "allow":
        return "Failed Anonymous Kubernetes API Access Attempt(s) Detected"
    if k8s_udm(event, "requestURI") == "/version":
        return "Anonymous Kubernetes API Access to /version Endpoint Detected"

    # For successful access to other endpoints, provide detailed information
    source_ips = k8s_udm(event, "sourceIPs") or []
    source_ip = source_ips[0] if source_ips else "<UNKNOWN_IP>"
    request_uri = k8s_udm(event, "requestURI") or "<UNKNOWN_URI>"
    return (
        f"Anonymous API access detected on Kubernetes API server "
        f"from [{source_ip}] to [{request_uri}]"
    )


def severity(event):
    annotations = k8s_udm(event, "annotations") or {}
    if annotations.get("authorization.k8s.io/decision") != "allow":
        return "INFO"
    if k8s_udm(event, "requestURI") == "/version":
        return "INFO"
    return "DEFAULT"


def dedup(event):
    user_agent = k8s_udm(event, "userAgent") or "<UNKNOWN_USER_AGENT>"
    return f"anonymous_access_{user_agent}"


def alert_context(event):
    return k8s_alert_context(
        event,
        extra_fields={"annotations": k8s_udm(event, "annotations")},
    )
