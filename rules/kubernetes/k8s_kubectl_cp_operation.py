import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from urllib.parse import parse_qs, urlparse

from kubernetes_helpers import k8s_udm
from kubernetes_helpers import (
    is_failed_request,
    is_system_namespace,
    is_system_principal,
    k8s_alert_context,
)


def get_exec_command(event):
    """Extract exec command from requestObject (GCP/Azure) or requestURI query params (EKS).

    Returns:
        List of command arguments, or empty list if not found
    """
    # Try requestObject first (GCP/Azure format)
    request_object = k8s_udm(event, "requestObject") or {}
    command = request_object.get("command")
    if command:
        return command

    # Fall back to parsing requestURI query parameters (EKS format)
    # EKS format: /api/v1/.../exec?command=tar&command=cf&command=-
    request_uri = k8s_udm(event, "requestURI") or ""
    if "command=" in request_uri:
        try:
            parsed = urlparse(request_uri)
            params = parse_qs(parsed.query)
            return params.get("command", [])
        except Exception:  # pylint: disable=broad-except
            return []

    return []


def rule(event):
    verb = k8s_udm(event, "verb")
    resource = k8s_udm(event, "resource")
    subresource = k8s_udm(event, "subresource")
    namespace = k8s_udm(event, "namespace")
    username = k8s_udm(event, "username")
    response_status = k8s_udm(event, "responseStatus")

    # Only check exec subresource operations
    if verb not in ("create", "get") or resource != "pods" or subresource != "exec":
        return False

    # Skip failed requests
    if is_failed_request(response_status):
        return False

    # Exclude system principals creating pods in system namespaces (legitimate)
    # but alert on system principals in user namespaces (malicious Deployments)
    # and alert on user-created pods in system namespaces (suspicious)
    if is_system_principal(username) and is_system_namespace(namespace):
        return False

    # Extract command from either requestObject or requestURI
    command = get_exec_command(event)
    if not command:
        return False

    # Check if command contains tar with cf - pattern
    # tar cf - indicates copying FROM pod (stdout output = exfil)
    tar_found = False
    cf_flag_found = False
    stdout_dash_found = False

    for i, arg in enumerate(command):
        arg_str = str(arg).lower()

        if "tar" in arg_str:
            tar_found = True

        # Look for cf flag (create+file) - handles: cf, -cf, czf, -czf, etc.
        if "cf" in arg_str and arg_str != "-c":
            cf_flag_found = True

        # Check if - appears after cf flag was found (stdout redirect)
        if arg_str == "-" and i > 0 and cf_flag_found:
            stdout_dash_found = True

    return tar_found and cf_flag_found and stdout_dash_found


def title(event):
    username = k8s_udm(event, "username") or "<UNKNOWN_USER>"
    namespace = k8s_udm(event, "namespace") or "<UNKNOWN_NAMESPACE>"
    name = k8s_udm(event, "name") or "<UNKNOWN_POD>"

    command = get_exec_command(event)

    # Extract the path being copied if possible
    # Command format: ["tar", "cf", "-", "/path/to/file"]
    path = "<UNKNOWN_PATH>"
    if len(command) >= 4:
        for i, arg in enumerate(command):
            if arg == "-" and i + 1 < len(command):
                path = str(command[i + 1])
                break

    return f"[{username}] copied data from pod [{namespace}/{name}] path [{path}] via kubectl cp"


def dedup(event):
    username = k8s_udm(event, "username") or "<UNKNOWN_USER>"
    namespace = k8s_udm(event, "namespace") or "<UNKNOWN_NAMESPACE>"
    name = k8s_udm(event, "name") or "<UNKNOWN_POD>"
    return f"k8s_kubectl_cp_{username}_{namespace}_{name}"


def severity(event):
    """Increase severity for copying from sensitive paths."""
    command = get_exec_command(event)
    command_str = " ".join(str(arg) for arg in command).lower()

    # Critical severity for copying credentials or SSH keys
    critical_patterns = [
        "/root",
        ".ssh",
        "id_rsa",
        "id_ecdsa",
        "id_ed25519",
        "credentials",
        "secrets",
        "token",
        ".kube",
        "serviceaccount",
    ]
    if any(pattern in command_str for pattern in critical_patterns):
        return "CRITICAL"

    # High severity for copying from sensitive system directories
    sensitive_paths = ["/etc", "/var/run", "/proc", "config", "password", "shadow"]
    if any(path in command_str for path in sensitive_paths):
        return "HIGH"

    return "MEDIUM"


def alert_context(event):
    command = get_exec_command(event)
    request_object = k8s_udm(event, "requestObject") or {}

    return k8s_alert_context(
        event,
        extra_fields={
            "pod_name": k8s_udm(event, "name"),
            "command": command,
            "container": request_object.get("container"),
        },
    )
