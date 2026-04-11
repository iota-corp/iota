import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from kubernetes_helpers import k8s_udm
from kubernetes_helpers import is_failed_request, is_system_principal, k8s_alert_context

PRIVILEGED_CLUSTER_ROLES = {
    "cluster-admin",  # Full cluster control
    "system:masters",  # Superuser group
    "admin",  # Namespace admin capabilities
    "system:kube-controller-manager",  # Controller manager privileges
    "system:kube-scheduler",  # Scheduler privileges
}


def rule(event):
    verb = k8s_udm(event, "verb")
    resource = k8s_udm(event, "resource")
    username = k8s_udm(event, "username")
    response_status = k8s_udm(event, "responseStatus")

    # Only check ClusterRoleBinding creation events
    if verb != "create" or resource != "clusterrolebindings":
        return False

    # Skip failed requests
    if is_failed_request(response_status):
        return False

    # Exclude system principals to reduce false positives from legitimate operators
    if is_system_principal(username):
        return False

    # Check if binding references a privileged cluster role
    request_object = k8s_udm(event, "requestObject") or {}
    role_name = deep_get(request_object, "roleRef", "name", default="")
    if role_name in PRIVILEGED_CLUSTER_ROLES:
        return True

    return False


def title(event):
    username = k8s_udm(event, "username") or "<UNKNOWN_USER>"
    name = k8s_udm(event, "name") or "<UNKNOWN_BINDING>"

    request_object = k8s_udm(event, "requestObject") or {}
    role_ref = request_object.get("roleRef", {})
    role_name = role_ref.get("name", "<UNKNOWN_ROLE>")

    # Extract subject information
    subjects = request_object.get("subjects", [])
    subject_names = []
    for subject in subjects:
        subject_type = subject.get("kind", "")
        subject_name = subject.get("name", "")
        if subject_type and subject_name:
            subject_names.append(f"{subject_type}:{subject_name}")

    subjects_str = ", ".join(subject_names) if subject_names else "<UNKNOWN_SUBJECTS>"

    return (
        f"[{username}] created ClusterRoleBinding [{name}] granting [{role_name}] "
        f"to [{subjects_str}]"
    )


def dedup(event):
    username = k8s_udm(event, "username") or "<UNKNOWN_USER>"
    name = k8s_udm(event, "name") or "<UNKNOWN_BINDING>"
    return f"k8s_clusterrolebinding_{username}_{name}"


def severity(event):
    """Increase severity for cluster-admin and system:masters roles."""
    request_object = k8s_udm(event, "requestObject") or {}
    role_ref = request_object.get("roleRef", {})
    role_name = role_ref.get("name", "")

    # High for cluster-admin and system:masters (full cluster control)
    if role_name in {"cluster-admin", "system:masters"}:
        return "HIGH"

    # Medium for other privileged system roles
    return "DEFAULT"


def alert_context(event):
    request_object = k8s_udm(event, "requestObject") or {}
    role_ref = request_object.get("roleRef", {})
    subjects = request_object.get("subjects", [])

    return k8s_alert_context(
        event,
        extra_fields={
            "binding_name": k8s_udm(event, "name"),
            "role_name": role_ref.get("name"),
            "role_kind": role_ref.get("kind"),
            "subjects": subjects,
        },
    )
