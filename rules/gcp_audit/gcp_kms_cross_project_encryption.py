import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from gcp_helpers import gcp_alert_context


def rule(event):
    if (
        deep_get(event, "protoPayload", "serviceName") != "cloudkms.googleapis.com"
        or deep_get(event, "protoPayload", "methodName") != "Encrypt"
        or "gs-project-accounts.iam.gserviceaccount.com"
        not in deep_get(
            event, "protoPayload", "authenticationInfo", "principalEmail", default=""
        )
    ):
        return False

    # Get the target project from the log name
    # Format: projects/PROJECT/logs/cloudaudit.googleapis.com%2Fdata_access
    source_project = None
    if event.get("logName").startswith("projects/"):
        parts = event.get("logName").split("/")
        if len(parts) >= 2:
            source_project = parts[1]

    kms_project = None
    if deep_get(event, "protoPayload", "resourceName").startswith("projects/"):
        parts = deep_get(event, "protoPayload", "resourceName").split("/")
        if len(parts) >= 2:
            kms_project = parts[1]

    if source_project and kms_project is not None and source_project != kms_project:
        return True

    return False


def title(event):
    kms_key = deep_get(
        event, "protoPayload", "resourceName", default="<UNKNOWN_KMS_KEY>"
    )
    principal = deep_get(
        event,
        "protoPayload",
        "authenticationInfo",
        "principalEmail",
        default="<UNKNOWN_PRINCIPAL>",
    )
    return (
        f"Cross-project KMS encryption by [{principal}] using key [{kms_key}] detected"
    )


def alert_context(event):
    context = gcp_alert_context(event)
    context["kms_key"] = deep_get(
        event, "protoPayload", "resourceName", default="<UNKNOWN_KMS_KEY>"
    )
    return context
