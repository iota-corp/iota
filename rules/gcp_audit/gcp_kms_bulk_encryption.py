import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get


def rule(event):
    method_name = deep_get(event, "protoPayload", "methodName")
    service_name = deep_get(event, "protoPayload", "serviceName")
    principal = deep_get(
        event,
        "protoPayload",
        "authenticationInfo",
        "principalEmail",
        default="<UNKNOWN_PRINCIPAL>",
    )
    severity = event.get("severity")
    principal_domain = (
        principal.rsplit("@", 1)[-1].lower()
        if isinstance(principal, str) and "@" in principal
        else ""
    )
    expected_domain = "gs-project-accounts.iam.gserviceaccount.com"
    gcs_project_sa = principal_domain == expected_domain or principal_domain.endswith(
        "." + expected_domain
    )
    return all(
        [
            method_name == "Encrypt",
            service_name == "cloudkms.googleapis.com",
            gcs_project_sa,
            severity != "ERROR",  # Operation succeeded
        ]
    )


def title(event):
    key = deep_get(event, "resource", "labels", "crypto_key_id", default="Unknown")
    return f"GCS service account performing bulk KMS encryption with key [{key}]"


def alert_context(event):
    return {
        "principal": deep_get(
            event, "protoPayload", "authenticationInfo", "principalEmail"
        ),
        "kms_key": deep_get(event, "protoPayload", "resourceName"),
        "key_ring": deep_get(event, "resource", "labels", "key_ring_id"),
        "crypto_key": deep_get(event, "resource", "labels", "crypto_key_id"),
        "project": deep_get(event, "resource", "labels", "project_id"),
        "status": deep_get(event, "protoPayload", "status"),
        "location": deep_get(event, "resource", "labels", "location"),
    }
