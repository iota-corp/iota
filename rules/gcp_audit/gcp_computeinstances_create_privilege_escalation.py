import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, deep_walk
from gcp_helpers import gcp_alert_context

REQUIRED_PERMISSIONS = [
    "compute.disks.create",
    "compute.instances.create",
    "compute.instances.setMetadata",
    "compute.instances.setServiceAccount",
    "compute.subnetworks.use",
    "compute.subnetworks.useExternalIp",
]


def rule(event):
    if deep_get(event, "protoPayload", "response", "error"):
        return False

    method = deep_get(event, "protoPayload", "methodName", default="METHOD_NOT_FOUND")
    if not method.endswith("compute.instances.insert"):
        return False

    # Skip allowlisted actors
    principal = deep_get(
        event, "protoPayload", "authenticationInfo", "principalEmail", default=""
    )
    if principal.endswith("@cloudservices.gserviceaccount.com"):
        return False

    granted_permissions = {}
    for auth in deep_walk(event, "protoPayload", "authorizationInfo") or []:
        granted_permissions[auth.get("permission")] = auth.get("granted")
    for permission in REQUIRED_PERMISSIONS:
        if not granted_permissions.get(permission):
            return False

    return True


def title(event):
    actor = deep_get(
        event,
        "protoPayload",
        "authenticationInfo",
        "principalEmail",
        default="<ACTOR_NOT_FOUND>",
    )

    service_accounts = deep_get(event, "protoPayload", "request", "serviceAccounts")
    if not service_accounts:
        service_account_emails = "<SERVICE_ACCOUNT_EMAILS_NOT_FOUND>"
    else:
        service_account_emails = [
            service_acc["email"] for service_acc in service_accounts
        ]

    project = deep_get(
        event, "resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>"
    )
    return (
        f"[GCP]: [{actor}] created a new Compute Engine instance with [{service_account_emails}] "
        f"Service Account on project [{project}]"
    )


def alert_context(event):
    context = gcp_alert_context(event)
    service_accounts = deep_get(event, "protoPayload", "request", "serviceAccounts")
    if not service_accounts:
        service_account_emails = "<SERVICE_ACCOUNT_EMAILS_NOT_FOUND>"
    else:
        service_account_emails = [
            service_acc["email"] for service_acc in service_accounts
        ]
    context["serviceAccount"] = service_account_emails
    return context
