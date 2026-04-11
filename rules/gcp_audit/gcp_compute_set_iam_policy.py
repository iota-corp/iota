import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from gcp_helpers import gcp_alert_context, get_binding_deltas

SUSPICIOUS_ACTIONS = [
    "v1.compute.disks.setIamPolicy",
    "v1.compute.images.setIamPolicy",
    "v1.compute.snapshots.setIamPolicy",
]


def rule(event):
    if deep_get(event, "protoPayload", "response", "error"):
        return False

    method = deep_get(event, "protoPayload", "methodName", default="METHOD_NOT_FOUND")
    if method in SUSPICIOUS_ACTIONS:
        return True

    return False


def title(event):
    actor = deep_get(
        event,
        "protoPayload",
        "authenticationInfo",
        "principalEmail",
        default="<ACTOR_NOT_FOUND>",
    )

    items = deep_get(
        event, "protoPayload", "methodName", default="ITEMS_NOT_FOUND. "
    ).split(".")[-2]

    project = deep_get(
        event, "resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>"
    )
    return f"[GCP]: [{actor}] updated IAM policy for [{items}] on project [{project}]"


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
    context["binding_deltas"] = get_binding_deltas(event)
    return context
