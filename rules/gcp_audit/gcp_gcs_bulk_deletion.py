import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get


def rule(event):
    method_name = deep_get(
        event, "protoPayload", "methodName", default="UNKNOWN_METHOD_NAME"
    )
    service_name = deep_get(event, "protoPayload", "serviceName")
    severity = event.get("severity")
    return all(
        [
            method_name == "storage.objects.delete",
            service_name == "storage.googleapis.com",
            severity != "ERROR",  # Operation succeeded
        ]
    )


def title(event):
    principal = deep_get(event, "protoPayload", "authenticationInfo", "principalEmail")
    resource = deep_get(event, "protoPayload", "resourceName")
    return (
        f"GCP: Bulk object deletion in resource [{resource}] by principal [{principal}]"
    )


def alert_context(event):
    return {
        "principal": deep_get(
            event, "protoPayload", "authenticationInfo", "principalEmail"
        ),
        "project": deep_get(event, "resource", "labels", "project_id"),
        "status": deep_get(event, "protoPayload", "status"),
        "location": deep_get(event, "resource", "labels", "location"),
        "resource": deep_get(event, "protoPayload", "resourceName"),
    }
