import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get

BUCKET_OPERATIONS = ["storage.buckets.delete", "storage.buckets.update"]


def rule(event):
    return all(
        [
            deep_get(event, "protoPayload", "serviceName", default="")
            == "storage.googleapis.com",
            deep_get(event, "protoPayload", "methodName", default="")
            in BUCKET_OPERATIONS,
            event.get("severity") != "ERROR",
        ]
    )


def title(event):
    actor = deep_get(
        event,
        "protoPayload",
        "authenticationInfo",
        "principalEmail",
        default="<ACTOR_NOT_FOUND>",
    )
    operation = deep_get(
        event, "protoPayload", "methodName", default="<OPERATION_NOT_FOUND>"
    )
    project = deep_get(
        event, "resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>"
    )
    bucket = deep_get(
        event, "resource", "labels", "bucket_name", default="<BUCKET_NOT_FOUND>"
    )

    return f"GCP: [{actor}] performed a [{operation}] on bucket [{bucket}] in project [{project}]."


def alert_context(event):
    return {
        "actor": deep_get(
            event, "protoPayload", "authenticationInfo", "principalEmail"
        ),
        "bucket": deep_get(event, "resource", "labels", "bucket_name"),
        "source_ip": deep_get(event, "protoPayload", "requestMetadata", "callerIp"),
        "user_agent": deep_get(
            event, "protoPayload", "requestMetadata", "callerSuppliedUserAgent"
        ),
        "project": deep_get(event, "resource", "labels", "project_id"),
    }
