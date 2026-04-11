import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get


def rule(event):
    return (
        deep_get(event, "resource", "type") == "gcs_bucket"
        and deep_get(event, "protoPayload", "methodName") == "storage.setIamPermissions"
    )


def dedup(event):
    return deep_get(
        event, "resource", "labels", "project_id", default="<UNKNOWN_PROJECT>"
    )
