import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get

METHODS = [
    "google.iam.v1.WorkloadIdentityPools.CreateWorkloadIdentityPoolProvider",
    "google.iam.v1.WorkloadIdentityPools.UpdateWorkloadIdentityPoolProvider",
]


def rule(event):
    return deep_get(event, "protoPayload", "methodName", default="") in METHODS


def title(event):
    actor = deep_get(
        event,
        "protoPayload",
        "authenticationInfo",
        "principalEmail",
        default="<ACTOR_NOT_FOUND>",
    )
    resource = deep_get(
        event, "protoPayload", "resourceName", default="<RESOURCE_NOT_FOUND>"
    ).split("/")
    workload_identity_pool = resource[resource.index("workloadIdentityPools") + 1]
    project_id = deep_get(
        event, "resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>"
    )

    return (
        f"GCP: [{actor}] created or updated workload identity pool "
        f"[{workload_identity_pool}] in project [{project_id}]"
    )


def alert_context(event):
    return deep_get(
        event, "protoPayload", "request", "workloadIdentityPoolProvider", default={}
    )
