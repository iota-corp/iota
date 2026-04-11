import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from gcp_helpers import gcp_alert_context


def rule(event):
    if deep_get(event, "operation", "producer") == "k8s.io" and deep_get(
        event, "p_enrichment", "tor_exit_nodes"
    ):
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
    operation = deep_get(
        event, "protoPayload", "methodName", default="<OPERATION_NOT_FOUND>"
    )
    project_id = deep_get(
        event, "resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>"
    )

    return f"[GCP]: [{actor}] performed [{operation}] on project [{project_id}]"


def alert_context(event):
    context = gcp_alert_context(event)
    context["tor_exit_nodes"] = deep_get(event, "p_enrichment", "tor_exit_nodes")
    return context
