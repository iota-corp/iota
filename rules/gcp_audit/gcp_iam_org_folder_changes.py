import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get


def rule(event):
    # Return True to match the log event and trigger an alert.
    logname = event.get("logName")
    return (
        deep_get(event, "protoPayload", "methodName") == "SetIamPolicy"
        and (logname.startswith("organizations") or logname.startswith("folder"))
        and logname.endswith("/logs/cloudaudit.googleapis.com%2Factivity")
    )


def title(event):
    # use unified data model field in title
    return f"{event.get('p_log_type')}: [{event.udm('actor_user')}] made manual changes to Org policy"


def alert_context(event):
    return {
        "actor": event.udm("actor_user"),
        "policy_change": deep_get(event, "protoPayload", "serviceData", "policyDelta"),
        "caller_ip": deep_get(event, "protoPayload", "requestMetadata", "callerIP"),
        "user_agent": deep_get(
            event, "protoPayload", "requestMetadata", "callerSuppliedUserAgent"
        ),
    }


def severity(event):
    if (
        deep_get(event, "protoPayload", "requestMetadata", "callerSuppliedUserAgent")
        .lower()
        .find("terraform")
        != -1
    ):
        return "INFO"
    return "HIGH"
