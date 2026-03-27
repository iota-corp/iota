"""
Lambda function code updated by an interactive identity (IAM user, federated user, or IAM Identity Center).

Narrows noise from service roles compared to broad Lambda modification coverage.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import aws_rule_context, deep_get, get_actor_user, is_successful


def rule(event):
    if not is_successful(event):
        return False
    if event.get("eventSource") != "lambda.amazonaws.com":
        return False
    event_name = event.get("eventName") or ""
    if not event_name.startswith("UpdateFunctionCode"):
        return False

    identity_type = deep_get(event, "userIdentity", "type", default="")
    if identity_type in ("IAMUser", "FederatedUser"):
        return True
    if identity_type == "AssumedRole":
        role_name = deep_get(
            event,
            "userIdentity",
            "sessionContext",
            "sessionIssuer",
            "userName",
            default="",
        )
        return str(role_name).startswith("AWSReservedSSO_")
    return False


def title(event):
    lambda_name = deep_get(
        event,
        "responseElements",
        "functionName",
        default=deep_get(event, "requestParameters", "functionName", default="UNKNOWN"),
    )
    actor = get_actor_user(event)
    return f"[AWS.CloudTrail] User [{actor}] updated Lambda function code for [{lambda_name}]"


def severity():
    return "HIGH"


def alert_context(event):
    context = aws_rule_context(event)
    context["identity_type"] = deep_get(event, "userIdentity", "type")
    context["user_arn"] = deep_get(event, "userIdentity", "arn")
    context["functionName"] = deep_get(
        event,
        "responseElements",
        "functionName",
        default=deep_get(event, "requestParameters", "functionName"),
    )
    return context
