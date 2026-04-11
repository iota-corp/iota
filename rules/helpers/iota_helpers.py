"""
iota helper functions for standalone detection
"""

from collections import OrderedDict
from collections.abc import Mapping, Sequence
from typing import Any, Optional, Union


def deep_get(dictionary, *keys, default=None):
    """
    Safely access nested dictionary values.

    Example:
        deep_get(event, 'userIdentity', 'type') returns event['userIdentity']['type']
        or default if any key doesn't exist
    """
    result = dictionary
    for key in keys:
        if isinstance(result, dict):
            result = result.get(key)
            if result is None:
                return default
        else:
            return default
    return result


def deep_walk(
    obj: Optional[Any],
    *keys: str,
    default: Optional[Any] = None,
    return_val: str = "all",
) -> Union[Any, list, None]:
    """Traverse dict/list structures; collect values when paths cross lists (SIEM-style list handling)."""

    def _empty_list(sub_obj: Any) -> bool:
        return (
            all(_empty_list(next_obj) for next_obj in sub_obj)
            if isinstance(sub_obj, Sequence) and not isinstance(sub_obj, str)
            else False
        )

    if not keys:
        return default if _empty_list(obj) else obj

    current_key = keys[0]
    found: OrderedDict = OrderedDict()

    if isinstance(obj, Mapping):
        next_key = obj.get(current_key, None)
        return (
            deep_walk(next_key, *keys[1:], default=default, return_val=return_val)
            if next_key is not None
            else default
        )
    if isinstance(obj, Sequence) and not isinstance(obj, str):
        for item in obj:
            value = deep_walk(item, *keys, default=default, return_val=return_val)
            if value is not None:
                if isinstance(value, Sequence) and not isinstance(value, str):
                    for sub_item in value:
                        found[sub_item] = None
                else:
                    found[value] = None

    found_list: list[Any] = list(found.keys())
    if not found_list:
        return default
    return {
        "first": found_list[0],
        "last": found_list[-1],
        "all": found_list[0] if len(found_list) == 1 else found_list,
    }.get(return_val, "all")


def key_value_list_to_dict(list_objects: list, key: str, value: str) -> dict:
    return {item[key]: item[value] for item in list_objects}


def aws_rule_context(event):
    """
    Generate standard AWS CloudTrail context for alerts.
    """
    return {
        "eventName": event.get("eventName"),
        "eventTime": event.get("eventTime"),
        "sourceIPAddress": event.get("sourceIPAddress"),
        "userAgent": event.get("userAgent"),
        "recipientAccountId": event.get("recipientAccountId"),
        "userIdentity": event.get("userIdentity", {}),
        "requestParameters": event.get("requestParameters", {}),
        "responseElements": event.get("responseElements", {}),
    }


def is_assume_role_event(event):
    """Check if event is an AssumeRole action"""
    return event.get("eventName") == "AssumeRole"


def is_console_login(event):
    """Check if event is a console login"""
    return event.get("eventName") == "ConsoleLogin"


def is_root_user(event):
    """Check if event was performed by root user"""
    return deep_get(event, "userIdentity", "type") == "Root"


def is_successful(event):
    """Check if event was successful"""
    error_code = event.get("errorCode")
    error_message = event.get("errorMessage")
    return not error_code and not error_message


def get_account_id(event):
    """Extract account ID from event"""
    return event.get("recipientAccountId") or deep_get(
        event, "userIdentity", "accountId"
    )


def get_user_identity_arn(event):
    """Extract user identity ARN"""
    return deep_get(event, "userIdentity", "arn", default="<UNKNOWN_ARN>")


def get_principal_id(event):
    """Extract principal ID"""
    return deep_get(event, "userIdentity", "principalId", default="<UNKNOWN_PRINCIPAL>")


def aws_guardduty_context(event):
    """Generate context for GuardDuty findings"""
    return {
        "severity": deep_get(event, "severity"),
        "type": deep_get(event, "type"),
        "title": deep_get(event, "title"),
        "description": deep_get(event, "description"),
        "accountId": deep_get(event, "accountId"),
        "region": deep_get(event, "region"),
    }


def pattern_match(string_to_check, pattern_list):
    """
    Check if a string matches any pattern in a list (case-insensitive contains).
    """
    if not string_to_check or not pattern_list:
        return False

    string_lower = str(string_to_check).lower()
    return any(pattern.lower() in string_lower for pattern in pattern_list)


def pattern_match_list(strings_to_check, pattern_list):
    """
    Check if any string in a list matches any pattern (case-insensitive contains).
    """
    if not strings_to_check or not pattern_list:
        return False

    for string in strings_to_check:
        if pattern_match(string, pattern_list):
            return True
    return False


def get_actor_user(event):
    """
    Extract actor/user from various log types.
    Works with CloudTrail, Okta, GSuite, 1Password.
    """
    # CloudTrail
    user_identity = event.get("userIdentity", {})
    if user_identity:
        identity_type = user_identity.get("type")
        if identity_type == "IAMUser":
            return user_identity.get("userName", "<UNKNOWN>")
        if identity_type == "AssumedRole":
            session_context = user_identity.get("sessionContext", {})
            session_issuer = session_context.get("sessionIssuer", {})
            if session_issuer.get("userName"):
                return session_issuer.get("userName")
            arn = user_identity.get("arn", "")
            return arn.split("/")[-1] if arn else "<UNKNOWN>"
        if identity_type == "Root":
            return "root"
        if identity_type == "AWSService":
            return user_identity.get("invokedBy", "<AWS_SERVICE>")
        return user_identity.get("arn", "<UNKNOWN>").split("/")[-1]

    # Okta
    actor = event.get("actor", {})
    if actor:
        return actor.get("alternateId") or actor.get("displayName") or "<UNKNOWN>"

    # GSuite
    if "actor" in event and "email" in event.get("actor", {}):
        return event["actor"]["email"]

    # 1Password
    if "user" in event:
        user = event["user"]
        return user.get("email") or user.get("name") or "<UNKNOWN>"

    return "<UNKNOWN>"


def get_source_ip(event):
    """Extract source IP from various log types."""
    # CloudTrail
    if "sourceIPAddress" in event:
        return event["sourceIPAddress"]

    # Okta
    client = event.get("client", {})
    if client and "ipAddress" in client:
        return client["ipAddress"]

    # GSuite
    if "ipAddress" in event:
        return event["ipAddress"]

    # 1Password
    if "client" in event and "ip_address" in event.get("client", {}):
        return event["client"]["ip_address"]

    return "<UNKNOWN>"


def okta_alert_context(event):
    """Generate standard Okta alert context."""
    return {
        "eventType": event.get("eventType"),
        "uuid": event.get("uuid"),
        "published": event.get("published"),
        "severity": event.get("severity"),
        "displayMessage": event.get("displayMessage"),
        "actor": event.get("actor", {}),
        "client": event.get("client", {}),
        "outcome": event.get("outcome", {}),
        "target": event.get("target", []),
        "sourceIPAddress": deep_get(event, "client", "ipAddress"),
        "userAgent": deep_get(event, "client", "userAgent", "rawUserAgent"),
    }


def get_okta_actor(event):
    """Get actor information from Okta event as a dict."""
    return {
        "id": deep_get(event, "actor", "id"),
        "type": deep_get(event, "actor", "type"),
        "alternateId": deep_get(event, "actor", "alternateId"),
        "displayName": deep_get(event, "actor", "displayName"),
    }


def get_okta_target(event, index=0):
    """Get target information from Okta event."""
    targets = event.get("target", [])
    if not targets or index >= len(targets):
        return {}
    return targets[index]


def get_okta_user_agent(event):
    """Extract user agent from Okta event."""
    return deep_get(event, "client", "userAgent", "rawUserAgent")


def is_okta_success(event):
    """Check if Okta event was successful."""
    outcome = event.get("outcome", {})
    return outcome.get("result") == "SUCCESS"


def is_okta_failure(event):
    """Check if Okta event failed."""
    outcome = event.get("outcome", {})
    return outcome.get("result") == "FAILURE"


def get_okta_target_users(event):
    """Extract target users from Okta event."""
    targets = event.get("target", [])
    users = []
    for target in targets:
        if target.get("type") == "User":
            users.append(target.get("alternateId") or target.get("displayName"))
    return users
