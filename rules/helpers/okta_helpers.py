"""
Okta helper functions for iota detection rules
"""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from iota_helpers import deep_get


def okta_alert_context(event):
    """Generate standard Okta alert context"""
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
    """Get actor information from Okta event"""
    return {
        "id": deep_get(event, "actor", "id"),
        "type": deep_get(event, "actor", "type"),
        "alternateId": deep_get(event, "actor", "alternateId"),
        "displayName": deep_get(event, "actor", "displayName"),
    }


def get_okta_target(event, index=0):
    """Get target information from Okta event"""
    targets = event.get("target", [])
    if not targets or index >= len(targets):
        return {}
    return targets[index]


def is_okta_success(event):
    """Check if Okta event outcome was successful"""
    return deep_get(event, "outcome", "result") == "SUCCESS"


def is_okta_failure(event):
    """Check if Okta event outcome was a failure"""
    return deep_get(event, "outcome", "result") == "FAILURE"


def get_okta_ip(event):
    """Extract source IP from Okta event"""
    return deep_get(event, "client", "ipAddress")


def get_okta_user_agent(event):
    """Extract user agent from Okta event"""
    return deep_get(event, "client", "userAgent", "rawUserAgent")
