"""
Detect sign-in from anonymizing VPN/proxy (e.g. Tor, VPN).

Source RuleID (upstream): Okta.Anonymizing.VPN.Login
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from okta_helpers import okta_alert_context


def rule(event):
    return (
        event.get("eventType") == "user.session.start"
        and deep_get(event, "securityContext", "isProxy", default=False) is True
    )


def title(event):
    ip_context = {}
    client = event.get("client", {}) or {}
    security_context = event.get("securityContext", {}) or {}
    if client.get("ipAddress"):
        ip_context["IP"] = client.get("ipAddress")
    for key, source_value in [
        ("ASO", security_context.get("asOrg")),
        ("ISP", security_context.get("isp")),
        ("Domain", security_context.get("domain")),
    ]:
        if source_value:
            ip_context[key] = source_value
    display_name = deep_get(
        event, "actor", "displayName", default="<displayName-not-found>"
    )
    alternate_id = deep_get(
        event, "actor", "alternateId", default="<alternateId-not-found>"
    )
    return f"{display_name} <{alternate_id}> attempted to sign-in from anonymizing VPN - {ip_context}"


def severity():
    return "MEDIUM"


def dedup(event):
    return (
        event.get("uuid", "")
        or f"{deep_get(event, 'actor', 'id')}-{event.get('published', '')}"
    )


def alert_context(event):
    return okta_alert_context(event)
