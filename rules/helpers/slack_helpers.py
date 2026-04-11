from iota_helpers import deep_get


def slack_alert_context(event):
    return {
        "actor-name": deep_get(
            event, "actor", "user", "name", default="<MISSING_NAME>"
        ),
        "actor-email": deep_get(
            event, "actor", "user", "email", default="<MISSING_EMAIL>"
        ),
        "actor-ip": deep_get(event, "context", "ip_address", default="<MISSING_IP>"),
        "user-agent": deep_get(event, "context", "ua", default="<MISSING_UA>"),
    }
