import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))

from correlation_store import event_unix_ts, sliding_window_threshold_crossed
from cloudflare_helpers import cloudflare_http_alert_context

# Upstream: DedupPeriodMinutes 60, Threshold 7560
_WINDOW_SEC = 60 * 60
_THRESHOLD = 7560


def _dedup_key(event):
    return f"cf_http_botvol:{event.get('ClientRequestHost', '')}:{event.get('ClientIP', '')}"


def rule(event):
    bot = event.get("BotScore", 100)
    base = 1 <= bot <= 30
    if not base:
        return False
    ts = event_unix_ts(event)
    return sliding_window_threshold_crossed(
        _dedup_key(event), _WINDOW_SEC, _THRESHOLD, ts
    )


def title(event):
    return (
        f"Cloudflare: High Volume of Bot Requests "
        f"to [{event.get('ClientRequestHost', '<NO_REQ_HOST>')}]"
    )


def alert_context(event):
    return cloudflare_http_alert_context(event)
