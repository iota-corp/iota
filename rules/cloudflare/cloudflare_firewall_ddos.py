import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))

from correlation_store import event_unix_ts, sliding_window_threshold_crossed
from cloudflare_helpers import cloudflare_fw_alert_context

# Upstream: DedupPeriodMinutes 60, Threshold 100
_WINDOW_SEC = 60 * 60
_THRESHOLD = 100


def _dedup_key(event):
    host = event.get("ClientRequestHost") or ""
    zid = event.get("ZoneID", "")
    return f"cf_fw_l7ddos:{zid}:{host}"


def rule(event):
    if event.get("Source", "") != "l7ddos":
        return False
    ts = event_unix_ts(event)
    return sliding_window_threshold_crossed(
        _dedup_key(event), _WINDOW_SEC, _THRESHOLD, ts
    )


def title(_):
    return "Cloudflare: Detected L7 DDoS"


def alert_context(event):
    return cloudflare_fw_alert_context(event)


def severity(event):
    if event.get("Action", "") == "block":
        return "Info"
    return "Medium"
