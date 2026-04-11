import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))

from iota_helpers import deep_get
from kubernetes_helpers import is_k8s_log, k8s_alert_context, k8s_udm


def rule(event):
    if is_k8s_log(event) and deep_get(
        event, "p_enrichment", "tor_exit_nodes", default=None
    ):
        return True

    return False


def title(event):
    username = k8s_udm(event, "username") or "<UNKNOWN_USER>"
    tor_nodes = deep_get(event, "p_enrichment", "tor_exit_nodes", default=[]) or []
    tor_ip = tor_nodes[0] if tor_nodes else "<UNKNOWN_IP>"

    return f"Kubernetes API activity from Tor exit node [{tor_ip}] by user [{username}]"


def dedup(event):
    tor_nodes = deep_get(event, "p_enrichment", "tor_exit_nodes", default=[]) or []
    tor_ip = tor_nodes[0] if tor_nodes else "<UNKNOWN_IP>"
    return f"k8s_tor_{tor_ip}"


def alert_context(event):
    return k8s_alert_context(
        event,
        extra_fields={
            "tor_exit_nodes": deep_get(event, "p_enrichment", "tor_exit_nodes")
        },
    )
