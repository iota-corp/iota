# Unified Kubernetes rules (`Amazon.EKS.Audit`, `GCP.AuditLog` k8s.io)

Rules are ported from upstream `kubernetes_rules`. Field access uses `k8s_udm(event, key)` in `rules/helpers/kubernetes_helpers.py`, matching EKS audit JSON and GKE audit (`protoPayload.serviceName == k8s.io`).

## Enrichment-dependent rules

| File | Requirement |
|------|-------------|
| `k8s_ioc_activity.py` | `p_enrichment.tor_exit_nodes` populated by the pipeline (Tor exit attribution). |
| `k8s_system_principal_public_ip.py` | Cloud-provider ASN allowlisting uses `p_enrichment.ipinfo` (see `get_ipinfo_asn` in `kubernetes_helpers.py`). Without enrichment, legitimate-node filtering is limited and false positives are more likely. |

## Threshold / dedup semantics (upstream)

| Rule | Upstream `Threshold` | Notes |
|------|----------------------|-------|
| `k8s_secret_access_denied` | 20 (15 min window) | iota evaluates per-event; use for hunting until correlation is wired for this rule. |
| `k8s_multiple_403_public_ip` | 10 (30 min window) | Same. |

Azure `Azure.MonitorActivity` log types in upstream YAML are not ingested; those test cases do not apply until an Azure parser exists.
