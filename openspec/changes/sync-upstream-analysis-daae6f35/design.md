# Design: Upstream analysis sync boundaries

## In scope for single-event Python ports

- **CloudTrail**: Native JSON; use `iota_helpers` (`deep_get`, `is_successful`, `get_actor_user`, `aws_rule_context`) instead of vendor-specific event helpers (`event.deep_get` / `event.udm`).
- **Okta / GSuite / 1Password**: Same unwrap as today in `engines/iota/engine.py`; port rules that only need the raw system log object.

## Out of scope until platform support exists

| Upstream area | Reason |
|---------------|--------|
| `queries/`, `lookup_tables/`, Okta baseline YAML | Require scheduled SQL and vendor data models |
| Rules whose YAML sets `Threshold` > 1 | Platform correlation / counting not in iota’s per-event engine |
| `correlation_rules/` | No sequence engine |
| Kubernetes, CrowdStrike, SentinelOne, Azure, Proofpoint, Upwind, Auth0, GreyNoise (API) | No matching log type or live enrichment in iota |

## Severity resolution order

`get_severity(event)` tries `severity(event)` first, then `severity()` on `TypeError`, then `"INFO"`. Rules that only implement `severity(event)` are unchanged at the call site.
