# Cloudflare rules

Ported from upstream `cloudflare_rules` with `scripts/port_cloudflare_rules.py`. Set `IOTA_UPSTREAM_RULES` to your local clone root if it is not at `../redteamtools/upstream-analysis`.

## Correlation

`cloudflare_firewall_ddos.py` and `cloudflare_httpreq_bot_high_volume.py` use `rules/helpers/correlation_store.py` with upstream-aligned windows (60 minutes) and thresholds (100 and 7560). Dedup keys include zone, host, and client IP where applicable.

`cloudflare_react2shell_rce_attempt.py` is single-event.

High-volume HTTP logs: prefer filtering at ingest or sampling; see Cloudflare Logpush documentation for delivery options.
