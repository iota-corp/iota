# Slack audit rules

Ported from upstream `slack_rules` via `scripts/port_slack_rules.py`. Set `IOTA_UPSTREAM_RULES` to your local clone root if it is not at `../redteamtools/upstream-analysis`.

## Correlation

`slack_application_dos.py` uses sliding-window counting (`rules/helpers/correlation_store.py`): 60 matching events per dedup key within 24 hours. State lives in `IOTA_CORRELATION_STATE` (default `~/.cache/iota/correlation.sqlite`). Set `IOTA_CORRELATION=0` to evaluate base conditions only (not recommended for production).
