# Tasks: add-rule-log-type-indexing

- [x] Add `engines/iota/log_type_index.py` (`PACK_LOG_TYPES`, `infer_log_type_from_event`, `pack_for_rule_file`).
- [x] Update `engines/iota/engine.py` — index rules by log type; `analyze(events, log_types)`; worker/oneshot read `log_types`.
- [x] Extend `internal/engine.Request` with `log_types`; `Analyze(ctx, events, logTypes []string)`.
- [x] Pass `ProcessedEvent.LogType` from EventBridge and S3 handlers; `runOnce` and `audit-tail`; `nil` for watch/s3-poll.
- [x] Go tests (`TestEngineAnalyzeSkipsPackByLogType`); Python `engines/iota/test_log_type_index.py`.
- [x] Update `openspec/specs/detection-engine/spec.md` and `openspec/specs/performance/spec.md`.
- [x] CI: run Python `unittest` for `engines/iota`.
- [ ] Archive when validated: `openspec archive add-rule-log-type-indexing --skip-specs --yes` (requires OpenSpec CLI).
