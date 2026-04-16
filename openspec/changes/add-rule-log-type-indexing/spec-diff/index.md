# Spec diff: add-rule-log-type-indexing

Manual summary (regenerate with `/openspec-spec-diff` if the project uses automated annotation).

## `openspec/specs/detection-engine/spec.md`

- **Rule filtering by log type:** Implementation detail added — pack directory + `log_types` / inference; unknown packs remain unindexed.
- **Batch / engine request:** Optional parallel `log_types` on the Python request when Go knows classifier output.

## `openspec/specs/performance/spec.md`

- **Rule selection cost:** Notes current implementation (`log_type_index.py` + `log_types`).
