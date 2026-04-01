# Proposal: IR-friendly data path and ingestion discipline

## Why

Incident responders need **fast, predictable queries** over the data lake. That depends less on swapping the SQL engine alone than on **how data is grouped on S3** (partition pruning), **batching writes** (fewer objects, fewer round trips), and **safe replay** (idempotency) when SQS or pipelines redeliver work.

This change series applies the “TigerBeetle lessons” **without** TigerBeetle: tighter batches, explicit layouts, and measurable hot paths—on top of existing DuckDB/Athena query code.

## Goals

1. **Document and lock in** the lake layout (log type → table name, `year/month/day/hour` partitions) so DuckDB and Athena can prune scans.
2. **Prevent regressions** in partition paths and table naming via tests.
3. **Iterate in small PRs**: optional hardening (e.g. message-level dedupe, projection columns) follows separate tasks.

## Non-goals (this change id)

- Replacing DuckDB or Athena.
- New log sources (see `plan-extended-sources-correlation`).

## Success criteria

- Specs or code clearly describe the **canonical S3 key pattern** for lake objects.
- Tests fail if partition layout or table slug changes unintentionally.

## References

- `internal/datalake/writer.go`
- `internal/query/engine.go` (`buildS3Paths`)
- `openspec/changes/add-fast-historical-queries/`
