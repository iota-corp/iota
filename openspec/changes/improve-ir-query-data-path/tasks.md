# Tasks: IR query data path

## Done in repo (baseline)

- [x] Smoke test for `once` mode (`scripts/smoke.sh`, CI).
- [x] Data lake writer batches by log type + hour; flushes on size/age (`internal/datalake/writer.go`).
- [x] S3 state cursor per bucket/account/region for CloudTrail keys (`cmd/iota/sqs_handler.go`).

## This series

- [x] Regression tests for lake partition path and table slug (`internal/datalake/writer_test.go`).
- [x] Document canonical layout in `openspec/specs/historical-queries/spec.md`.
- [ ] Optional: `buildS3Paths` integration test vs same layout as writer (query engine ↔ writer alignment).
- [ ] Optional: SQS visibility / receipt-level idempotency notes or implementation (separate PR).
