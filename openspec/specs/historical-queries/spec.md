---
version: 1.0.0
status: active
owner: bilals12
---

# Capability: Historical Queries

Query interface for the data lake, enabling ad-hoc analysis, compliance reporting, and incident response investigations.

## Requirements

### Requirement: Athena Query Execution

The system SHALL support executing SQL queries against the data lake via AWS Athena.

#### Scenario: Successful query

- **GIVEN** a valid SQL query
- **AND** a configured Athena workgroup and database
- **WHEN** the query is submitted
- **THEN** the system SHALL poll for completion
- **AND** return results when succeeded

#### Scenario: Query timeout

- **GIVEN** a query that exceeds the maximum wait time (5 minutes)
- **WHEN** polling for results
- **THEN** the system SHALL return a timeout error

#### Scenario: Query failure

- **GIVEN** a query with invalid SQL or permissions error
- **WHEN** Athena reports failure
- **THEN** the system SHALL return the failure reason

### Requirement: Data lake S3 layout (query pruning)

Lake objects SHALL use a consistent key prefix so time-bounded queries scan only relevant prefixes.

#### Scenario: Hourly partition path

- **GIVEN** a flushed batch for log type `AWS.CloudTrail` and event hour `2024-03-15T14:00:00Z`
- **WHEN** the object key is generated
- **THEN** it SHALL begin with `logs/aws_cloudtrail/year=2024/month=03/day=15/hour=14/`
- **AND** the filename SHALL end with `.json.gz`

(Log type segments use the same slug as `getTableName`: dots → underscores, lowercased.)

### Requirement: Glue Catalog Integration

The system SHALL register data lake tables and partitions in AWS Glue Catalog.

#### Scenario: Table creation

- **GIVEN** a new log type
- **WHEN** the data lake writer initializes
- **THEN** a Glue table SHALL be created with appropriate schema
- **AND** partition keys for year/month/day/hour

#### Scenario: Partition registration

- **GIVEN** a data lake flush to S3
- **WHEN** new hourly data is written
- **THEN** a Glue partition SHALL be added
- **AND** subsequent Athena queries SHALL include the new data

## Current Implementation

- **Location**: `internal/athena/query.go`, `internal/glue/catalog.go`
- **Poll interval**: 2 seconds
- **Max wait time**: 5 minutes
- **Query latency**: 30 seconds to 5+ minutes depending on data volume

## Known Limitations

1. **Query latency**: Athena has inherent latency from query queueing and data scanning. Not suitable for rapid iteration during incident response.

2. **Cold start**: First query after idle period may take longer due to Athena worker provisioning.

3. **Concurrent queries**: Limited by Athena concurrency limits per workgroup.

4. **Cost**: Charged per TB scanned. Large historical queries can be expensive.

5. **DuckDB + JSON.GZ**: `read_ndjson` expects gzip-wrapped newline-delimited JSON. If on-disk objects use a different encoding (e.g. concatenated gzip members per record), queries may need a format adjustment or a compaction step to standard NDJSON.GZ or Parquet.

## Related Changes

- `add-fast-historical-queries`: Proposal to add DuckDB for sub-second queries on recent data
