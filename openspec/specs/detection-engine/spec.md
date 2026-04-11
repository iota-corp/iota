---
version: 1.0.0
status: active
owner: bilals12
---

# Capability: Detection Engine

Core detection pipeline that evaluates security events against Python rules and generates alerts.

## Requirements

### Requirement: Python Rule Evaluation

The system SHALL execute Python detection rules against normalized events and return matches.

#### Scenario: Rule matches event

- **GIVEN** a normalized CloudTrail event
- **WHEN** the event matches a rule's `rule(event)` function (returns True)
- **THEN** the system SHALL generate an alert with title from `title(event)`
- **AND** severity from `severity(event)`
- **AND** include the full event payload

#### Scenario: Rule does not match

- **GIVEN** a normalized event
- **WHEN** the rule's `rule(event)` function returns False
- **THEN** no alert SHALL be generated for that rule

#### Scenario: Rule execution error

- **GIVEN** a rule that raises an exception
- **WHEN** the rule is evaluated
- **THEN** the error SHALL be logged
- **AND** processing SHALL continue with remaining rules

### Requirement: Rule Discovery

The system SHALL automatically discover and load Python rules from the rules directory.

#### Scenario: Loading rules from directory

- **GIVEN** a rules directory path
- **WHEN** the engine initializes
- **THEN** it SHALL recursively find all `.py` files
- **AND** load rules that define `rule()`, `title()`, and `severity()` functions

#### Scenario: Rule filtering by log type

- **GIVEN** rules organized in `rules/{log_type}/` directories
- **WHEN** processing an event with known log type
- **THEN** only rules matching that log type SHALL be evaluated

**Note:** The reference Python engine (`engines/iota/engine.py`) evaluates every loaded rule against every event in a batch. For production throughput, deployments SHOULD point `--rules` at a single pack or a symlinked subtree (per pipeline / log source) rather than the full tree, or split workloads so each binary does not load unrelated packs. See `openspec/project.md` (Multi-source deployments).

### Requirement: Extended rule packs

The system SHALL support organizing Python detection rules for additional sources under `rules/<logical_source>/` (e.g. `rules/github_audit/`, `rules/gcp_auditlog/`) consistent with upstream YAML rule folders in the mirrored analysis tree under `redteamtools`.

#### Scenario: Ported upstream rule behavior

- **GIVEN** a rule ported from upstream `AnalysisType: rule` with `Threshold: 1` (or equivalent single-shot semantics)
- **WHEN** the normalized event matches the ported `rule(event)` logic
- **THEN** the system SHALL emit an alert with `title(event)` and `severity(event)` as for existing rules

#### Scenario: Out of scope upstream patterns

- **GIVEN** a rule that requires upstream scheduled queries, lookup tables, or correlation-only packs (not expressible as per-event Python)
- **WHEN** planning iota ports
- **THEN** such rules SHALL be deferred or redesigned; sliding-window and string-set state MAY use `rules/helpers/correlation_store.py` where ported

### Requirement: Batch Processing

The system SHALL support processing events in batches for efficiency.

#### Scenario: Batch analysis

- **GIVEN** a batch of events
- **WHEN** `engine.Analyze(events)` is called
- **THEN** all events SHALL be evaluated against applicable rules
- **AND** all matches SHALL be returned as a single result set

### Requirement: Alert Output

The system SHALL output alerts as structured JSON to stdout.

#### Scenario: Alert JSON format

- **GIVEN** a rule match
- **WHEN** the alert is generated
- **THEN** output SHALL include:
  - `rule_id`: Rule identifier (filename without extension)
  - `title`: Human-readable title from `title(event)`
  - `severity`: CRITICAL/HIGH/MEDIUM/LOW/INFO
  - `dedup`: Deduplication key
  - `event`: Full event payload

### Requirement: Rule severity signature

The Python engine SHALL resolve severity by invoking `severity(event)` when the rule defines a one-parameter severity function, and SHALL fall back to `severity()` when the rule defines a zero-parameter severity function.

#### Scenario: Event-aware severity

- **GIVEN** a rule that defines `severity(event)` returning a level based on the event
- **WHEN** a match is produced
- **THEN** the alert SHALL use the string returned by `severity(event)`

## Current Implementation

- **Location**: `internal/engine/engine.go`, `engines/iota/engine.py`
- **Rule Count**: 254 Python rules under `rules/` (excluding `rules/helpers/`), across CloudTrail, IAM, S3 access, VPC Flow, ALB, Bedrock model invocation, GCP audit and HTTP LB, Kubernetes (EKS/GKE-unified pack), GitHub audit and webhook, Slack audit, Cloudflare firewall/React2Shell, Okta, GSuite, 1Password
- **Execution**: Python subprocess via `exec.Command`
