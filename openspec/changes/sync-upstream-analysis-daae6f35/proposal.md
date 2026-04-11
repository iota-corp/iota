# Proposal: Sync iota with upstream analysis rules (daae6f35)

## Why

The upstream analysis rules repository (synced under `redteamtools`) added many rules: Kubernetes, Proofpoint, Upwind, Okta behavioral baselines, and CloudTrail updates. iota only ingests CloudTrail, Okta, GSuite, and 1Password, and has no vendor-style **scheduled queries**, **lookup tables**, or **rule thresholds**—so we need a deliberate porting strategy and spec updates rather than copying the tree wholesale.

## What Changes

- **Detection engine (Python)**: Evaluate `severity(event)` when the rule defines a one-argument `severity` function, falling back to `severity()` for zero-argument rules. This matches how iota rules are already written (most use `severity(event)`) and aligns the runtime with `openspec/specs/detection-engine/spec.md`.
- **New CloudTrail rule**: Port logic from upstream `aws_overwrite_lambda_code` as `aws_lambda_update_function_code_interactive_identity`—successful `UpdateFunctionCode*` by IAM users, federated users, or IAM Identity Center (SSO) roles. This is a focused complement to the broader `aws_lambda_function_modified` rule.
- **Specs and project context**: Refresh `detection-engine` spec and `project.md` rule counts and document which upstream categories are **out of scope** until log pipelines or correlation exist.

## Impact

- **Operators**: Severity on alerts from rules using `severity(event)` will now reflect the rule’s logic instead of defaulting to `INFO`.
- **Scope**: Behavioral Okta rules that depend on Snowflake queries and baselines, Kubernetes/EDR/Azure/Proofpoint/Upwind rules, and threshold-only rules remain documented as future work—not silently implied as supported.

## References

- Upstream snapshot @ `daae6f35` (post-merge with main).
- Local mirror: analysis rules tree under `redteamtools`.
