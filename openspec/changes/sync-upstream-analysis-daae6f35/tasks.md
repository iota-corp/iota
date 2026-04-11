## 1. Engine

- [x] 1.1 Update `engines/iota/engine.py`: pass unwrapped event into severity resolution; support `severity(event)` and `severity()`.

## 2. Rules

- [x] 2.1 Add `rules/aws_cloudtrail/aws_lambda_update_function_code_interactive_identity.py` (from upstream `aws_overwrite_lambda_code`).

## 3. Specs and docs

- [x] 3.1 Update `openspec/specs/detection-engine/spec.md` (severity scenario, rule count).
- [x] 3.2 Update `openspec/project.md` detection coverage counts.

## 4. Validation

- [x] 4.1 Run `go test ./...` from repo root.
- [x] 4.2 Smoke-load new rule module with Python.
