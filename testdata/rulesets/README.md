# Ruleset fixtures

Synthetic JSON for local testing when you do not have production logs. One folder per log family (aligned with `rules/<name>/`).

| Directory | Log type | Contents |
|-----------|----------|----------|
| `aws_bedrockmodelinvocation/` | `AWS.BedrockModelInvocation` | `samples.jsonl` (one `ModelInvocationLog` per line), `samples.records.json` (S3-style `{"Records":[...]}`) |

**Conventions**

- **JSONL**: one minified JSON object per line; matches how `iota --mode=once --jsonl=...` reads files.
- **Records**: optional; same objects wrapped as CloudTrail-style `Records` for pipelines that deliver a single JSON file with an array.

Add new folders as you port parsers (e.g. `github_audit/`, `gcp_auditlog/`). Prefer deriving shapes from upstream rule YAML `Tests:` blocks when possible.

**Smoke**

```bash
./scripts/smoke-bedrock.sh
```
