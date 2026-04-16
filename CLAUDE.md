# iota — guide for coding agents

Use this file as the **entry point** when working in this repository with Claude, Cursor, or similar tools. It points to the canonical docs so you do not duplicate long context in chat.

## Read first

| Document                                         | Purpose                                                                                                        |
| ------------------------------------------------ | -------------------------------------------------------------------------------------------------------------- |
| **[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)**   | Contributor handbook: OpenSpec, branches/PRs, **local testing & TDD**, repo map, pipeline notes, GitOps links. |
| **[openspec/AGENTS.md](openspec/AGENTS.md)**     | OpenSpec workflow detail (Turo-style: specs in `openspec/specs/`, changes under `openspec/changes/<id>/`).     |
| **[openspec/project.md](openspec/project.md)**   | Product context, log types, conventions.                                                                       |
| **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** | System architecture and diagrams (reference, not step-by-step).                                                |
| **[docs/TIER-B-C.md](docs/TIER-B-C.md)**         | SQS/EventBridge tuning env vars, parallelism, Tier C ops (DLQ, replicas).                                      |
| **[TESTING.md](TESTING.md)**                     | Deep dive: fixtures, CloudTrail tests, gunzip examples.                                                        |

## Minimum commands (before proposing code)

```bash
export CGO_ENABLED=1
go test ./...
./scripts/smoke.sh
# or: make ci-local
```

## OpenSpec in one line

Non-trivial behavior changes start with a **change id** under `openspec/changes/<id>/` (`proposal.md`, `tasks.md`, optional `design.md`) and updates to **`openspec/specs/`**. See `openspec/AGENTS.md` for the full checklist and when to skip a proposal.

## Related repos

| Repo                                                                  | Role                                                                      |
| --------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| **iota** (here)                                                       | Application, parsers, rules, `Dockerfile`, `deployments/kubernetes/base`. |
| **[iota-deployments](https://github.com/iota-corp/iota-deployments)** | Kustomize overlays per cluster; image tags; Argo CD apps.                 |
| **[iota-infra](https://github.com/iota-corp/iota-infra)**             | Terraform (IAM, EKS, queues, etc., depending on environment).             |

Do not confuse **iota** (code) with **iota-deployments** (what runs where) or **iota-infra** (cloud IAM/topology).
