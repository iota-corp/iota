# Versioning and release rubric

iota uses **semantic versions** (`MAJOR.MINOR.PATCH`, tagged as `vMAJOR.MINOR.PATCH`) and **Conventional Commits** for commit messages. The bump from the previous tag to the next is computed by `scripts/next-release-version.sh` from all commits since the latest `v*.*.*` tag (merge commits are ignored; commits from merged branches are included).

## Bump rules

| Effect | Commit types / triggers |
|--------|-------------------------|
| **Major** | `feat:` — any change that adds, adjusts, or removes API or UI behavior; **or** a breaking change: `BREAKING CHANGE:` / `BREAKING-CHANGE:` in the commit body, or `!` after the type (e.g. `feat!:`, `chore!:`). |
| **Minor** | `fix:`, `refactor:`, `perf:` — fixes to prior features, internal rewrites without API/UI change, or performance work that does not change API/UI semantics. |
| **Patch** | `style:`, `test:`, `docs:`, `build:`, `ops:`, `chore:`, and any message that does not match the conventional pattern. |

When several commits are released together, the **strongest** bump wins (major over minor over patch).

## Commit type reference

- **feat** — Adds, adjusts, or removes a feature for the API or UI.
- **fix** — Fixes an API or UI bug introduced by an earlier `feat`.
- **refactor** — Restructures code without changing API or UI behavior.
- **perf** — Performance-focused refactors (same bump as **refactor**).
- **style** — Formatting, whitespace, etc.; no behavior change.
- **test** — Tests only.
- **docs** — Documentation only.
- **build** — Build tools, dependencies, project version metadata, etc.
- **ops** — Infrastructure, deployment, CI/CD, backups, monitoring, recovery.
- **chore** — Repo housekeeping (e.g. `.gitignore`), tooling that does not fit elsewhere.

## Relation to Argo CD

Pushes to **main** in `iota` can create a new tag; the **Release** workflow then builds and pushes the image and (if configured) updates **`iota-deployments`** so the tag in `clusters/*/kustomization.yaml` matches. Argo CD reconciles from the **deployments** Git repo; applying manifests locally does not change what Argo tracks until those changes are **pushed** to the remote the Application points at.

## Local vs CI

- **CI:** Push to `main` → workflow may create the next tag → publish job runs on that tag.
- **Local:** Run `./scripts/next-release-version.sh`, then `git tag` / `git push origin <tag>` (see `make release-help`). To refresh the live cluster via GitOps, push the tag and any `iota-deployments` updates to the remotes Argo watches.

Use `[skip release]` in a commit subject to push to `main` without cutting a release from that push.

## CLI default `--mode`

The **`cmd/iota`** default **`--mode`** is **`eventbridge`** (aligned with low-latency CloudTrail API ingestion). Scripts or containers that relied on the previous default **`sqs`** must pass **`--mode=sqs`** explicitly. Kubernetes manifests in **iota** / **iota-deployments** that already set **`--mode=sqs`** in **`args`** are unchanged.
