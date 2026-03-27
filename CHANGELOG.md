# Changelog

Releases and version bumps are managed by [Release Please](https://github.com/googleapis/release-please). Merge the release PR it opens to publish a version tag, GitHub Release notes, container images, and Linux binaries.

## Version bumps (conventional commits)

- `feat:` → minor version (e.g. 0.1.0 → 0.2.0)
- `fix:` / `perf:` → patch (e.g. 0.1.0 → 0.1.1)
- `feat!:` / `fix!:` / `BREAKING CHANGE:` → major when pre-1.0 is handled per config

`refactor:` and `chore:` are listed in the changelog when part of a release, but **do not bump the version** by themselves. Use `feat:` / `fix:` when a change should trigger a release, or batch refactors with a release that already includes a bumping commit.

## Troubleshooting Release Please

If the workflow fails with **“GitHub Actions is not permitted to create or approve pull requests”**, enable in the repo: **Settings → Actions → General → Workflow permissions** → select **Read and write permissions**, and turn on **Allow GitHub Actions to create and approve pull requests**. The workflow already sets `permissions: contents: write` and `pull-requests: write`; the checkbox is still required for PR creation.
