# Changelog

## [0.4.0](https://github.com/bilals12/iota/compare/v0.3.0...v0.4.0) (2026-04-02)


### Features

* **query:** align DuckDB and Glue paths with data lake via lakepath ([d9497e6](https://github.com/bilals12/iota/commit/d9497e6ac83c280ec94b326b56bf8cfc930bf493))

## [Unreleased]

### Features

- **Data lake / queries:** Introduce `internal/lakepath` so the data lake writer, Glue catalog, and DuckDB `iota query` paths share one layout: `logs/<table_slug>/year=…/month=…/day=…/hour=…/*.json.gz`. DuckDB uses `read_ndjson` with those globs (replacing Parquet placeholders that did not match stored objects). CLI shorthand `cloudtrail` canonicalizes to `AWS.CloudTrail` for slug and path generation.

### Added

- CI and local **smoke test** (`scripts/smoke.sh`, `make smoke`): build with CGO, run `once` mode on sample JSONL with the Python rules engine.

### Fixed

- **pre-commit:** pin an absolute `GOPATH` for `go-build` / `go-mod-tidy` / `golangci-lint` when the shell leaves `$HOME/go` unexpanded.

## [0.3.0](https://github.com/bilals12/iota/compare/v0.2.0...v0.3.0) (2026-03-27)

### Features

- unify release workflow and document Release Please token ([76d7a3e](https://github.com/bilals12/iota/commit/76d7a3e987c2495f6a69855c765255332bacb440))

## [0.2.0](https://github.com/bilals12/iota/compare/v0.1.0...v0.2.0) (2026-03-27)

### Features

- add DuckDB query engine for fast historical queries ([3370357](https://github.com/bilals12/iota/commit/3370357383a887a84bb20614cad7ec135913b856))
- add S3 ransomware/exfil and Okta security detection rules ([dabec7e](https://github.com/bilals12/iota/commit/dabec7e6584078f158aca25b49b2a83c88f7b710))
- adding eventbridge support and rules ([272805a](https://github.com/bilals12/iota/commit/272805a2a7cfefa48cf9b028b6233aa0bfbd98a2))
- adding more okta rules ([5dd3a30](https://github.com/bilals12/iota/commit/5dd3a308730b8c1c545530e4582d1e1976b88aaa))
- adding release please and unified release workflow ([#27](https://github.com/bilals12/iota/issues/27)) ([f72e832](https://github.com/bilals12/iota/commit/f72e832dc13ac83def799d64e15361248327b935))
- bootstrap OpenSpec for spec-driven development ([1eb0319](https://github.com/bilals12/iota/commit/1eb0319e8c7476985b7fa45d5f2822a536431734))
- pipeline architecture ([69293bb](https://github.com/bilals12/iota/commit/69293bbf26a6d61d77b13f3bbc4a8a5a90be4f49))
- refactoring release workflows to prepare for major version releases ([86ff479](https://github.com/bilals12/iota/commit/86ff4791009f31d43a6e4e33fb4397401ba55b48))

### Bug Fixes

- **engine:** resolve severity(event) in Python rules engine ([#25](https://github.com/bilals12/iota/issues/25)) ([06dd143](https://github.com/bilals12/iota/commit/06dd143ae0d042f47d5d1eee899c79f0e9057d81))
- okta event log parsing ([08403b4](https://github.com/bilals12/iota/commit/08403b484e7e5791db0887c2af3b54da59729039))

## How releases work

Everything is driven by **`/.github/workflows/release.yml`** (“Release pipeline”):

- **Push to `main`**: Release Please opens or updates the release PR (changelog + version bump). It uses the **`RELEASE_PLEASE_TOKEN`** secret (a fine‑grained PAT with contents and pull requests), not `GITHUB_TOKEN`, so that when you merge the release PR the tag push can trigger the publish jobs.
- **Tag `v*.*.*` or manual “Run workflow”** with a tag: build Linux binaries, attach them to the GitHub Release, build and push multi-arch images to Docker Hub (`bilals12/iota`).

If a tag or release exists but Docker Hub is empty, run the workflow manually and pass that tag (e.g. `v0.2.0`).

## Version bumps (conventional commits)

- `feat:` → minor version (e.g. 0.1.0 → 0.2.0)
- `fix:` / `perf:` → patch (e.g. 0.1.0 → 0.1.1)
- `feat!:` / `fix!:` / `BREAKING CHANGE:` → major when pre-1.0 is handled per config

`refactor:` and `chore:` are listed in the changelog when part of a release, but **do not bump the version** by themselves. Use `feat:` / `fix:` when a change should trigger a release, or batch refactors with a release that already includes a bumping commit.

## Troubleshooting Release Please

If the workflow fails with **“GitHub Actions is not permitted to create or approve pull requests”**, enable in the repo: **Settings → Actions → General → Workflow permissions** → select **Read and write permissions**, and turn on **Allow GitHub Actions to create and approve pull requests**. The workflow already sets `permissions: contents: write` and `pull-requests: write`; the checkbox is still required for PR creation.

If Release Please **creates a tag and release but binaries or Docker images never appear**, the publish job likely did not run because the tag was created with the default **`GITHUB_TOKEN`** (GitHub does not trigger workflow runs from those events). **Fix the secret `RELEASE_PLEASE_TOKEN`** (PAT) on the Release Please step and re-run or merge a new release; use **Actions → Release pipeline → Run workflow** with the tag to backfill binaries and images.
