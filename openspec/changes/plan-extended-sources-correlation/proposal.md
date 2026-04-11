# Proposal: Extended detection sources and adjacent patterns (roadmap)

## Why

`openspec/changes/sync-upstream-analysis-daae6f35/proposal.md` marked several upstream categories as **explicitly out of scope** until **log pipelines** or **correlation** (and, for some cases, **stateful baselines** or **threshold infrastructure**) exist:

| Category | Typical blocker |
|----------|------------------|
| **Kubernetes** | New log pipeline (audit/API server), parsers, optional correlation across workload events |
| **EDR** | Vendor-specific log formats and ingestion (CrowdStrike, SentinelOne, etc.) |
| **Azure** | Azure AD / Activity / Defender pipelines distinct from AWS CloudTrail |
| **Proofpoint** | SaaS email-security logs + ingestion (often API or file drop) |
| **Upwind** | CSPM/vendor-specific integration |
| **Behavioral Okta (Snowflake / baselines)** | Long-window aggregates, per-entity baselines, storage—**not** single-event rules |
| **Threshold-only patterns** | Stateful counters over a time window + reset semantics, often separate from one-shot rules |

This change **does not implement** those detections. It **defines the plan**: prerequisites, ordering, and exit criteria so implementation work can be proposed in smaller, reviewable chunks.

## What this change produces

1. A **dependency matrix** (below) tying each category to: pipeline, correlation, baselines store, threshold engine.
2. A **recommended phase order** for iota (aligned with existing Phase 3 themes: parsers → correlation → query/state).
3. **`tasks.md`** as the checklist for **research and follow-on proposals** (not production code in this change).

## Dependency matrix

| Area | Log pipeline / parser | Correlation (multi-event) | Stateful baselines | Thresholds / schedules |
|------|------------------------|---------------------------|--------------------|-------------------------|
| Kubernetes | **Required** | Often useful | Optional | Useful |
| EDR | **Required** | Sometimes | Sometimes | Often |
| Azure | **Required** | Sometimes | Sometimes | Sometimes |
| Proofpoint | **Required** | Rare | Rare | Sometimes |
| Upwind | **Required** | Depends | CSPM-style | Depends |
| Behavioral Okta | Partial (Okta exists) | **Often** | **Required** (baseline store) | **Required** |
| Threshold-only (rate / count) | Optional | Sometimes | **Required** | **Required** |

**Implication:** “Correlation OR pipelines” was shorthand. In practice:

- **Pipelines** unlock **new log types** (K8s, Azure, Proofpoint, EDR, Upwind).
- **Correlation** unlocks **multi-step** logic across events.
- **Baselines + thresholds** unlock **behavioral Okta** and **threshold-only** rules—usually **on top of** a query or state layer (e.g. DuckDB/SQLite/scheduled jobs), not inside a single `rule(event)`.

## Recommended phase order (for follow-on proposals)

1. **Foundation (already in flight elsewhere):** Adaptive classifier, parsers, consistent ingest for `AWS.*`, SaaS via EventBridge—so new sources plug into the same path.
2. **Correlation MVP:** Minimal engine + contract for multi-event rules (enables multi-step patterns that are not baseline-only).
3. **Threshold / state layer:** Windowed counts, per-key state, schedule or stream triggers—unblocks **threshold-only** and simple **rate** rules without full Snowflake.
4. **Baselines (behavioral Okta):** Define storage (aggregate tables, rolling stats), refresh cadence, and how rules reference “normal vs anomaly”—likely **after** fast query + optional scheduled jobs.
5. **Per-vendor pipelines (parallel tracks after 1–2):** Pick **one** of K8s audit, Azure AD, or a single EDR format as the first **new** source to avoid boiling the ocean.

## Out of scope for *this* change (documentation only)

- Implementing parsers, correlation code, or new rule packs.
- Committing to a specific vendor (e.g. CrowdStrike vs SentinelOne) before a spike.

## Success criteria

- [ ] Stakeholders agree on **phase order** or document explicit reordering.
- [ ] Each category in the matrix has a **named next step** (spike vs proposal vs deferred).
- [ ] Follow-on work is filed as **separate** OpenSpec changes (e.g. `add-correlation-mvp`, `add-threshold-engine`, `add-k8s-audit-pipeline`).

## References

- `openspec/changes/sync-upstream-analysis-daae6f35/proposal.md`
- `GAP_ANALYSIS.md`, `PHASE_3_PLAN.md`, `IMPLEMENTATION_ROADMAP.md`
- `openspec/specs/log-processing/spec.md`, `openspec/specs/detection-engine/spec.md`
