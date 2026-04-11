# Tasks: Extended sources and correlation (planning)

## Charter and alignment

- [ ] Review `proposal.md` with owner; confirm phase order or edit proposal with agreed reorder.
- [ ] Link this change from `openspec/project.md` or README “Roadmap” if project prefers a single index (optional).

## Per-area next step (research → follow-on proposal)

Each row should end in either **Deferred**, **Spike**, or **OpenSpec change: &lt;id&gt;**.

- [ ] **Kubernetes:** Document target log shape (audit vs Falco vs cloud vendor); spike ingestion path; proposal for parser + sample rules.
- [ ] **EDR:** Pick one reference vendor for a spike; defer others.
- [ ] **Azure:** List minimum log types (Entra ID, Activity, Defender); map to iota ingestion (S3 vs EventBridge vs API).
- [ ] **Proofpoint:** Identify delivery mechanism (SIEM export, API, syslog); spike format.
- [ ] **Upwind:** Clarify product API/logs; CSPM overlap with future iota posture work.
- [ ] **Behavioral Okta:** Define baseline model (entity keys, windows, storage); dependency on query engine + scheduled evaluation.
- [ ] **Threshold-only rules:** Extract 3–5 representative rules from upstream; specify state + window semantics for iota.

## Platform prerequisites (cross-cutting)

- [ ] **Correlation:** Reference or create `add-correlation-mvp` proposal when engine design is ready.
- [ ] **Thresholds:** Reference or create `add-threshold-state` (or similar) proposal.
- [ ] **Baselines:** Reference query/schedule capabilities (DuckDB path, cron, or stream).

## Closure

- [ ] Archive this change after follow-on proposals exist and this charter is superseded (`openspec archive plan-extended-sources-correlation --skip-specs --yes` when appropriate).
