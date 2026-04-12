# Tasks: add-azure-entra-support

## Research
- [ ] Document Entra audit log JSON schema
- [ ] Document Entra sign-in log JSON schema
- [ ] Identify Entra P1/P2 licensing requirements for log export
- [ ] Survey Panther/Elastic open-source rules for Entra
- [ ] Decide ingestion path (Event Hubs vs SQS forwarder)

## Phase 1: Parsers
- [ ] internal/logprocessor/parsers/entra_audit.go
- [ ] internal/logprocessor/parsers/entra_audit_test.go
- [ ] internal/logprocessor/parsers/entra_signin.go (if separate shape)
- [ ] internal/logprocessor/parsers/entra_signin_test.go
- [ ] Register in internal/logprocessor/processor.go (getParsers map)
- [ ] testdata/rulesets/entra_audit/samples.jsonl
- [ ] testdata/rulesets/entra_signin/samples.jsonl
- [ ] processor_entra_fixtures_test.go

## Phase 2: Rules
- [ ] rules/entra_audit/README.md
- [ ] Hand-written critical rules (MFA disabled, privileged role assigned, suspicious sign-in, etc.)
- [ ] Ported rules via scripts/port_entra_rules.py

## Phase 3: Integration
- [ ] scripts/smoke-entra.sh
- [ ] docs/ARCHITECTURE.md: add Entra to diagram
- [ ] README.md: add Entra to supported sources
- [ ] openspec/specs/log-processing/spec.md: add Entra section

## Phase 4: End-to-end
- [ ] Deploy to homelab-test via Tailscale
- [ ] Real Entra audit logs flow through pipeline
- [ ] Alerts fire in Slack
