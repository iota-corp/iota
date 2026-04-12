# Tasks: add-azure-resource-diagnostic-settings

## Research
- [ ] Document Azure activity log JSON schema
- [ ] Document Azure resource log schemas (varies by resource type)
- [ ] Map diagnostic settings export options (Event Hub, Storage Account, Log Analytics)
- [ ] Survey Panther/Elastic open-source rules for Azure activity logs
- [ ] Decide ingestion path (Event Hubs vs SQS forwarder)
- [ ] Identify which resource types to support first (NSG flow, Key Vault, App Gateway, etc.)

## Phase 1: Parsers
- [ ] internal/logprocessor/parsers/azure_activity.go
- [ ] internal/logprocessor/parsers/azure_activity_test.go
- [ ] internal/logprocessor/parsers/azure_resource.go (if separate shape per resource type)
- [ ] internal/logprocessor/parsers/azure_resource_test.go
- [ ] Register in internal/logprocessor/processor.go (getParsers map)
- [ ] testdata/rulesets/azure_activity/samples.jsonl
- [ ] testdata/rulesets/azure_resource/samples.jsonl
- [ ] processor_azure_fixtures_test.go

## Phase 2: Rules
- [ ] rules/azure_activity/README.md
- [ ] Hand-written critical rules (resource deletion, RBAC changes, policy modifications, etc.)
- [ ] Ported rules via scripts/port_azure_rules.py

## Phase 3: Integration
- [ ] scripts/smoke-azure.sh
- [ ] docs/ARCHITECTURE.md: add Azure to diagram
- [ ] README.md: add Azure to supported sources
- [ ] openspec/specs/log-processing/spec.md: add Azure section

## Phase 4: End-to-end
- [ ] Deploy to homelab-test via Tailscale
- [ ] Real Azure activity logs flow through pipeline
- [ ] Alerts fire in Slack
