# FreeRADIUS Use Cases, GUI Coverage, and Improvement Roadmap

Date: 2026-04-08

## Scope
This document summarizes:
- common FreeRADIUS use cases seen in real deployments,
- how the current FreeRADIUS Web GUI supports them,
- practical gaps and a phased implementation roadmap.

It also references public positioning themes from radius-as-a-service.com as directional market context (certificate-first auth, guest/BYOD workflows, SIEM integration, Entra admin/RBAC).

## Common FreeRADIUS Use Cases
1. Enterprise 802.1X with EAP-TLS for Wi-Fi/LAN/VPN
2. Credential-based auth (PEAP/EAP-TTLS) for legacy/non-certificate devices
3. NAS onboarding and lifecycle management (APs, switches, firewalls, VPN)
4. Guest and BYOD onboarding with limited-lifetime access
5. PKI lifecycle management (CSR, cert updates, trust chain, revocation checks)
6. Operations and troubleshooting (logs, validation failures, rollback)
7. SIEM/compliance workflows (audit logs, export/forwarding)
8. Accounting and usage reporting
9. High availability and resilience
10. Multi-tenant MSP-style operations

## Current GUI Coverage Assessment

### Strong Coverage
- Service controls and health:
  - Start/stop/restart, status, logs, summary metrics
- Safe config mutation model:
  - validate -> apply -> restart with rollback
- Config surfaces:
  - Simple mode for radiusd options, clients, modules, sites, policy
  - Advanced mode for editable/autodiscovered files
- Certificate management:
  - Server cert details/update/upload and CSR generation
  - Trusted roots listing/add/delete/details (system and custom)
- Access control:
  - Local/Entra/hybrid auth and RBAC-gated operations

### Partial Coverage
- Guest/BYOD is possible via manual policy editing but not guided workflows
- Troubleshooting exists but is not deeply guided for failure triage
- PKI lifecycle supports update/install basics, but not revocation automation

### Not Covered / Major Gaps
- Guided templates/wizards for common deployment patterns
- Guest self-service and delegated account workflows
- Persistent action-level audit trail and SIEM export path
- Accounting/reporting dashboards and export helpers
- Built-in HA/cluster orchestration guidance and controls
- True multi-tenant architecture

## Ease of Configuration (Operator Experience)
- Easy today:
  - module/site enablement,
  - NAS client CRUD,
  - direct option/policy edits for experienced admins,
  - cert and trust-root updates.
- Medium difficulty:
  - assembling production-grade EAP-TLS and PEAP workflows safely,
  - diagnosing auth failures quickly at scale.
- Hard/unsupported:
  - guest/BYOD operations at scale,
  - SIEM-ready auditing,
  - accounting analytics,
  - tenant isolation patterns.

## Phased Roadmap

### Phase 1: High-Impact Quick Wins
1. Policy templates and setup wizards
- EAP-TLS baseline wizard
- PEAP-MSCHAPv2 baseline wizard
- common VPN RADIUS baseline wizard

2. Bulk NAS onboarding
- CSV import
- validation preview
- rollback-safe apply behavior

3. Better failure diagnostics
- Surface backend validation details inline on apply failure
- Add common-failure hints (cert path mismatch, missing module, syntax errors)

4. Certificate lifecycle guardrails
- expiry alerts and warnings in dashboard/certs views

### Phase 2: Governance and Observability
1. Persistent audit trail for all mutating actions (who/when/what)
2. SIEM export integration points (structured logs/forwarding)
3. richer auth metrics (by server/module/failure category where possible)

### Phase 3: Advanced Workflows
1. Guest/BYOD operations pack
- account lifecycle templates
- delegated helpdesk-safe actions

2. Accounting/reporting foundation
- SQL/detail/linelog setup helpers
- basic usage reports

3. HA guidance in product docs and checks
- recommended self-hosted patterns (LB/failover/config sync)

## Prioritization Rationale
- Prioritize high-frequency admin workflows over broad feature parity.
- Keep expert direct-edit mode while layering guided workflows above it.
- Preserve validate/apply/rollback safety for all new write paths.

## Suggested Initial Deliverables
1. Add template catalog format and three starter templates (EAP-TLS, PEAP, VPN)
2. Add CSV NAS import endpoint and preview UI
3. Expand apply error UX to include backend details in failure status
4. Add cert expiry indicator in overview and cert sections

## Validation Criteria for the Roadmap
1. Generated configs validate cleanly with the configured validator command
2. Every mutating flow remains rollback-safe
3. New guided flows are RBAC-scoped and auditable
4. Troubleshooting time-to-resolution decreases for common misconfigurations
