# Entra identity review pack

The audit connector accepts Microsoft Graph directory audit exports through the existing `entra_audit` profile and content-based log detection. These rules identify successful sensitive changes for analyst review, not confirmed compromise.

| Rule | Activity | Validation |
| --- | --- | --- |
| DF-ENTRA-002 | Application/service-principal credential changes | Identify target and actor; compare against approved maintenance; examine subsequent sign-ins |
| DF-ENTRA-003 | Consent, delegated grants, app role assignments | Inspect exact granted permissions, recipient, publisher and consent approval |
| DF-ENTRA-004 | Directory role assignment | Identify role privilege, recipient and approval/PIM context |
| DF-ENTRA-005 | Service-principal credential addition followed by workload authentication | Requires same explicit target principal ID within 30 minutes; validate approved maintenance |

Application actors are retained under `details.actor_application_id`, `actor_application_name`, and `actor_id`. The canonical human `user` remains empty for application-only actors to avoid false human-identity correlations. Target identifiers, types, and modified property names are retained; original values remain available in raw evidence.

These activities can be legitimate. Current rules intentionally produce medium-severity review signals without guessing privilege from a display name. Activity aliases and export variants must be checked against telemetry from the intended tenant. Microsoft lists activity names in its [audit activity reference](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities) and describes grants in [application permission audit logs](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/app-perms-audit-logs).

## Demonstration

Create a case, upload `examples/identity_review.jsonl`, and select Auto or Entra audit. The synthetic sample produces three medium review alerts. It contains no credentials or real tenant data.

## Coverage and limits

- Modified property values, permission changes and role changes are parsed when present. Approval/PIM integration and authoritative permission privilege classification remain future work.
- Workload sign-ins and target-based credential/authentication sequences are supported within a case; use separate cases for separate tenants. Automatic tenant-boundary inference is not implemented.
- Analyst dispositions and validated AI citations are supported. Resolving a citation establishes provenance, not the correctness of the model's conclusion.

## Preview and explicit exclusions

The rule builder can preview an unsaved candidate against a selected case. It reports alert counts, suppression counts relative to the same rule without exclusions, and up to 20 matching event IDs. Preview does not install the rule, modify the case, or request AI analysis.

Optional exclusions are a JSON list of condition specifications, for example `[{"conditions":{"user":"approved@example.test","action":"Consent to application"}}]`. Conditions within one exclusion are ANDed; separate exclusions are ORed. Matching events are unavailable to that rule, including every correlation stage. Free-text known-false-positive guidance does not suppress events. Use narrow conditions and validate negative fixtures: a zero-alert preview is not evidence of correctness.
