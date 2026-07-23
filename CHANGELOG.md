# Changelog

## 0.9.0 - 2026-07-23

- Export the complete package-owned Drizzle schema and
  `createDrizzleVulnerabilityStore(db)` for feeds, records, sync history,
  leases, findings, observations, risk, remediation, VEX, and alerts.
- Preserve atomic snapshot replacement, tenant filters, validation, lease
  fencing, and native JSONB without a tagged-template SQL client.
- Add PostgreSQL-semantic Drizzle conformance for replacement, filtering,
  leases, and physical JSONB types.

## 0.8.0 - 2026-07-23

- Export package-owned Drizzle schemas and lifecycle stores for vulnerability
  alert policies, incidents, events, and leased deliveries.
- Preserve atomic recurrence, escalation, resolution, acknowledgment,
  idempotent routing, and `FOR UPDATE SKIP LOCKED` delivery claims without a
  tagged-template SQL client.
- Encode JSONB through typed database expressions for Bun SQL and Drizzle RC
  compatibility.

## 0.7.0 - 2026-07-19

- Accept and retain the 0.14 evidence witness operational alert kinds through
  the existing durable incident, escalation, resolution, and delivery stores.

## 0.6.2 - 2026-07-18

- Export a typed alert-policy validation error so applications can distinguish
  invalid operator input from database failures.

## 0.6.1 - 2026-07-18

- Preserve nullable versions for built-in alert policies and allow lifecycle
  processing to use an explicit fallback policy for inactive tenants.

## 0.6.0 - 2026-07-18

- Add immutable tenant alert-policy version persistence.
- Add atomic alert incident observation, acknowledgement, escalation,
  resolution, and recurrence transitions.
- Add durable event history and idempotent, leased notification delivery queues.
- Export the alert schema and package-owned read models used by admin consoles.

## 0.5.3 - 2026-07-18

- Verify durable feed, VEX, risk, and remediation stores against
  `@absolutejs/vulnerabilities@0.10.0`.

## 0.5.1 - 2026-07-18

- Consume exact-release remediation verification from vulnerability core 0.8.1.

## 0.5.0 - 2026-07-18

- Add tenant-scoped remediation plan, execution, and verification persistence.

## 0.4.0 - 2026-07-18

- Add tenant-scoped VEX decision and finding-application persistence.

## 0.1.0 - 2026-07-18

- Add durable feed snapshots and atomic record replacement.
- Add filterable feed synchronization history.
- Add tenant-scoped managed finding persistence.
- Add expiring distributed refresh leases.
- Add lazy idempotent schema creation and migration-ready DDL export.
