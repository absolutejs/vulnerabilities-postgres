# Changelog

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
