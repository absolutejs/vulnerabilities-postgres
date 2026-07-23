import { PGlite } from "@electric-sql/pglite";
import {
  DEFAULT_VULNERABILITY_ALERT_CONFIGURATION,
  type VulnerabilityAlert,
} from "@absolutejs/vulnerabilities";
import { afterAll, beforeAll, expect, test } from "bun:test";
import { drizzle } from "drizzle-orm/pglite";
import {
  createDrizzleVulnerabilityAlertStores,
  vulnerabilityAlertPostgresSchemaSql,
  VulnerabilityAlertConflictError,
} from "../src";

const actorId = "9ecdfd74-df85-4df7-8563-b0dc47c75df5";
const tenantId = "drizzle-alert-test";
const alert: VulnerabilityAlert = {
  assetId: "b08b61d8-c4b6-4664-a0fa-d86089162c9a",
  body: "A critical vulnerability requires remediation.",
  dueAt: "2026-07-23T17:00:00.000Z",
  findingId: "finding-drizzle",
  fingerprint: "drizzle-alert-fingerprint",
  id: "alert-drizzle",
  kind: "remediation_plan_overdue",
  observedAt: "2026-07-23T16:00:00.000Z",
  planId: null,
  severity: "critical",
  sourceId: "source-drizzle",
  tenantId,
  title: "Critical vulnerability",
};

const client = new PGlite();
const db = drizzle({ client });
const store = createDrizzleVulnerabilityAlertStores(db);

beforeAll(async () => {
  await client.exec(vulnerabilityAlertPostgresSchemaSql());
});

afterAll(async () => {
  await client.close();
});

test("runs the schema-derived alert lifecycle with native JSONB", async () => {
  const policy = await store.alertPolicies.activate({
    activatedAt: "2026-07-23T16:00:00.000Z",
    activatedBy: actorId,
    configuration: structuredClone(DEFAULT_VULNERABILITY_ALERT_CONFIGURATION),
    reason: "Drizzle lifecycle conformance",
    tenantId,
  });
  expect(policy.version).toBe(1);
  expect(await store.alertIncidents.observe({ alert, policy })).toBe("opened");
  expect(await store.alertIncidents.observe({ alert, policy })).toBe(
    "observed",
  );
  expect((await store.alertIncidents.incidents())[0]?.observation_count).toBe(
    2,
  );

  const [delivery] = await store.alertIncidents.claimDeliveries({
    tenantIds: [tenantId],
  });
  expect(delivery?.audience).toBe("owner");
  expect(
    await store.alertIncidents.failDelivery({
      alertId: alert.id,
      deliveryId: delivery!.id,
      error: "Synthetic provider failure",
      kind: "opened",
      retryAt: "2026-07-23T16:01:00.000Z",
    }),
  ).toBe(true);
  await client.query(
    "UPDATE vulnerability_alert_deliveries SET next_attempt_at = now()",
  );
  const [retry] = await store.alertIncidents.claimDeliveries({
    tenantIds: [tenantId],
  });
  expect(retry?.attempt_count).toBe(2);
  expect(
    await store.alertIncidents.completeDelivery({
      alertId: alert.id,
      audience: "owner",
      deliveryId: retry!.id,
      kind: "opened",
    }),
  ).toBe(true);

  expect(
    await store.alertIncidents.acknowledge({
      acknowledgedAt: "2026-07-23T16:02:00.000Z",
      acknowledgedBy: actorId,
      alertId: alert.id,
    }),
  ).toBe(true);
  expect(
    await store.alertIncidents.resolveInactive({
      activeAlertIds: new Set(),
      policies: new Map([[tenantId, policy]]),
      resolvedAt: "2026-07-23T16:03:00.000Z",
    }),
  ).toBe(1);
  await expect(
    store.alertIncidents.acknowledge({
      acknowledgedAt: "2026-07-23T16:04:00.000Z",
      acknowledgedBy: actorId,
      alertId: alert.id,
    }),
  ).rejects.toBeInstanceOf(VulnerabilityAlertConflictError);
  expect(await store.alertIncidents.observe({ alert, policy })).toBe(
    "reopened",
  );

  const jsonTypes = await client.query<{
    metadata_type: string;
    policy_type: string;
    value_type: string;
  }>(`
    SELECT
      jsonb_typeof(i.value) AS value_type,
      jsonb_typeof(e.metadata) AS metadata_type,
      jsonb_typeof(p.configuration) AS policy_type
    FROM vulnerability_alert_incidents i
    JOIN vulnerability_alert_events e ON e.alert_id = i.alert_id
    JOIN vulnerability_alert_policy_versions p ON p.tenant_id = i.tenant_id
    LIMIT 1
  `);
  expect(jsonTypes.rows[0]).toEqual({
    metadata_type: "object",
    policy_type: "object",
    value_type: "object",
  });
});
