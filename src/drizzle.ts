import { and, asc, desc, eq, inArray, lte, max, or, sql } from "drizzle-orm";
import {
  bigserial,
  customType,
  index,
  integer,
  pgTable,
  primaryKey,
  text,
  timestamp,
  uniqueIndex,
  uuid,
  type PgAsyncDatabase,
} from "drizzle-orm/pg-core";
import {
  resolveVulnerabilityAlertAudiences,
  validateVulnerabilityAlertConfiguration,
  type VulnerabilityAlert,
  type VulnerabilityAlertConfiguration,
} from "@absolutejs/vulnerabilities";
import {
  VulnerabilityAlertConflictError,
  VulnerabilityAlertNotFoundError,
  VulnerabilityAlertValidationError,
  type VulnerabilityAlertIncidentStore,
  type VulnerabilityAlertPolicyStore,
} from "./alerts";

const databaseNow = sql<Date>`now()`;
const portableJsonb = customType<{ data: unknown; driverData: unknown }>({
  dataType: () => "jsonb",
  fromDriver: (value) =>
    typeof value === "string" ? JSON.parse(value) : value,
  toDriver: (value) => JSON.stringify(value),
});
const encodedJsonb = <Value>(value: Value) =>
  sql<Value>`${JSON.stringify(value)}::text::jsonb`;
const boundedLimit = (value = 1_000) => {
  if (!Number.isInteger(value) || value < 1 || value > 1_000)
    throw new Error("Alert query limit must be an integer from 1 through 1000");
  return value;
};

export const vulnerabilityAlertPolicyVersions = pgTable(
  "vulnerability_alert_policy_versions",
  {
    activated_at: timestamp({ mode: "date", withTimezone: true }).notNull(),
    activated_by: uuid().notNull(),
    configuration: portableJsonb()
      .$type<VulnerabilityAlertConfiguration>()
      .notNull(),
    reason: text().notNull(),
    status: text().$type<"active" | "superseded">().notNull(),
    tenant_id: text().notNull(),
    version: integer().notNull(),
  },
  (table) => [
    primaryKey({ columns: [table.tenant_id, table.version] }),
    uniqueIndex("vulnerability_alert_policy_versions_active_idx")
      .on(table.tenant_id)
      .where(sql`${table.status} = 'active'`),
    index("vulnerability_alert_policy_versions_history_idx").on(
      table.tenant_id,
      table.activated_at,
    ),
  ],
);

export const vulnerabilityAlertIncidents = pgTable(
  "vulnerability_alert_incidents",
  {
    acknowledged_at: timestamp({ mode: "date", withTimezone: true }),
    acknowledged_by: uuid(),
    alert_id: text().primaryKey(),
    asset_id: text(),
    body: text().notNull(),
    due_at: timestamp({ mode: "date", withTimezone: true }),
    finding_id: text(),
    first_observed_at: timestamp({
      mode: "date",
      withTimezone: true,
    }).notNull(),
    kind: text().$type<VulnerabilityAlert["kind"]>().notNull(),
    last_observed_at: timestamp({
      mode: "date",
      withTimezone: true,
    }).notNull(),
    next_escalation_at: timestamp({ mode: "date", withTimezone: true }),
    observation_count: integer().notNull().default(1),
    occurrence_count: integer().notNull().default(1),
    plan_id: text(),
    policy_version: integer(),
    resolved_at: timestamp({ mode: "date", withTimezone: true }),
    severity: text().$type<VulnerabilityAlert["severity"]>().notNull(),
    source_id: text(),
    status: text()
      .$type<"acknowledged" | "open" | "resolved">()
      .notNull()
      .default("open"),
    tenant_id: text().notNull(),
    title: text().notNull(),
    updated_at: timestamp({ mode: "date", withTimezone: true })
      .notNull()
      .defaultNow(),
    value: portableJsonb().$type<VulnerabilityAlert>().notNull(),
  },
  (table) => [
    index("vulnerability_alert_incidents_status_idx").on(
      table.status,
      table.last_observed_at,
    ),
    index("vulnerability_alert_incidents_tenant_idx").on(
      table.tenant_id,
      table.status,
    ),
    index("vulnerability_alert_incidents_escalation_idx").on(
      table.status,
      table.next_escalation_at,
    ),
  ],
);

export const vulnerabilityAlertEvents = pgTable(
  "vulnerability_alert_events",
  {
    actor_id: uuid(),
    alert_id: text()
      .notNull()
      .references(() => vulnerabilityAlertIncidents.alert_id, {
        onDelete: "cascade",
      }),
    created_at: timestamp({ mode: "date", withTimezone: true })
      .notNull()
      .defaultNow(),
    id: bigserial({ mode: "number" }).primaryKey(),
    kind: text()
      .$type<
        | "acknowledged"
        | "alert_dismissed"
        | "alert_retried"
        | "delivery_failed"
        | "delivered"
        | "escalated"
        | "observed"
        | "opened"
        | "resolved"
      >()
      .notNull(),
    metadata: portableJsonb()
      .$type<Record<string, unknown>>()
      .notNull()
      .default(sql`'{}'::jsonb`),
  },
  (table) => [
    index("vulnerability_alert_events_alert_idx").on(
      table.alert_id,
      table.created_at,
    ),
  ],
);

export const vulnerabilityAlertDeliveries = pgTable(
  "vulnerability_alert_deliveries",
  {
    alert_id: text()
      .notNull()
      .references(() => vulnerabilityAlertIncidents.alert_id, {
        onDelete: "cascade",
      }),
    attempt_count: integer().notNull().default(0),
    audience: text().$type<"admin" | "owner">().notNull(),
    created_at: timestamp({ mode: "date", withTimezone: true })
      .notNull()
      .defaultNow(),
    delivered_at: timestamp({ mode: "date", withTimezone: true }),
    id: uuid().primaryKey().defaultRandom(),
    idempotency_key: text().notNull(),
    kind: text().$type<"escalated" | "opened" | "resolved">().notNull(),
    last_error: text(),
    lease_expires_at: timestamp({ mode: "date", withTimezone: true }),
    next_attempt_at: timestamp({ mode: "date", withTimezone: true })
      .notNull()
      .defaultNow(),
    state: text()
      .$type<"delivered" | "delivering" | "dismissed" | "failed" | "pending">()
      .notNull()
      .default("pending"),
    updated_at: timestamp({ mode: "date", withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    uniqueIndex("vulnerability_alert_deliveries_key_idx").on(
      table.idempotency_key,
    ),
    index("vulnerability_alert_deliveries_state_idx").on(
      table.state,
      table.next_attempt_at,
    ),
  ],
);

export const vulnerabilityAlertDrizzleSchema = {
  vulnerabilityAlertDeliveries,
  vulnerabilityAlertEvents,
  vulnerabilityAlertIncidents,
  vulnerabilityAlertPolicyVersions,
};

type AnyPgDatabase = PgAsyncDatabase<any, any>;
type Transaction = AnyPgDatabase;

const queue = async (
  transaction: Transaction,
  alert: Pick<VulnerabilityAlert, "assetId" | "id" | "severity">,
  configuration: VulnerabilityAlertConfiguration,
  kind: "escalated" | "opened" | "resolved",
  occurrence: number,
) => {
  const audiences = resolveVulnerabilityAlertAudiences({
    configuration,
    hasOwner: alert.assetId !== null,
    kind,
    severity: alert.severity,
  });
  if (audiences.length === 0) return;
  await transaction
    .insert(vulnerabilityAlertDeliveries)
    .values(
      audiences.map((audience) => ({
        alert_id: alert.id,
        audience,
        id: crypto.randomUUID(),
        idempotency_key: `${alert.id}:${audience}:${kind}:${occurrence}`,
        kind,
      })),
    )
    .onConflictDoNothing({
      target: vulnerabilityAlertDeliveries.idempotency_key,
    });
};

export const createDrizzleVulnerabilityAlertStores = <DB extends AnyPgDatabase>(
  db: DB,
): {
  alertIncidents: VulnerabilityAlertIncidentStore;
  alertPolicies: VulnerabilityAlertPolicyStore;
} => {
  const alertPolicies: VulnerabilityAlertPolicyStore = {
    activate: async (input) => {
      let configuration: VulnerabilityAlertConfiguration;
      try {
        configuration = validateVulnerabilityAlertConfiguration(
          input.configuration,
        );
      } catch (error) {
        throw new VulnerabilityAlertValidationError(
          error instanceof Error ? error.message : "Policy is invalid",
        );
      }
      const reason = input.reason.trim();
      if (!reason)
        throw new VulnerabilityAlertValidationError(
          "Policy activation reason is required",
        );
      return db.transaction(async (transaction) => {
        await transaction.execute(
          sql`SELECT pg_advisory_xact_lock(hashtext(${`vulnerability-alert-policy:${input.tenantId}`}))`,
        );
        const [latest] = await transaction
          .select({
            version: sql<number>`COALESCE(${max(vulnerabilityAlertPolicyVersions.version)}, 0)::integer`,
          })
          .from(vulnerabilityAlertPolicyVersions)
          .where(
            eq(vulnerabilityAlertPolicyVersions.tenant_id, input.tenantId),
          );
        const version = (latest?.version ?? 0) + 1;
        await transaction
          .update(vulnerabilityAlertPolicyVersions)
          .set({ status: "superseded" })
          .where(
            and(
              eq(vulnerabilityAlertPolicyVersions.tenant_id, input.tenantId),
              eq(vulnerabilityAlertPolicyVersions.status, "active"),
            ),
          );
        await transaction.insert(vulnerabilityAlertPolicyVersions).values({
          activated_at: new Date(input.activatedAt),
          activated_by: input.activatedBy,
          configuration: encodedJsonb(configuration),
          reason,
          status: "active",
          tenant_id: input.tenantId,
          version,
        });
        return {
          activatedAt: input.activatedAt,
          configuration,
          reason,
          tenantId: input.tenantId,
          version,
        };
      });
    },
    active: async () => {
      const rows = await db
        .select({
          configuration: vulnerabilityAlertPolicyVersions.configuration,
          tenantId: vulnerabilityAlertPolicyVersions.tenant_id,
          version: vulnerabilityAlertPolicyVersions.version,
        })
        .from(vulnerabilityAlertPolicyVersions)
        .where(eq(vulnerabilityAlertPolicyVersions.status, "active"));
      return rows.map((row) => ({
        configuration: validateVulnerabilityAlertConfiguration(
          row.configuration,
        ),
        tenantId: row.tenantId,
        version: row.version,
      }));
    },
    list: (requestedLimit) =>
      db
        .select()
        .from(vulnerabilityAlertPolicyVersions)
        .orderBy(desc(vulnerabilityAlertPolicyVersions.activated_at))
        .limit(boundedLimit(requestedLimit)),
  };

  const observe: VulnerabilityAlertIncidentStore["observe"] = async ({
    alert,
    policy,
    observedAt,
  }) => {
    const at = observedAt ?? new Date().toISOString();
    const configuration = validateVulnerabilityAlertConfiguration(
      policy.configuration,
    );
    return db.transaction(async (transaction) => {
      const [existing] = await transaction
        .select({
          occurrenceCount: vulnerabilityAlertIncidents.occurrence_count,
          status: vulnerabilityAlertIncidents.status,
        })
        .from(vulnerabilityAlertIncidents)
        .where(eq(vulnerabilityAlertIncidents.alert_id, alert.id))
        .for("update")
        .limit(1);
      const reopened = existing?.status === "resolved";
      const nextEscalationAt = new Date(
        new Date(at).getTime() +
          configuration.escalationAfterMs[alert.severity],
      );
      await transaction
        .insert(vulnerabilityAlertIncidents)
        .values({
          alert_id: alert.id,
          asset_id: alert.assetId,
          body: alert.body,
          due_at: alert.dueAt ? new Date(alert.dueAt) : null,
          finding_id: alert.findingId,
          first_observed_at: new Date(alert.observedAt),
          kind: alert.kind,
          last_observed_at: new Date(alert.observedAt),
          next_escalation_at: nextEscalationAt,
          plan_id: alert.planId,
          policy_version: policy.version,
          severity: alert.severity,
          source_id: alert.sourceId,
          status: "open",
          tenant_id: alert.tenantId,
          title: alert.title,
          value: encodedJsonb(alert),
        })
        .onConflictDoUpdate({
          set: {
            asset_id: sql`excluded.asset_id`,
            body: sql`excluded.body`,
            due_at: sql`excluded.due_at`,
            finding_id: sql`excluded.finding_id`,
            last_observed_at: sql`excluded.last_observed_at`,
            next_escalation_at: sql`CASE
              WHEN ${vulnerabilityAlertIncidents.status} = 'resolved'
                THEN excluded.next_escalation_at
              WHEN ${vulnerabilityAlertIncidents.status} = 'open'
                AND ${vulnerabilityAlertIncidents.policy_version}
                  IS DISTINCT FROM excluded.policy_version
                THEN excluded.next_escalation_at
              ELSE ${vulnerabilityAlertIncidents.next_escalation_at}
            END`,
            observation_count: sql`${vulnerabilityAlertIncidents.observation_count} + 1`,
            occurrence_count: sql`CASE
              WHEN ${vulnerabilityAlertIncidents.status} = 'resolved'
                THEN ${vulnerabilityAlertIncidents.occurrence_count} + 1
              ELSE ${vulnerabilityAlertIncidents.occurrence_count}
            END`,
            plan_id: sql`excluded.plan_id`,
            policy_version: sql`excluded.policy_version`,
            resolved_at: sql`CASE
              WHEN ${vulnerabilityAlertIncidents.status} = 'resolved'
                THEN null
              ELSE ${vulnerabilityAlertIncidents.resolved_at}
            END`,
            severity: sql`excluded.severity`,
            source_id: sql`excluded.source_id`,
            status: sql`CASE
              WHEN ${vulnerabilityAlertIncidents.status} = 'resolved'
                THEN 'open'
              ELSE ${vulnerabilityAlertIncidents.status}
            END`,
            tenant_id: sql`excluded.tenant_id`,
            title: sql`excluded.title`,
            updated_at: databaseNow,
            value: sql`excluded.value`,
          },
          target: vulnerabilityAlertIncidents.alert_id,
        });
      if (!existing || reopened) {
        await transaction.insert(vulnerabilityAlertEvents).values({
          alert_id: alert.id,
          kind: "opened",
          metadata: encodedJsonb({}),
        });
        await queue(
          transaction,
          alert,
          configuration,
          "opened",
          existing ? existing.occurrenceCount + 1 : 1,
        );
      }
      return !existing ? "opened" : reopened ? "reopened" : "observed";
    });
  };

  const alertIncidents: VulnerabilityAlertIncidentStore = {
    acknowledge: (input) =>
      db.transaction(async (transaction) => {
        const [present] = await transaction
          .select({ status: vulnerabilityAlertIncidents.status })
          .from(vulnerabilityAlertIncidents)
          .where(eq(vulnerabilityAlertIncidents.alert_id, input.alertId))
          .for("update")
          .limit(1);
        if (!present)
          throw new VulnerabilityAlertNotFoundError(
            "Vulnerability alert not found",
          );
        if (present.status === "resolved")
          throw new VulnerabilityAlertConflictError(
            "Resolved vulnerability alerts cannot be acknowledged",
          );
        if (present.status === "acknowledged") return false;
        await transaction
          .update(vulnerabilityAlertIncidents)
          .set({
            acknowledged_at: new Date(input.acknowledgedAt),
            acknowledged_by: input.acknowledgedBy,
            next_escalation_at: null,
            status: "acknowledged",
            updated_at: new Date(input.acknowledgedAt),
          })
          .where(eq(vulnerabilityAlertIncidents.alert_id, input.alertId));
        await transaction.insert(vulnerabilityAlertEvents).values({
          actor_id: input.acknowledgedBy,
          alert_id: input.alertId,
          kind: "acknowledged",
          metadata: encodedJsonb({}),
        });
        return true;
      }),
    claimDeliveries: (input = {}) =>
      db.transaction(async (transaction) => {
        const leaseMs = input.leaseMs ?? 300_000;
        const queryLimit = boundedLimit(input.limit ?? 100);
        const due = or(
          and(
            inArray(vulnerabilityAlertDeliveries.state, ["pending", "failed"]),
            lte(vulnerabilityAlertDeliveries.next_attempt_at, databaseNow),
          ),
          and(
            eq(vulnerabilityAlertDeliveries.state, "delivering"),
            lte(vulnerabilityAlertDeliveries.lease_expires_at, databaseNow),
          ),
        );
        const candidates = await transaction
          .select({ id: vulnerabilityAlertDeliveries.id })
          .from(vulnerabilityAlertDeliveries)
          .innerJoin(
            vulnerabilityAlertIncidents,
            eq(
              vulnerabilityAlertIncidents.alert_id,
              vulnerabilityAlertDeliveries.alert_id,
            ),
          )
          .where(
            and(
              due,
              input.tenantIds && input.tenantIds.length > 0
                ? inArray(vulnerabilityAlertIncidents.tenant_id, [
                    ...input.tenantIds,
                  ])
                : undefined,
            ),
          )
          .orderBy(asc(vulnerabilityAlertDeliveries.created_at))
          .limit(queryLimit)
          .for("update", {
            of: vulnerabilityAlertDeliveries,
            skipLocked: true,
          });
        const ids = candidates.map(({ id }) => id);
        if (ids.length === 0) return [];
        await transaction
          .update(vulnerabilityAlertDeliveries)
          .set({
            attempt_count: sql`${vulnerabilityAlertDeliveries.attempt_count} + 1`,
            lease_expires_at: sql`now() + ${leaseMs} * interval '1 millisecond'`,
            state: "delivering",
            updated_at: databaseNow,
          })
          .where(inArray(vulnerabilityAlertDeliveries.id, ids));
        return transaction
          .select({
            alert_id: vulnerabilityAlertDeliveries.alert_id,
            asset_id: vulnerabilityAlertIncidents.asset_id,
            attempt_count: vulnerabilityAlertDeliveries.attempt_count,
            audience: vulnerabilityAlertDeliveries.audience,
            body: vulnerabilityAlertIncidents.body,
            created_at: vulnerabilityAlertDeliveries.created_at,
            delivered_at: vulnerabilityAlertDeliveries.delivered_at,
            id: vulnerabilityAlertDeliveries.id,
            idempotency_key: vulnerabilityAlertDeliveries.idempotency_key,
            kind: vulnerabilityAlertDeliveries.kind,
            last_error: vulnerabilityAlertDeliveries.last_error,
            lease_expires_at: vulnerabilityAlertDeliveries.lease_expires_at,
            next_attempt_at: vulnerabilityAlertDeliveries.next_attempt_at,
            severity: vulnerabilityAlertIncidents.severity,
            state: vulnerabilityAlertDeliveries.state,
            tenant_id: vulnerabilityAlertIncidents.tenant_id,
            title: vulnerabilityAlertIncidents.title,
            updated_at: vulnerabilityAlertDeliveries.updated_at,
          })
          .from(vulnerabilityAlertDeliveries)
          .innerJoin(
            vulnerabilityAlertIncidents,
            eq(
              vulnerabilityAlertIncidents.alert_id,
              vulnerabilityAlertDeliveries.alert_id,
            ),
          )
          .where(inArray(vulnerabilityAlertDeliveries.id, ids));
      }),
    completeDelivery: (input) =>
      db.transaction(async (transaction) => {
        const updated = await transaction
          .update(vulnerabilityAlertDeliveries)
          .set({
            delivered_at: databaseNow,
            last_error: null,
            lease_expires_at: null,
            state: "delivered",
            updated_at: databaseNow,
          })
          .where(
            and(
              eq(vulnerabilityAlertDeliveries.id, input.deliveryId),
              eq(vulnerabilityAlertDeliveries.state, "delivering"),
            ),
          )
          .returning({ id: vulnerabilityAlertDeliveries.id });
        if (updated.length === 0) return false;
        await transaction.insert(vulnerabilityAlertEvents).values({
          alert_id: input.alertId,
          kind: "delivered",
          metadata: encodedJsonb({
            audience: input.audience,
            kind: input.kind,
          }),
        });
        return true;
      }),
    deliveries: (requestedLimit) =>
      db
        .select()
        .from(vulnerabilityAlertDeliveries)
        .orderBy(desc(vulnerabilityAlertDeliveries.created_at))
        .limit(boundedLimit(requestedLimit)),
    events: (requestedLimit) =>
      db
        .select()
        .from(vulnerabilityAlertEvents)
        .orderBy(desc(vulnerabilityAlertEvents.created_at))
        .limit(boundedLimit(requestedLimit)),
    failDelivery: (input) =>
      db.transaction(async (transaction) => {
        const updated = await transaction
          .update(vulnerabilityAlertDeliveries)
          .set({
            last_error: input.error,
            lease_expires_at: null,
            next_attempt_at: new Date(input.retryAt),
            state: "failed",
            updated_at: databaseNow,
          })
          .where(
            and(
              eq(vulnerabilityAlertDeliveries.id, input.deliveryId),
              eq(vulnerabilityAlertDeliveries.state, "delivering"),
            ),
          )
          .returning({ id: vulnerabilityAlertDeliveries.id });
        if (updated.length === 0) return false;
        await transaction.insert(vulnerabilityAlertEvents).values({
          alert_id: input.alertId,
          kind: "delivery_failed",
          metadata: encodedJsonb({ error: input.error, kind: input.kind }),
        });
        return true;
      }),
    incidents: (requestedLimit) =>
      db
        .select()
        .from(vulnerabilityAlertIncidents)
        .orderBy(desc(vulnerabilityAlertIncidents.last_observed_at))
        .limit(boundedLimit(requestedLimit)),
    observe,
    processEscalations: async ({ fallbackPolicy, policies, tenantIds }) => {
      const due = await db
        .select({
          alertId: vulnerabilityAlertIncidents.alert_id,
          assetId: vulnerabilityAlertIncidents.asset_id,
          occurrenceCount: vulnerabilityAlertIncidents.occurrence_count,
          severity: vulnerabilityAlertIncidents.severity,
          tenantId: vulnerabilityAlertIncidents.tenant_id,
        })
        .from(vulnerabilityAlertIncidents)
        .where(
          and(
            eq(vulnerabilityAlertIncidents.status, "open"),
            lte(vulnerabilityAlertIncidents.next_escalation_at, databaseNow),
            tenantIds && tenantIds.length > 0
              ? inArray(vulnerabilityAlertIncidents.tenant_id, [...tenantIds])
              : undefined,
          ),
        );
      let processed = 0;
      for (const incident of due) {
        const policy = policies.get(incident.tenantId) ?? fallbackPolicy;
        if (!policy) continue;
        const changed = await db.transaction(async (transaction) => {
          const claimed = await transaction
            .update(vulnerabilityAlertIncidents)
            .set({
              next_escalation_at: null,
              updated_at: databaseNow,
            })
            .where(
              and(
                eq(vulnerabilityAlertIncidents.alert_id, incident.alertId),
                eq(vulnerabilityAlertIncidents.status, "open"),
                lte(
                  vulnerabilityAlertIncidents.next_escalation_at,
                  databaseNow,
                ),
              ),
            )
            .returning({ id: vulnerabilityAlertIncidents.alert_id });
          if (claimed.length === 0) return false;
          await transaction.insert(vulnerabilityAlertEvents).values({
            alert_id: incident.alertId,
            kind: "escalated",
            metadata: encodedJsonb({}),
          });
          await queue(
            transaction,
            {
              assetId: incident.assetId,
              id: incident.alertId,
              severity: incident.severity,
            },
            policy.configuration,
            "escalated",
            incident.occurrenceCount,
          );
          return true;
        });
        if (changed) processed += 1;
      }
      return processed;
    },
    resolveInactive: async ({
      activeAlertIds,
      fallbackPolicy,
      policies,
      resolvedAt,
      tenantIds,
    }) => {
      const open = await db
        .select({
          alertId: vulnerabilityAlertIncidents.alert_id,
          assetId: vulnerabilityAlertIncidents.asset_id,
          occurrenceCount: vulnerabilityAlertIncidents.occurrence_count,
          severity: vulnerabilityAlertIncidents.severity,
          tenantId: vulnerabilityAlertIncidents.tenant_id,
        })
        .from(vulnerabilityAlertIncidents)
        .where(
          and(
            inArray(vulnerabilityAlertIncidents.status, [
              "open",
              "acknowledged",
            ]),
            tenantIds && tenantIds.length > 0
              ? inArray(vulnerabilityAlertIncidents.tenant_id, [...tenantIds])
              : undefined,
          ),
        );
      const at = new Date(resolvedAt ?? new Date().toISOString());
      let processed = 0;
      for (const incident of open) {
        if (activeAlertIds.has(incident.alertId)) continue;
        const policy = policies.get(incident.tenantId) ?? fallbackPolicy;
        if (!policy) continue;
        const changed = await db.transaction(async (transaction) => {
          const resolved = await transaction
            .update(vulnerabilityAlertIncidents)
            .set({
              next_escalation_at: null,
              resolved_at: at,
              status: "resolved",
              updated_at: databaseNow,
            })
            .where(
              and(
                eq(vulnerabilityAlertIncidents.alert_id, incident.alertId),
                inArray(vulnerabilityAlertIncidents.status, [
                  "open",
                  "acknowledged",
                ]),
              ),
            )
            .returning({ id: vulnerabilityAlertIncidents.alert_id });
          if (resolved.length === 0) return false;
          await transaction.insert(vulnerabilityAlertEvents).values({
            alert_id: incident.alertId,
            kind: "resolved",
            metadata: encodedJsonb({}),
          });
          await queue(
            transaction,
            {
              assetId: incident.assetId,
              id: incident.alertId,
              severity: incident.severity,
            },
            policy.configuration,
            "resolved",
            incident.occurrenceCount,
          );
          return true;
        });
        if (changed) processed += 1;
      }
      return processed;
    },
  };

  return { alertIncidents, alertPolicies };
};
