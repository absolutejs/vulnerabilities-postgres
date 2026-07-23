import {
  ManagedVulnerabilityFindingSchema,
  RemediationExecutionSchema,
  RemediationPlanSchema,
  RemediationVerificationSchema,
  VexDecisionSchema,
  VexFindingApplicationSchema,
  VulnerabilityObservationSchema,
  VulnerabilityRiskAssessmentSchema,
  type FeedCursor,
  type FeedSnapshotStore,
  type FeedSyncRun,
  type FeedSyncRunFilter,
  type FeedSyncRunStore,
  type ManagedFindingFilter,
  type ManagedFindingStore,
  type ManagedVulnerabilityFinding,
  type RemediationExecution,
  type RemediationExecutionStore,
  type RemediationPlan,
  type RemediationPlanFilter,
  type RemediationPlanStore,
  type RemediationVerification,
  type RemediationVerificationStore,
  type VexDecision,
  type VexDecisionFilter,
  type VexDecisionStore,
  type VexFindingApplication,
  type VexFindingApplicationStore,
  type VulnerabilityObservation,
  type VulnerabilityObservationFilter,
  type VulnerabilityObservationStore,
  type VulnerabilityRiskAssessment,
  type VulnerabilityRiskAssessmentFilter,
  type VulnerabilityRiskAssessmentStore,
} from "@absolutejs/vulnerabilities";
import { Value } from "@sinclair/typebox/value";
import { and, desc, eq, lte, notInArray, or, sql } from "drizzle-orm";
import {
  check,
  index,
  integer,
  jsonb,
  pgTable,
  primaryKey,
  text,
  timestamp,
  type PgAsyncDatabase,
} from "drizzle-orm/pg-core";
import { createDrizzleVulnerabilityAlertStores } from "./drizzle";
import type { FeedLeaseStore, PostgresVulnerabilityStore } from "./index";

const encodedJsonb = <Value>(value: Value) =>
  sql<Value>`${JSON.stringify(value)}::text::jsonb`;
const databaseNow = sql<Date>`now()`;

const requiredText = (value: string, label: string) => {
  const normalized = value.trim();
  if (normalized.length === 0) throw new Error(`${label} is required`);
  return normalized;
};

const boundedLimit = (value: number | undefined, fallback = 100) => {
  const normalized = value ?? fallback;
  if (!Number.isInteger(normalized) || normalized < 1 || normalized > 1_000)
    throw new Error(
      "Postgres query limit must be an integer from 1 through 1000",
    );
  return normalized;
};

const valid = <Value>(
  schema: Parameters<typeof Value.Check>[0],
  value: Value,
  label: string,
) => {
  if (!Value.Check(schema, value)) throw new Error(`${label} is invalid`);
  return value;
};

const iso = (value: Date) => value.toISOString();

export const vulnerabilityFeedSnapshots = pgTable(
  "vulnerability_feed_snapshots",
  {
    cursor: jsonb().$type<FeedCursor>().notNull(),
    feed_id: text().primaryKey(),
    feed_name: text().notNull(),
    feed_url: text().notNull(),
    fetched_at: timestamp({ mode: "date", withTimezone: true }).notNull(),
    revision: text(),
    updated_at: timestamp({ mode: "date", withTimezone: true })
      .notNull()
      .defaultNow(),
  },
);

export const vulnerabilityFeedRecords = pgTable(
  "vulnerability_feed_records",
  {
    feed_id: text()
      .notNull()
      .references(() => vulnerabilityFeedSnapshots.feed_id, {
        onDelete: "cascade",
      }),
    modified_at: timestamp({ mode: "date", withTimezone: true }).notNull(),
    record_id: text().notNull(),
    value: jsonb().notNull(),
  },
  (table) => [
    primaryKey({ columns: [table.feed_id, table.record_id] }),
    index("vulnerability_feed_records_modified_idx").on(
      table.feed_id,
      table.modified_at,
    ),
  ],
);

export const vulnerabilityFeedSyncRuns = pgTable(
  "vulnerability_feed_sync_runs",
  {
    completed_at: timestamp({ mode: "date", withTimezone: true }).notNull(),
    error: text(),
    feed_id: text().notNull(),
    id: text().primaryKey(),
    records: integer().notNull(),
    revision: text(),
    started_at: timestamp({ mode: "date", withTimezone: true }).notNull(),
    status: text()
      .$type<"failed" | "not_modified" | "stale" | "updated">()
      .notNull(),
  },
  (table) => [
    check(
      "vulnerability_feed_sync_runs_records_check",
      sql`${table.records} >= 0`,
    ),
    check(
      "vulnerability_feed_sync_runs_status_check",
      sql`${table.status} IN ('failed', 'not_modified', 'stale', 'updated')`,
    ),
    index("vulnerability_feed_sync_runs_feed_started_idx").on(
      table.feed_id,
      table.started_at,
    ),
    index("vulnerability_feed_sync_runs_status_started_idx").on(
      table.status,
      table.started_at,
    ),
  ],
);

export const vulnerabilityFindings = pgTable(
  "vulnerability_findings",
  {
    asset_id: text().notNull(),
    component_id: text().notNull(),
    finding_id: text().notNull(),
    first_seen_at: timestamp({
      mode: "date",
      withTimezone: true,
    }).notNull(),
    last_seen_at: timestamp({ mode: "date", withTimezone: true }).notNull(),
    severity: text().notNull(),
    status: text().notNull(),
    tenant_id: text().notNull(),
    updated_at: timestamp({ mode: "date", withTimezone: true })
      .notNull()
      .defaultNow(),
    value: jsonb().$type<ManagedVulnerabilityFinding>().notNull(),
  },
  (table) => [
    primaryKey({ columns: [table.tenant_id, table.finding_id] }),
    index("vulnerability_findings_tenant_status_idx").on(
      table.tenant_id,
      table.status,
      table.last_seen_at,
    ),
    index("vulnerability_findings_tenant_severity_idx").on(
      table.tenant_id,
      table.severity,
      table.last_seen_at,
    ),
    index("vulnerability_findings_tenant_asset_idx").on(
      table.tenant_id,
      table.asset_id,
      table.last_seen_at,
    ),
  ],
);

export const vulnerabilityObservations = pgTable(
  "vulnerability_observations",
  {
    asset_id: text().notNull(),
    component_id: text().notNull(),
    observation_id: text().notNull(),
    observed_at: timestamp({ mode: "date", withTimezone: true }).notNull(),
    tenant_id: text().notNull(),
    updated_at: timestamp({ mode: "date", withTimezone: true })
      .notNull()
      .defaultNow(),
    value: jsonb().$type<VulnerabilityObservation>().notNull(),
  },
  (table) => [
    primaryKey({ columns: [table.tenant_id, table.observation_id] }),
    index("vulnerability_observations_tenant_asset_idx").on(
      table.tenant_id,
      table.asset_id,
      table.observed_at,
    ),
    index("vulnerability_observations_tenant_component_idx").on(
      table.tenant_id,
      table.component_id,
      table.observed_at,
    ),
  ],
);

export const vulnerabilityRiskAssessments = pgTable(
  "vulnerability_risk_assessments",
  {
    assessed_at: timestamp({ mode: "date", withTimezone: true }).notNull(),
    finding_id: text().notNull(),
    priority: text().notNull(),
    remediate_by: timestamp({ mode: "date", withTimezone: true }),
    tenant_id: text().notNull(),
    updated_at: timestamp({ mode: "date", withTimezone: true })
      .notNull()
      .defaultNow(),
    value: jsonb().$type<VulnerabilityRiskAssessment>().notNull(),
  },
  (table) => [
    primaryKey({ columns: [table.tenant_id, table.finding_id] }),
    index("vulnerability_risk_assessments_tenant_priority_idx").on(
      table.tenant_id,
      table.priority,
      table.assessed_at,
    ),
    index("vulnerability_risk_assessments_tenant_due_idx")
      .on(table.tenant_id, table.remediate_by)
      .where(sql`${table.remediate_by} IS NOT NULL`),
  ],
);

export const vulnerabilityRemediationPlans = pgTable(
  "vulnerability_remediation_plans",
  {
    created_at: timestamp({ mode: "date", withTimezone: true }).notNull(),
    plan_id: text().notNull(),
    status: text().notNull(),
    tenant_id: text().notNull(),
    updated_at: timestamp({ mode: "date", withTimezone: true })
      .notNull()
      .defaultNow(),
    value: jsonb().$type<RemediationPlan>().notNull(),
  },
  (table) => [
    primaryKey({ columns: [table.tenant_id, table.plan_id] }),
    index("vulnerability_remediation_plans_tenant_status_idx").on(
      table.tenant_id,
      table.status,
      table.created_at,
    ),
  ],
);

export const vulnerabilityRemediationExecutions = pgTable(
  "vulnerability_remediation_executions",
  {
    completed_at: timestamp({ mode: "date", withTimezone: true }),
    execution_id: text().notNull(),
    plan_id: text().notNull(),
    started_at: timestamp({ mode: "date", withTimezone: true }).notNull(),
    status: text().notNull(),
    tenant_id: text().notNull(),
    updated_at: timestamp({ mode: "date", withTimezone: true })
      .notNull()
      .defaultNow(),
    value: jsonb().$type<RemediationExecution>().notNull(),
  },
  (table) => [
    primaryKey({ columns: [table.tenant_id, table.execution_id] }),
    index("vulnerability_remediation_executions_tenant_plan_idx").on(
      table.tenant_id,
      table.plan_id,
      table.started_at,
    ),
  ],
);

export const vulnerabilityRemediationVerifications = pgTable(
  "vulnerability_remediation_verifications",
  {
    execution_id: text().notNull(),
    observed_at: timestamp({ mode: "date", withTimezone: true }).notNull(),
    plan_id: text().notNull(),
    status: text().notNull(),
    tenant_id: text().notNull(),
    updated_at: timestamp({ mode: "date", withTimezone: true })
      .notNull()
      .defaultNow(),
    value: jsonb().$type<RemediationVerification>().notNull(),
    verification_id: text().notNull(),
  },
  (table) => [
    primaryKey({ columns: [table.tenant_id, table.verification_id] }),
    index("vulnerability_remediation_verifications_tenant_execution_idx").on(
      table.tenant_id,
      table.execution_id,
      table.observed_at,
    ),
  ],
);

export const vulnerabilityVexDecisions = pgTable(
  "vulnerability_vex_decisions",
  {
    created_at: timestamp({ mode: "date", withTimezone: true }).notNull(),
    decision_id: text().notNull(),
    expires_at: timestamp({ mode: "date", withTimezone: true }),
    product_id: text().notNull(),
    status: text().notNull(),
    tenant_id: text().notNull(),
    updated_at: timestamp({ mode: "date", withTimezone: true })
      .notNull()
      .defaultNow(),
    value: jsonb().$type<VexDecision>().notNull(),
    vulnerability_id: text().notNull(),
  },
  (table) => [
    primaryKey({ columns: [table.tenant_id, table.decision_id] }),
    index("vulnerability_vex_decisions_tenant_product_idx").on(
      table.tenant_id,
      table.product_id,
      table.created_at,
    ),
    index("vulnerability_vex_decisions_tenant_vulnerability_idx").on(
      table.tenant_id,
      table.vulnerability_id,
      table.created_at,
    ),
  ],
);

export const vulnerabilityVexApplications = pgTable(
  "vulnerability_vex_applications",
  {
    applied_at: timestamp({ mode: "date", withTimezone: true }).notNull(),
    decision_id: text().notNull(),
    ended_at: timestamp({ mode: "date", withTimezone: true }),
    finding_id: text().notNull(),
    tenant_id: text().notNull(),
    updated_at: timestamp({ mode: "date", withTimezone: true })
      .notNull()
      .defaultNow(),
    value: jsonb().$type<VexFindingApplication>().notNull(),
  },
  (table) => [
    primaryKey({ columns: [table.tenant_id, table.finding_id] }),
    index("vulnerability_vex_applications_tenant_decision_idx").on(
      table.tenant_id,
      table.decision_id,
      table.applied_at,
    ),
  ],
);

export const vulnerabilityFeedLeases = pgTable("vulnerability_feed_leases", {
  expires_at: timestamp({ mode: "date", withTimezone: true }).notNull(),
  feed_id: text().primaryKey(),
  owner_id: text().notNull(),
  updated_at: timestamp({ mode: "date", withTimezone: true })
    .notNull()
    .defaultNow(),
});

export const vulnerabilityCoreDrizzleSchema = {
  vulnerabilityFeedLeases,
  vulnerabilityFeedRecords,
  vulnerabilityFeedSnapshots,
  vulnerabilityFeedSyncRuns,
  vulnerabilityFindings,
  vulnerabilityObservations,
  vulnerabilityRemediationExecutions,
  vulnerabilityRemediationPlans,
  vulnerabilityRemediationVerifications,
  vulnerabilityRiskAssessments,
  vulnerabilityVexApplications,
  vulnerabilityVexDecisions,
};

type AnyPgDatabase = PgAsyncDatabase<any, any>;

export const createDrizzleVulnerabilityStore = <DB extends AnyPgDatabase>(
  db: DB,
): PostgresVulnerabilityStore => {
  const alertStores = createDrizzleVulnerabilityAlertStores(db);

  const snapshots = <T>(): FeedSnapshotStore<T> => ({
    load: async (feedId) => {
      const id = requiredText(feedId, "Feed id");
      const [snapshot] = await db
        .select()
        .from(vulnerabilityFeedSnapshots)
        .where(eq(vulnerabilityFeedSnapshots.feed_id, id))
        .limit(1);
      if (!snapshot) return null;
      const records = await db
        .select()
        .from(vulnerabilityFeedRecords)
        .where(eq(vulnerabilityFeedRecords.feed_id, id))
        .orderBy(vulnerabilityFeedRecords.record_id);
      return {
        cursor: snapshot.cursor,
        feed: {
          id: snapshot.feed_id,
          name: snapshot.feed_name,
          url: snapshot.feed_url,
        },
        fetchedAt: iso(snapshot.fetched_at),
        records: records.map((record) => ({
          id: record.record_id,
          modifiedAt: iso(record.modified_at),
          value: record.value as T,
        })),
        revision: snapshot.revision,
      };
    },
    save: async (snapshot) => {
      const feedId = requiredText(snapshot.feed.id, "Feed id");
      await db.transaction(async (transaction) => {
        await transaction
          .insert(vulnerabilityFeedSnapshots)
          .values({
            cursor: encodedJsonb(snapshot.cursor),
            feed_id: feedId,
            feed_name: requiredText(snapshot.feed.name, "Feed name"),
            feed_url: requiredText(snapshot.feed.url, "Feed URL"),
            fetched_at: new Date(snapshot.fetchedAt),
            revision: snapshot.revision,
            updated_at: databaseNow,
          })
          .onConflictDoUpdate({
            set: {
              cursor: encodedJsonb(snapshot.cursor),
              feed_name: requiredText(snapshot.feed.name, "Feed name"),
              feed_url: requiredText(snapshot.feed.url, "Feed URL"),
              fetched_at: new Date(snapshot.fetchedAt),
              revision: snapshot.revision,
              updated_at: databaseNow,
            },
            target: vulnerabilityFeedSnapshots.feed_id,
          });
        const recordIds = snapshot.records.map((record) =>
          requiredText(record.id, "Feed record id"),
        );
        await transaction
          .delete(vulnerabilityFeedRecords)
          .where(
            and(
              eq(vulnerabilityFeedRecords.feed_id, feedId),
              recordIds.length === 0
                ? undefined
                : notInArray(vulnerabilityFeedRecords.record_id, recordIds),
            ),
          );
        if (snapshot.records.length > 0)
          await transaction
            .insert(vulnerabilityFeedRecords)
            .values(
              snapshot.records.map((record) => ({
                feed_id: feedId,
                modified_at: new Date(record.modifiedAt),
                record_id: requiredText(record.id, "Feed record id"),
                value: encodedJsonb(record.value),
              })),
            )
            .onConflictDoUpdate({
              set: {
                modified_at: sql`excluded.modified_at`,
                value: sql`excluded.value`,
              },
              target: [
                vulnerabilityFeedRecords.feed_id,
                vulnerabilityFeedRecords.record_id,
              ],
            });
      });
    },
  });

  const syncRuns: FeedSyncRunStore = {
    append: async (run) => {
      if (!Number.isInteger(run.records) || run.records < 0)
        throw new Error("Feed sync records must be a non-negative integer");
      await db
        .insert(vulnerabilityFeedSyncRuns)
        .values({
          completed_at: new Date(run.completedAt),
          error: run.error,
          feed_id: requiredText(run.feedId, "Feed sync feed id"),
          id: requiredText(run.id, "Feed sync run id"),
          records: run.records,
          revision: run.revision,
          started_at: new Date(run.startedAt),
          status: run.status,
        })
        .onConflictDoUpdate({
          set: {
            completed_at: new Date(run.completedAt),
            error: run.error,
            feed_id: requiredText(run.feedId, "Feed sync feed id"),
            records: run.records,
            revision: run.revision,
            started_at: new Date(run.startedAt),
            status: run.status,
          },
          target: vulnerabilityFeedSyncRuns.id,
        });
    },
    list: async (filter: FeedSyncRunFilter = {}) => {
      const rows = await db
        .select()
        .from(vulnerabilityFeedSyncRuns)
        .where(
          and(
            filter.feedId
              ? eq(vulnerabilityFeedSyncRuns.feed_id, filter.feedId.trim())
              : undefined,
            filter.status
              ? eq(vulnerabilityFeedSyncRuns.status, filter.status)
              : undefined,
          ),
        )
        .orderBy(
          desc(vulnerabilityFeedSyncRuns.started_at),
          desc(vulnerabilityFeedSyncRuns.id),
        )
        .limit(boundedLimit(filter.limit));
      return rows.map(
        (row): FeedSyncRun => ({
          completedAt: iso(row.completed_at),
          error: row.error,
          feedId: row.feed_id,
          id: row.id,
          records: row.records,
          revision: row.revision,
          startedAt: iso(row.started_at),
          status: row.status,
        }),
      );
    },
  };

  const saveFindings = async (
    findings: readonly ManagedVulnerabilityFinding[],
  ) => {
    if (findings.length === 0) return;
    for (const finding of findings)
      valid(
        ManagedVulnerabilityFindingSchema,
        finding,
        `Managed finding ${finding.id}`,
      );
    await db
      .insert(vulnerabilityFindings)
      .values(
        findings.map((finding) => ({
          asset_id: finding.assetId,
          component_id: finding.componentId,
          finding_id: finding.id,
          first_seen_at: new Date(finding.firstSeenAt),
          last_seen_at: new Date(finding.lastSeenAt),
          severity: finding.severity,
          status: finding.status,
          tenant_id: finding.tenantId,
          value: encodedJsonb(finding),
        })),
      )
      .onConflictDoUpdate({
        set: {
          asset_id: sql`excluded.asset_id`,
          component_id: sql`excluded.component_id`,
          first_seen_at: sql`least(${vulnerabilityFindings.first_seen_at}, excluded.first_seen_at)`,
          last_seen_at: sql`greatest(${vulnerabilityFindings.last_seen_at}, excluded.last_seen_at)`,
          severity: sql`excluded.severity`,
          status: sql`excluded.status`,
          updated_at: databaseNow,
          value: sql`excluded.value`,
        },
        target: [
          vulnerabilityFindings.tenant_id,
          vulnerabilityFindings.finding_id,
        ],
      });
  };

  const findings: ManagedFindingStore = {
    get: async (tenantId, findingId) => {
      const [row] = await db
        .select({ value: vulnerabilityFindings.value })
        .from(vulnerabilityFindings)
        .where(
          and(
            eq(
              vulnerabilityFindings.tenant_id,
              requiredText(tenantId, "Tenant id"),
            ),
            eq(
              vulnerabilityFindings.finding_id,
              requiredText(findingId, "Finding id"),
            ),
          ),
        )
        .limit(1);
      return row
        ? valid(
            ManagedVulnerabilityFindingSchema,
            row.value,
            "Stored managed finding",
          )
        : null;
    },
    list: async (filter: ManagedFindingFilter) => {
      const rows = await db
        .select({ value: vulnerabilityFindings.value })
        .from(vulnerabilityFindings)
        .where(
          and(
            eq(
              vulnerabilityFindings.tenant_id,
              requiredText(filter.tenantId, "Tenant id"),
            ),
            filter.assetId
              ? eq(vulnerabilityFindings.asset_id, filter.assetId.trim())
              : undefined,
            filter.severity
              ? eq(vulnerabilityFindings.severity, filter.severity)
              : undefined,
            filter.status
              ? eq(vulnerabilityFindings.status, filter.status)
              : undefined,
          ),
        )
        .orderBy(
          desc(vulnerabilityFindings.last_seen_at),
          vulnerabilityFindings.finding_id,
        )
        .limit(boundedLimit(filter.limit));
      return rows.map(({ value }) =>
        valid(
          ManagedVulnerabilityFindingSchema,
          value,
          "Stored managed finding",
        ),
      );
    },
    save: async (finding) => saveFindings([finding]),
    saveMany: saveFindings,
  };

  const saveObservations = async (
    tenantId: string,
    observations: readonly VulnerabilityObservation[],
  ) => {
    if (observations.length === 0) return;
    const normalizedTenantId = requiredText(tenantId, "Tenant id");
    for (const observation of observations)
      valid(
        VulnerabilityObservationSchema,
        observation,
        `Vulnerability observation ${observation.id}`,
      );
    await db
      .insert(vulnerabilityObservations)
      .values(
        observations.map((observation) => ({
          asset_id: observation.assetId,
          component_id: observation.componentId,
          observation_id: observation.id,
          observed_at: new Date(observation.observedAt),
          tenant_id: normalizedTenantId,
          value: encodedJsonb(observation),
        })),
      )
      .onConflictDoUpdate({
        set: {
          asset_id: sql`excluded.asset_id`,
          component_id: sql`excluded.component_id`,
          observed_at: sql`excluded.observed_at`,
          updated_at: databaseNow,
          value: sql`excluded.value`,
        },
        target: [
          vulnerabilityObservations.tenant_id,
          vulnerabilityObservations.observation_id,
        ],
      });
  };

  const observations: VulnerabilityObservationStore = {
    get: async (tenantId, observationId) => {
      const [row] = await db
        .select({ value: vulnerabilityObservations.value })
        .from(vulnerabilityObservations)
        .where(
          and(
            eq(
              vulnerabilityObservations.tenant_id,
              requiredText(tenantId, "Tenant id"),
            ),
            eq(
              vulnerabilityObservations.observation_id,
              requiredText(observationId, "Observation id"),
            ),
          ),
        )
        .limit(1);
      return row
        ? valid(
            VulnerabilityObservationSchema,
            row.value,
            "Stored vulnerability observation",
          )
        : null;
    },
    list: async (filter: VulnerabilityObservationFilter) => {
      const rows = await db
        .select({ value: vulnerabilityObservations.value })
        .from(vulnerabilityObservations)
        .where(
          and(
            eq(
              vulnerabilityObservations.tenant_id,
              requiredText(filter.tenantId, "Tenant id"),
            ),
            filter.assetId
              ? eq(vulnerabilityObservations.asset_id, filter.assetId.trim())
              : undefined,
            filter.componentId
              ? eq(
                  vulnerabilityObservations.component_id,
                  filter.componentId.trim(),
                )
              : undefined,
          ),
        )
        .orderBy(
          desc(vulnerabilityObservations.observed_at),
          vulnerabilityObservations.observation_id,
        )
        .limit(boundedLimit(filter.limit));
      return rows.map(({ value }) =>
        valid(
          VulnerabilityObservationSchema,
          value,
          "Stored vulnerability observation",
        ),
      );
    },
    save: async (tenantId, observation) =>
      saveObservations(tenantId, [observation]),
    saveMany: saveObservations,
  };

  const saveRiskAssessments = async (
    tenantId: string,
    assessments: readonly VulnerabilityRiskAssessment[],
  ) => {
    if (assessments.length === 0) return;
    const normalizedTenantId = requiredText(tenantId, "Tenant id");
    for (const assessment of assessments)
      valid(
        VulnerabilityRiskAssessmentSchema,
        assessment,
        `Vulnerability risk assessment ${assessment.findingId}`,
      );
    await db
      .insert(vulnerabilityRiskAssessments)
      .values(
        assessments.map((assessment) => ({
          assessed_at: new Date(assessment.assessedAt),
          finding_id: assessment.findingId,
          priority: assessment.priority,
          remediate_by: assessment.remediateBy
            ? new Date(assessment.remediateBy)
            : null,
          tenant_id: normalizedTenantId,
          value: encodedJsonb(assessment),
        })),
      )
      .onConflictDoUpdate({
        set: {
          assessed_at: sql`excluded.assessed_at`,
          priority: sql`excluded.priority`,
          remediate_by: sql`excluded.remediate_by`,
          updated_at: databaseNow,
          value: sql`excluded.value`,
        },
        target: [
          vulnerabilityRiskAssessments.tenant_id,
          vulnerabilityRiskAssessments.finding_id,
        ],
      });
  };

  const riskAssessments: VulnerabilityRiskAssessmentStore = {
    get: async (tenantId, findingId) => {
      const [row] = await db
        .select({ value: vulnerabilityRiskAssessments.value })
        .from(vulnerabilityRiskAssessments)
        .where(
          and(
            eq(
              vulnerabilityRiskAssessments.tenant_id,
              requiredText(tenantId, "Tenant id"),
            ),
            eq(
              vulnerabilityRiskAssessments.finding_id,
              requiredText(findingId, "Finding id"),
            ),
          ),
        )
        .limit(1);
      return row
        ? valid(
            VulnerabilityRiskAssessmentSchema,
            row.value,
            "Stored vulnerability risk assessment",
          )
        : null;
    },
    list: async (filter: VulnerabilityRiskAssessmentFilter) => {
      const rows = await db
        .select({ value: vulnerabilityRiskAssessments.value })
        .from(vulnerabilityRiskAssessments)
        .where(
          and(
            eq(
              vulnerabilityRiskAssessments.tenant_id,
              requiredText(filter.tenantId, "Tenant id"),
            ),
            filter.priority
              ? eq(vulnerabilityRiskAssessments.priority, filter.priority)
              : undefined,
          ),
        )
        .orderBy(
          desc(vulnerabilityRiskAssessments.assessed_at),
          vulnerabilityRiskAssessments.finding_id,
        )
        .limit(boundedLimit(filter.limit));
      return rows.map(({ value }) =>
        valid(
          VulnerabilityRiskAssessmentSchema,
          value,
          "Stored vulnerability risk assessment",
        ),
      );
    },
    save: async (tenantId, assessment) =>
      saveRiskAssessments(tenantId, [assessment]),
    saveMany: saveRiskAssessments,
  };

  const remediationPlans: RemediationPlanStore = {
    get: async (tenantId, planId) => {
      const [row] = await db
        .select({ value: vulnerabilityRemediationPlans.value })
        .from(vulnerabilityRemediationPlans)
        .where(
          and(
            eq(
              vulnerabilityRemediationPlans.tenant_id,
              requiredText(tenantId, "Tenant id"),
            ),
            eq(
              vulnerabilityRemediationPlans.plan_id,
              requiredText(planId, "Remediation plan id"),
            ),
          ),
        )
        .limit(1);
      return row
        ? valid(RemediationPlanSchema, row.value, "Stored remediation plan")
        : null;
    },
    list: async (filter: RemediationPlanFilter) => {
      const rows = await db
        .select({ value: vulnerabilityRemediationPlans.value })
        .from(vulnerabilityRemediationPlans)
        .where(
          and(
            eq(
              vulnerabilityRemediationPlans.tenant_id,
              requiredText(filter.tenantId, "Tenant id"),
            ),
            filter.status
              ? eq(vulnerabilityRemediationPlans.status, filter.status)
              : undefined,
          ),
        )
        .orderBy(
          desc(vulnerabilityRemediationPlans.created_at),
          vulnerabilityRemediationPlans.plan_id,
        )
        .limit(boundedLimit(filter.limit));
      return rows.map(({ value }) =>
        valid(RemediationPlanSchema, value, "Stored remediation plan"),
      );
    },
    save: async (tenantId, plan) => {
      valid(RemediationPlanSchema, plan, `Remediation plan ${plan.id}`);
      await db
        .insert(vulnerabilityRemediationPlans)
        .values({
          created_at: new Date(plan.createdAt),
          plan_id: plan.id,
          status: plan.status,
          tenant_id: requiredText(tenantId, "Tenant id"),
          value: encodedJsonb(plan),
        })
        .onConflictDoUpdate({
          set: {
            created_at: new Date(plan.createdAt),
            status: plan.status,
            updated_at: databaseNow,
            value: encodedJsonb(plan),
          },
          target: [
            vulnerabilityRemediationPlans.tenant_id,
            vulnerabilityRemediationPlans.plan_id,
          ],
        });
    },
  };

  const remediationExecutions: RemediationExecutionStore = {
    get: async (tenantId, executionId) => {
      const [row] = await db
        .select({ value: vulnerabilityRemediationExecutions.value })
        .from(vulnerabilityRemediationExecutions)
        .where(
          and(
            eq(
              vulnerabilityRemediationExecutions.tenant_id,
              requiredText(tenantId, "Tenant id"),
            ),
            eq(
              vulnerabilityRemediationExecutions.execution_id,
              requiredText(executionId, "Remediation execution id"),
            ),
          ),
        )
        .limit(1);
      return row
        ? valid(
            RemediationExecutionSchema,
            row.value,
            "Stored remediation execution",
          )
        : null;
    },
    list: async (tenantId, planId) => {
      const rows = await db
        .select({ value: vulnerabilityRemediationExecutions.value })
        .from(vulnerabilityRemediationExecutions)
        .where(
          and(
            eq(
              vulnerabilityRemediationExecutions.tenant_id,
              requiredText(tenantId, "Tenant id"),
            ),
            eq(
              vulnerabilityRemediationExecutions.plan_id,
              requiredText(planId, "Remediation plan id"),
            ),
          ),
        )
        .orderBy(
          desc(vulnerabilityRemediationExecutions.started_at),
          vulnerabilityRemediationExecutions.execution_id,
        )
        .limit(1_000);
      return rows.map(({ value }) =>
        valid(
          RemediationExecutionSchema,
          value,
          "Stored remediation execution",
        ),
      );
    },
    save: async (tenantId, execution) => {
      valid(
        RemediationExecutionSchema,
        execution,
        `Remediation execution ${execution.id}`,
      );
      await db
        .insert(vulnerabilityRemediationExecutions)
        .values({
          completed_at: execution.completedAt
            ? new Date(execution.completedAt)
            : null,
          execution_id: execution.id,
          plan_id: execution.planId,
          started_at: new Date(execution.startedAt),
          status: execution.status,
          tenant_id: requiredText(tenantId, "Tenant id"),
          value: encodedJsonb(execution),
        })
        .onConflictDoUpdate({
          set: {
            completed_at: execution.completedAt
              ? new Date(execution.completedAt)
              : null,
            plan_id: execution.planId,
            started_at: new Date(execution.startedAt),
            status: execution.status,
            updated_at: databaseNow,
            value: encodedJsonb(execution),
          },
          target: [
            vulnerabilityRemediationExecutions.tenant_id,
            vulnerabilityRemediationExecutions.execution_id,
          ],
        });
    },
  };

  const remediationVerifications: RemediationVerificationStore = {
    get: async (tenantId, verificationId) => {
      const [row] = await db
        .select({
          value: vulnerabilityRemediationVerifications.value,
        })
        .from(vulnerabilityRemediationVerifications)
        .where(
          and(
            eq(
              vulnerabilityRemediationVerifications.tenant_id,
              requiredText(tenantId, "Tenant id"),
            ),
            eq(
              vulnerabilityRemediationVerifications.verification_id,
              requiredText(verificationId, "Remediation verification id"),
            ),
          ),
        )
        .limit(1);
      return row
        ? valid(
            RemediationVerificationSchema,
            row.value,
            "Stored remediation verification",
          )
        : null;
    },
    list: async (tenantId, executionId) => {
      const rows = await db
        .select({
          value: vulnerabilityRemediationVerifications.value,
        })
        .from(vulnerabilityRemediationVerifications)
        .where(
          and(
            eq(
              vulnerabilityRemediationVerifications.tenant_id,
              requiredText(tenantId, "Tenant id"),
            ),
            eq(
              vulnerabilityRemediationVerifications.execution_id,
              requiredText(executionId, "Remediation execution id"),
            ),
          ),
        )
        .orderBy(
          desc(vulnerabilityRemediationVerifications.observed_at),
          vulnerabilityRemediationVerifications.verification_id,
        )
        .limit(1_000);
      return rows.map(({ value }) =>
        valid(
          RemediationVerificationSchema,
          value,
          "Stored remediation verification",
        ),
      );
    },
    save: async (tenantId, verification) => {
      valid(
        RemediationVerificationSchema,
        verification,
        `Remediation verification ${verification.id}`,
      );
      await db
        .insert(vulnerabilityRemediationVerifications)
        .values({
          execution_id: verification.executionId,
          observed_at: new Date(verification.observedAt),
          plan_id: verification.planId,
          status: verification.status,
          tenant_id: requiredText(tenantId, "Tenant id"),
          value: encodedJsonb(verification),
          verification_id: verification.id,
        })
        .onConflictDoUpdate({
          set: {
            execution_id: verification.executionId,
            observed_at: new Date(verification.observedAt),
            plan_id: verification.planId,
            status: verification.status,
            updated_at: databaseNow,
            value: encodedJsonb(verification),
          },
          target: [
            vulnerabilityRemediationVerifications.tenant_id,
            vulnerabilityRemediationVerifications.verification_id,
          ],
        });
    },
  };

  const saveVexDecisions = async (
    tenantId: string,
    decisions: readonly VexDecision[],
  ) => {
    if (decisions.length === 0) return;
    const normalizedTenantId = requiredText(tenantId, "Tenant id");
    for (const decision of decisions)
      valid(VexDecisionSchema, decision, `VEX decision ${decision.id}`);
    await db
      .insert(vulnerabilityVexDecisions)
      .values(
        decisions.map((decision) => ({
          created_at: new Date(decision.createdAt),
          decision_id: decision.id,
          expires_at: decision.expiresAt ? new Date(decision.expiresAt) : null,
          product_id: decision.productId,
          status: decision.status,
          tenant_id: normalizedTenantId,
          value: encodedJsonb(decision),
          vulnerability_id: decision.vulnerabilityId,
        })),
      )
      .onConflictDoUpdate({
        set: {
          created_at: sql`excluded.created_at`,
          expires_at: sql`excluded.expires_at`,
          product_id: sql`excluded.product_id`,
          status: sql`excluded.status`,
          updated_at: databaseNow,
          value: sql`excluded.value`,
          vulnerability_id: sql`excluded.vulnerability_id`,
        },
        target: [
          vulnerabilityVexDecisions.tenant_id,
          vulnerabilityVexDecisions.decision_id,
        ],
      });
  };

  const vexDecisions: VexDecisionStore = {
    get: async (tenantId, decisionId) => {
      const [row] = await db
        .select({ value: vulnerabilityVexDecisions.value })
        .from(vulnerabilityVexDecisions)
        .where(
          and(
            eq(
              vulnerabilityVexDecisions.tenant_id,
              requiredText(tenantId, "Tenant id"),
            ),
            eq(
              vulnerabilityVexDecisions.decision_id,
              requiredText(decisionId, "Decision id"),
            ),
          ),
        )
        .limit(1);
      return row
        ? valid(VexDecisionSchema, row.value, "Stored VEX decision")
        : null;
    },
    list: async (filter: VexDecisionFilter) => {
      const rows = await db
        .select({ value: vulnerabilityVexDecisions.value })
        .from(vulnerabilityVexDecisions)
        .where(
          and(
            eq(
              vulnerabilityVexDecisions.tenant_id,
              requiredText(filter.tenantId, "Tenant id"),
            ),
            filter.productId
              ? eq(
                  vulnerabilityVexDecisions.product_id,
                  filter.productId.trim(),
                )
              : undefined,
            filter.vulnerabilityId
              ? eq(
                  vulnerabilityVexDecisions.vulnerability_id,
                  filter.vulnerabilityId.trim(),
                )
              : undefined,
          ),
        )
        .orderBy(
          desc(vulnerabilityVexDecisions.created_at),
          vulnerabilityVexDecisions.decision_id,
        )
        .limit(boundedLimit(filter.limit));
      return rows.map(({ value }) =>
        valid(VexDecisionSchema, value, "Stored VEX decision"),
      );
    },
    save: async (tenantId, decision) => saveVexDecisions(tenantId, [decision]),
    saveMany: saveVexDecisions,
  };

  const saveVexApplications = async (
    applications: readonly VexFindingApplication[],
  ) => {
    if (applications.length === 0) return;
    for (const application of applications)
      valid(
        VexFindingApplicationSchema,
        application,
        `VEX application ${application.findingId}`,
      );
    await db
      .insert(vulnerabilityVexApplications)
      .values(
        applications.map((application) => ({
          applied_at: new Date(application.appliedAt),
          decision_id: application.decisionId,
          ended_at: application.endedAt ? new Date(application.endedAt) : null,
          finding_id: application.findingId,
          tenant_id: application.tenantId,
          value: encodedJsonb(application),
        })),
      )
      .onConflictDoUpdate({
        set: {
          applied_at: sql`excluded.applied_at`,
          decision_id: sql`excluded.decision_id`,
          ended_at: sql`excluded.ended_at`,
          updated_at: databaseNow,
          value: sql`excluded.value`,
        },
        target: [
          vulnerabilityVexApplications.tenant_id,
          vulnerabilityVexApplications.finding_id,
        ],
      });
  };

  const vexApplications: VexFindingApplicationStore = {
    get: async (tenantId, findingId) => {
      const [row] = await db
        .select({ value: vulnerabilityVexApplications.value })
        .from(vulnerabilityVexApplications)
        .where(
          and(
            eq(
              vulnerabilityVexApplications.tenant_id,
              requiredText(tenantId, "Tenant id"),
            ),
            eq(
              vulnerabilityVexApplications.finding_id,
              requiredText(findingId, "Finding id"),
            ),
          ),
        )
        .limit(1);
      return row
        ? valid(
            VexFindingApplicationSchema,
            row.value,
            "Stored VEX application",
          )
        : null;
    },
    save: async (application) => saveVexApplications([application]),
    saveMany: saveVexApplications,
  };

  const leases: FeedLeaseStore = {
    acquire: async (request) => {
      if (!Number.isFinite(request.ttlMs) || request.ttlMs <= 0)
        throw new Error("Feed lease ttlMs must be positive and finite");
      const now = request.now ?? new Date();
      const ownerId = requiredText(request.ownerId, "Feed lease owner id");
      const [row] = await db
        .insert(vulnerabilityFeedLeases)
        .values({
          expires_at: new Date(now.getTime() + request.ttlMs),
          feed_id: requiredText(request.feedId, "Feed lease feed id"),
          owner_id: ownerId,
          updated_at: now,
        })
        .onConflictDoUpdate({
          set: {
            expires_at: new Date(now.getTime() + request.ttlMs),
            owner_id: ownerId,
            updated_at: now,
          },
          setWhere: or(
            lte(vulnerabilityFeedLeases.expires_at, now),
            eq(vulnerabilityFeedLeases.owner_id, ownerId),
          ),
          target: vulnerabilityFeedLeases.feed_id,
        })
        .returning({ ownerId: vulnerabilityFeedLeases.owner_id });
      return row?.ownerId === ownerId;
    },
    release: async (feedId, ownerId) => {
      const rows = await db
        .delete(vulnerabilityFeedLeases)
        .where(
          and(
            eq(
              vulnerabilityFeedLeases.feed_id,
              requiredText(feedId, "Feed lease feed id"),
            ),
            eq(
              vulnerabilityFeedLeases.owner_id,
              requiredText(ownerId, "Feed lease owner id"),
            ),
          ),
        )
        .returning({ feedId: vulnerabilityFeedLeases.feed_id });
      return rows.length > 0;
    },
  };

  return {
    alertIncidents: alertStores.alertIncidents,
    alertPolicies: alertStores.alertPolicies,
    ensureSchema: () => Promise.resolve(),
    findings,
    leases,
    observations,
    remediationExecutions,
    remediationPlans,
    remediationVerifications,
    riskAssessments,
    snapshots,
    syncRuns,
    vexApplications,
    vexDecisions,
  };
};
