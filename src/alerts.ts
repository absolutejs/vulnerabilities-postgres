import {
  resolveVulnerabilityAlertAudiences,
  validateVulnerabilityAlertConfiguration,
  type VulnerabilityAlert,
  type VulnerabilityAlertConfiguration,
} from "@absolutejs/vulnerabilities";

export type AlertPostgresTag = {
  <T = unknown>(
    strings: TemplateStringsArray,
    ...values: unknown[]
  ): PromiseLike<T[]>;
  begin?: <T>(callback: (sql: AlertPostgresTag) => Promise<T>) => Promise<T>;
  unsafe: (sql: string, ...args: never[]) => PromiseLike<unknown[]>;
};

export type VulnerabilityAlertPolicyVersion = {
  activated_at: Date;
  activated_by: string;
  configuration: VulnerabilityAlertConfiguration;
  reason: string;
  status: "active" | "superseded";
  tenant_id: string;
  version: number;
};

export type ActiveVulnerabilityAlertPolicy = {
  configuration: VulnerabilityAlertConfiguration;
  tenantId: string;
  version: number | null;
};

export type VulnerabilityAlertIncidentRow = {
  acknowledged_at: Date | null;
  acknowledged_by: string | null;
  alert_id: string;
  asset_id: string | null;
  body: string;
  due_at: Date | null;
  finding_id: string | null;
  first_observed_at: Date;
  kind: VulnerabilityAlert["kind"];
  last_observed_at: Date;
  next_escalation_at: Date | null;
  observation_count: number;
  occurrence_count: number;
  plan_id: string | null;
  policy_version: number | null;
  resolved_at: Date | null;
  severity: VulnerabilityAlert["severity"];
  source_id: string | null;
  status: "acknowledged" | "open" | "resolved";
  tenant_id: string;
  title: string;
  updated_at: Date;
  value: VulnerabilityAlert;
};

export type VulnerabilityAlertEventRow = {
  actor_id: string | null;
  alert_id: string;
  created_at: Date;
  id: number;
  kind:
    | "acknowledged"
    | "alert_dismissed"
    | "alert_retried"
    | "delivery_failed"
    | "delivered"
    | "escalated"
    | "observed"
    | "opened"
    | "resolved";
  metadata: Record<string, unknown>;
};

export type VulnerabilityAlertDeliveryRow = {
  alert_id: string;
  attempt_count: number;
  audience: "admin" | "owner";
  created_at: Date;
  delivered_at: Date | null;
  id: string;
  idempotency_key: string;
  kind: "escalated" | "opened" | "resolved";
  last_error: string | null;
  lease_expires_at: Date | null;
  next_attempt_at: Date;
  state: "delivered" | "delivering" | "dismissed" | "failed" | "pending";
  updated_at: Date;
};

export type ClaimedVulnerabilityAlertDelivery =
  VulnerabilityAlertDeliveryRow & {
    asset_id: string | null;
    body: string;
    severity: VulnerabilityAlert["severity"];
    tenant_id: string;
    title: string;
  };

export class VulnerabilityAlertConflictError extends Error {}
export class VulnerabilityAlertNotFoundError extends Error {}

export type VulnerabilityAlertPolicyStore = {
  activate: (input: {
    activatedAt: string;
    activatedBy: string;
    configuration: VulnerabilityAlertConfiguration;
    reason: string;
    tenantId: string;
  }) => Promise<
    ActiveVulnerabilityAlertPolicy & { activatedAt: string; reason: string }
  >;
  active: () => Promise<ActiveVulnerabilityAlertPolicy[]>;
  list: (limit?: number) => Promise<VulnerabilityAlertPolicyVersion[]>;
};

export type VulnerabilityAlertIncidentStore = {
  acknowledge: (input: {
    acknowledgedAt: string;
    acknowledgedBy: string;
    alertId: string;
  }) => Promise<boolean>;
  claimDeliveries: (input?: {
    leaseMs?: number;
    limit?: number;
    tenantIds?: readonly string[];
  }) => Promise<ClaimedVulnerabilityAlertDelivery[]>;
  completeDelivery: (input: {
    alertId: string;
    deliveryId: string;
    audience: "admin" | "owner";
    kind: "escalated" | "opened" | "resolved";
  }) => Promise<boolean>;
  deliveries: (limit?: number) => Promise<VulnerabilityAlertDeliveryRow[]>;
  events: (limit?: number) => Promise<VulnerabilityAlertEventRow[]>;
  failDelivery: (input: {
    alertId: string;
    deliveryId: string;
    error: string;
    kind: "escalated" | "opened" | "resolved";
    retryAt: string;
  }) => Promise<boolean>;
  incidents: (limit?: number) => Promise<VulnerabilityAlertIncidentRow[]>;
  observe: (input: {
    alert: VulnerabilityAlert;
    policy: ActiveVulnerabilityAlertPolicy;
    observedAt?: string;
  }) => Promise<"observed" | "opened" | "reopened">;
  processEscalations: (input: {
    fallbackPolicy?: ActiveVulnerabilityAlertPolicy;
    policies: ReadonlyMap<string, ActiveVulnerabilityAlertPolicy>;
    tenantIds?: readonly string[];
  }) => Promise<number>;
  resolveInactive: (input: {
    activeAlertIds: ReadonlySet<string>;
    fallbackPolicy?: ActiveVulnerabilityAlertPolicy;
    policies: ReadonlyMap<string, ActiveVulnerabilityAlertPolicy>;
    resolvedAt?: string;
    tenantIds?: readonly string[];
  }) => Promise<number>;
};

const IDENTIFIER = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

const tables = (prefix: string) => ({
  deliveries: `${prefix}_alert_deliveries`,
  events: `${prefix}_alert_events`,
  incidents: `${prefix}_alert_incidents`,
  policies: `${prefix}_alert_policy_versions`,
});

const boundedLimit = (value = 1_000) => {
  if (!Number.isInteger(value) || value < 1 || value > 1_000)
    throw new Error("Alert query limit must be an integer from 1 through 1000");
  return value;
};

const transaction = async <T>(
  sql: AlertPostgresTag,
  callback: (sql: AlertPostgresTag) => Promise<T>,
) => {
  if (!sql.begin)
    throw new Error(
      "Vulnerability alert persistence requires a transaction-capable Postgres tag",
    );
  return sql.begin(callback);
};

const tenantPredicate = (tenantIds: readonly string[] | undefined) =>
  tenantIds && tenantIds.length > 0 ? JSON.stringify(tenantIds) : null;

export const vulnerabilityAlertPostgresSchemaSql = (
  tablePrefix = "vulnerability",
) => {
  if (!IDENTIFIER.test(tablePrefix))
    throw new Error(
      `[vulnerabilities-postgres] invalid tablePrefix "${tablePrefix}"; must match ${IDENTIFIER.source}`,
    );
  const table = tables(tablePrefix);
  return `
    CREATE TABLE IF NOT EXISTS ${table.policies} (
      activated_at timestamptz NOT NULL,
      activated_by uuid NOT NULL,
      configuration jsonb NOT NULL,
      reason text NOT NULL,
      status text NOT NULL CHECK (status IN ('active', 'superseded')),
      tenant_id text NOT NULL,
      version integer NOT NULL,
      PRIMARY KEY (tenant_id, version)
    );
    CREATE UNIQUE INDEX IF NOT EXISTS ${table.policies}_active_idx ON ${table.policies} (tenant_id) WHERE status = 'active';
    CREATE INDEX IF NOT EXISTS ${table.policies}_history_idx ON ${table.policies} (tenant_id, activated_at);
    CREATE TABLE IF NOT EXISTS ${table.incidents} (
      acknowledged_at timestamptz,
      acknowledged_by uuid,
      alert_id text PRIMARY KEY,
      asset_id text,
      body text NOT NULL,
      due_at timestamptz,
      finding_id text,
      first_observed_at timestamptz NOT NULL,
      kind text NOT NULL,
      last_observed_at timestamptz NOT NULL,
      next_escalation_at timestamptz,
      observation_count integer NOT NULL DEFAULT 1,
      occurrence_count integer NOT NULL DEFAULT 1,
      plan_id text,
      policy_version integer,
      resolved_at timestamptz,
      severity text NOT NULL,
      source_id text,
      status text NOT NULL DEFAULT 'open' CHECK (status IN ('acknowledged', 'open', 'resolved')),
      tenant_id text NOT NULL,
      title text NOT NULL,
      updated_at timestamptz NOT NULL DEFAULT now(),
      value jsonb NOT NULL
    );
    CREATE INDEX IF NOT EXISTS ${table.incidents}_status_idx ON ${table.incidents} (status, last_observed_at);
    CREATE INDEX IF NOT EXISTS ${table.incidents}_tenant_idx ON ${table.incidents} (tenant_id, status);
    CREATE INDEX IF NOT EXISTS ${table.incidents}_escalation_idx ON ${table.incidents} (status, next_escalation_at);
    CREATE TABLE IF NOT EXISTS ${table.events} (
      actor_id uuid,
      alert_id text NOT NULL REFERENCES ${table.incidents}(alert_id) ON DELETE CASCADE,
      created_at timestamptz NOT NULL DEFAULT now(),
      id bigserial PRIMARY KEY,
      kind text NOT NULL,
      metadata jsonb NOT NULL DEFAULT '{}'::jsonb
    );
    CREATE INDEX IF NOT EXISTS ${table.events}_alert_idx ON ${table.events} (alert_id, created_at);
    CREATE TABLE IF NOT EXISTS ${table.deliveries} (
      alert_id text NOT NULL REFERENCES ${table.incidents}(alert_id) ON DELETE CASCADE,
      attempt_count integer NOT NULL DEFAULT 0,
      audience text NOT NULL CHECK (audience IN ('admin', 'owner')),
      created_at timestamptz NOT NULL DEFAULT now(),
      delivered_at timestamptz,
      id uuid PRIMARY KEY,
      idempotency_key text NOT NULL,
      kind text NOT NULL CHECK (kind IN ('escalated', 'opened', 'resolved')),
      last_error text,
      lease_expires_at timestamptz,
      next_attempt_at timestamptz NOT NULL DEFAULT now(),
      state text NOT NULL DEFAULT 'pending' CHECK (state IN ('delivered', 'delivering', 'dismissed', 'failed', 'pending')),
      updated_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE UNIQUE INDEX IF NOT EXISTS ${table.deliveries}_key_idx ON ${table.deliveries} (idempotency_key);
    CREATE INDEX IF NOT EXISTS ${table.deliveries}_state_idx ON ${table.deliveries} (state, next_attempt_at);
  `;
};

export const createPostgresVulnerabilityAlertStores = (options: {
  ensureSchema?: boolean;
  sql: AlertPostgresTag;
  tablePrefix?: string;
}): {
  alertIncidents: VulnerabilityAlertIncidentStore;
  alertPolicies: VulnerabilityAlertPolicyStore;
  ensureAlertSchema: () => Promise<void>;
} => {
  const tablePrefix = options.tablePrefix ?? "vulnerability";
  const table = tables(tablePrefix);
  const ddl = vulnerabilityAlertPostgresSchemaSql(tablePrefix);
  const sql = options.sql;
  let schema: Promise<void> | undefined;
  const ensureAlertSchema = async () => {
    schema ??= Promise.resolve(sql.unsafe(ddl)).then(() => undefined);
    await schema;
  };
  const ready = async () => {
    if (options.ensureSchema !== false) await ensureAlertSchema();
  };

  const queue = async (
    tx: AlertPostgresTag,
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
    for (const audience of audiences)
      await tx`
        INSERT INTO ${tx.unsafe(table.deliveries)} (
          id, alert_id, audience, idempotency_key, kind
        ) VALUES (
          ${crypto.randomUUID()}, ${alert.id}, ${audience},
          ${`${alert.id}:${audience}:${kind}:${occurrence}`}, ${kind}
        ) ON CONFLICT (idempotency_key) DO NOTHING
      `;
  };

  const alertPolicies: VulnerabilityAlertPolicyStore = {
    activate: async (input) => {
      await ready();
      const configuration = validateVulnerabilityAlertConfiguration(
        input.configuration,
      );
      const reason = input.reason.trim();
      if (!reason) throw new Error("Policy activation reason is required");
      return transaction(sql, async (tx) => {
        await tx`SELECT pg_advisory_xact_lock(hashtext(${`vulnerability-alert-policy:${input.tenantId}`}))`;
        const [latest] = await tx<{
          version: number;
        }>`SELECT COALESCE(MAX(version), 0)::integer AS version FROM ${tx.unsafe(table.policies)} WHERE tenant_id = ${input.tenantId}`;
        const version = (latest?.version ?? 0) + 1;
        await tx`UPDATE ${tx.unsafe(table.policies)} SET status = 'superseded' WHERE tenant_id = ${input.tenantId} AND status = 'active'`;
        await tx`INSERT INTO ${tx.unsafe(table.policies)} (activated_at, activated_by, configuration, reason, status, tenant_id, version) VALUES (${input.activatedAt}, ${input.activatedBy}, ${JSON.stringify(configuration)}::jsonb, ${reason}, 'active', ${input.tenantId}, ${version})`;
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
      await ready();
      const rows = await sql<{
        configuration: unknown;
        tenant_id: string;
        version: number;
      }>`SELECT configuration, tenant_id, version FROM ${sql.unsafe(table.policies)} WHERE status = 'active'`;
      return rows.map((row) => ({
        configuration: validateVulnerabilityAlertConfiguration(
          row.configuration as VulnerabilityAlertConfiguration,
        ),
        tenantId: row.tenant_id,
        version: row.version,
      }));
    },
    list: async (requestedLimit) => {
      await ready();
      return sql<VulnerabilityAlertPolicyVersion>`SELECT * FROM ${sql.unsafe(table.policies)} ORDER BY activated_at DESC LIMIT ${boundedLimit(requestedLimit)}` as PromiseLike<
        VulnerabilityAlertPolicyVersion[]
      >;
    },
  };

  const observe: VulnerabilityAlertIncidentStore["observe"] = async ({
    alert,
    policy,
    observedAt,
  }) => {
    await ready();
    const at = observedAt ?? new Date().toISOString();
    const configuration = validateVulnerabilityAlertConfiguration(
      policy.configuration,
    );
    return transaction(sql, async (tx) => {
      const [existing] = await tx<{
        occurrence_count: number;
        status: VulnerabilityAlertIncidentRow["status"];
      }>`SELECT occurrence_count, status FROM ${tx.unsafe(table.incidents)} WHERE alert_id = ${alert.id} FOR UPDATE`;
      const reopened = existing?.status === "resolved";
      const nextEscalationAt = new Date(
        new Date(at).getTime() +
          configuration.escalationAfterMs[alert.severity],
      ).toISOString();
      await tx`INSERT INTO ${tx.unsafe(table.incidents)} (alert_id, asset_id, body, due_at, finding_id, first_observed_at, kind, last_observed_at, next_escalation_at, plan_id, policy_version, severity, source_id, status, tenant_id, title, value) VALUES (${alert.id}, ${alert.assetId}, ${alert.body}, ${alert.dueAt}, ${alert.findingId}, ${alert.observedAt}, ${alert.kind}, ${alert.observedAt}, ${nextEscalationAt}, ${alert.planId}, ${policy.version}, ${alert.severity}, ${alert.sourceId}, 'open', ${alert.tenantId}, ${alert.title}, ${JSON.stringify(alert)}::jsonb) ON CONFLICT (alert_id) DO UPDATE SET asset_id = EXCLUDED.asset_id, body = EXCLUDED.body, due_at = EXCLUDED.due_at, finding_id = EXCLUDED.finding_id, last_observed_at = EXCLUDED.last_observed_at, observation_count = ${tx.unsafe(table.incidents)}.observation_count + 1, occurrence_count = CASE WHEN ${tx.unsafe(table.incidents)}.status = 'resolved' THEN ${tx.unsafe(table.incidents)}.occurrence_count + 1 ELSE ${tx.unsafe(table.incidents)}.occurrence_count END, plan_id = EXCLUDED.plan_id, policy_version = EXCLUDED.policy_version, severity = EXCLUDED.severity, source_id = EXCLUDED.source_id, tenant_id = EXCLUDED.tenant_id, title = EXCLUDED.title, updated_at = now(), value = EXCLUDED.value, status = CASE WHEN ${tx.unsafe(table.incidents)}.status = 'resolved' THEN 'open' ELSE ${tx.unsafe(table.incidents)}.status END, resolved_at = CASE WHEN ${tx.unsafe(table.incidents)}.status = 'resolved' THEN null ELSE ${tx.unsafe(table.incidents)}.resolved_at END, next_escalation_at = CASE WHEN ${tx.unsafe(table.incidents)}.status = 'resolved' THEN EXCLUDED.next_escalation_at WHEN ${tx.unsafe(table.incidents)}.status = 'open' AND ${tx.unsafe(table.incidents)}.policy_version IS DISTINCT FROM EXCLUDED.policy_version THEN EXCLUDED.next_escalation_at ELSE ${tx.unsafe(table.incidents)}.next_escalation_at END`;
      if (!existing || reopened) {
        await tx`INSERT INTO ${tx.unsafe(table.events)} (alert_id, kind) VALUES (${alert.id}, 'opened')`;
        await queue(
          tx,
          alert,
          configuration,
          "opened",
          existing ? existing.occurrence_count + 1 : 1,
        );
      }
      return !existing ? "opened" : reopened ? "reopened" : "observed";
    });
  };

  const alertIncidents: VulnerabilityAlertIncidentStore = {
    acknowledge: async (input) => {
      await ready();
      return transaction(sql, async (tx) => {
        const [present] = await tx<{
          status: VulnerabilityAlertIncidentRow["status"];
        }>`SELECT status FROM ${tx.unsafe(table.incidents)} WHERE alert_id = ${input.alertId} FOR UPDATE`;
        if (!present)
          throw new VulnerabilityAlertNotFoundError(
            "Vulnerability alert not found",
          );
        if (present.status === "resolved")
          throw new VulnerabilityAlertConflictError(
            "Resolved vulnerability alerts cannot be acknowledged",
          );
        if (present.status === "acknowledged") return false;
        await tx`UPDATE ${tx.unsafe(table.incidents)} SET acknowledged_at = ${input.acknowledgedAt}, acknowledged_by = ${input.acknowledgedBy}, next_escalation_at = null, status = 'acknowledged', updated_at = ${input.acknowledgedAt} WHERE alert_id = ${input.alertId}`;
        await tx`INSERT INTO ${tx.unsafe(table.events)} (actor_id, alert_id, kind) VALUES (${input.acknowledgedBy}, ${input.alertId}, 'acknowledged')`;
        return true;
      });
    },
    claimDeliveries: async (input = {}) => {
      await ready();
      const leaseMs = input.leaseMs ?? 300_000;
      const queryLimit = boundedLimit(input.limit ?? 100);
      const tenants = tenantPredicate(input.tenantIds);
      return transaction(sql, async (tx) => {
        const rows = await tx<{
          id: string;
        }>`SELECT d.id FROM ${tx.unsafe(table.deliveries)} d JOIN ${tx.unsafe(table.incidents)} i ON i.alert_id = d.alert_id WHERE (((d.state IN ('pending', 'failed') AND d.next_attempt_at <= now()) OR (d.state = 'delivering' AND d.lease_expires_at <= now()))) AND (${tenants}::jsonb IS NULL OR i.tenant_id IN (SELECT jsonb_array_elements_text(${tenants}::jsonb))) ORDER BY d.created_at FOR UPDATE OF d SKIP LOCKED LIMIT ${queryLimit}`;
        const ids = rows.map(({ id }) => id);
        if (ids.length === 0) return [];
        const encoded = JSON.stringify(ids);
        return tx<ClaimedVulnerabilityAlertDelivery>`UPDATE ${tx.unsafe(table.deliveries)} d SET attempt_count = attempt_count + 1, lease_expires_at = now() + ${leaseMs} * INTERVAL '1 millisecond', state = 'delivering', updated_at = now() FROM ${tx.unsafe(table.incidents)} i WHERE d.alert_id = i.alert_id AND d.id::text IN (SELECT jsonb_array_elements_text(${encoded}::jsonb)) RETURNING d.*, i.asset_id, i.body, i.severity, i.tenant_id, i.title` as PromiseLike<
          ClaimedVulnerabilityAlertDelivery[]
        >;
      });
    },
    completeDelivery: async (input) => {
      await ready();
      return transaction(sql, async (tx) => {
        const updated =
          await tx`UPDATE ${tx.unsafe(table.deliveries)} SET delivered_at = now(), last_error = null, lease_expires_at = null, state = 'delivered', updated_at = now() WHERE id = ${input.deliveryId} AND state = 'delivering' RETURNING id`;
        if (updated.length === 0) return false;
        await tx`INSERT INTO ${tx.unsafe(table.events)} (alert_id, kind, metadata) VALUES (${input.alertId}, 'delivered', ${JSON.stringify({ audience: input.audience, kind: input.kind })}::jsonb)`;
        return true;
      });
    },
    deliveries: async (requestedLimit) => {
      await ready();
      return sql<VulnerabilityAlertDeliveryRow>`SELECT * FROM ${sql.unsafe(table.deliveries)} ORDER BY created_at DESC LIMIT ${boundedLimit(requestedLimit)}` as PromiseLike<
        VulnerabilityAlertDeliveryRow[]
      >;
    },
    events: async (requestedLimit) => {
      await ready();
      return sql<VulnerabilityAlertEventRow>`SELECT * FROM ${sql.unsafe(table.events)} ORDER BY created_at DESC LIMIT ${boundedLimit(requestedLimit)}` as PromiseLike<
        VulnerabilityAlertEventRow[]
      >;
    },
    failDelivery: async (input) => {
      await ready();
      return transaction(sql, async (tx) => {
        const updated =
          await tx`UPDATE ${tx.unsafe(table.deliveries)} SET last_error = ${input.error}, lease_expires_at = null, next_attempt_at = ${input.retryAt}, state = 'failed', updated_at = now() WHERE id = ${input.deliveryId} AND state = 'delivering' RETURNING id`;
        if (updated.length === 0) return false;
        await tx`INSERT INTO ${tx.unsafe(table.events)} (alert_id, kind, metadata) VALUES (${input.alertId}, 'delivery_failed', ${JSON.stringify({ error: input.error, kind: input.kind })}::jsonb)`;
        return true;
      });
    },
    incidents: async (requestedLimit) => {
      await ready();
      return sql<VulnerabilityAlertIncidentRow>`SELECT * FROM ${sql.unsafe(table.incidents)} ORDER BY last_observed_at DESC LIMIT ${boundedLimit(requestedLimit)}` as PromiseLike<
        VulnerabilityAlertIncidentRow[]
      >;
    },
    observe,
    processEscalations: async ({ fallbackPolicy, policies, tenantIds }) => {
      await ready();
      const tenants = tenantPredicate(tenantIds);
      const due = await sql<
        Pick<
          VulnerabilityAlertIncidentRow,
          | "alert_id"
          | "asset_id"
          | "occurrence_count"
          | "severity"
          | "tenant_id"
        >
      >`SELECT alert_id, asset_id, occurrence_count, severity, tenant_id FROM ${sql.unsafe(table.incidents)} WHERE status = 'open' AND next_escalation_at <= now() AND (${tenants}::jsonb IS NULL OR tenant_id IN (SELECT jsonb_array_elements_text(${tenants}::jsonb)))`;
      let processed = 0;
      for (const incident of due) {
        const policy = policies.get(incident.tenant_id) ?? fallbackPolicy;
        if (!policy) continue;
        const changed = await transaction(sql, async (tx) => {
          const claimed =
            await tx`UPDATE ${tx.unsafe(table.incidents)} SET next_escalation_at = null, updated_at = now() WHERE alert_id = ${incident.alert_id} AND status = 'open' AND next_escalation_at <= now() RETURNING alert_id`;
          if (claimed.length === 0) return false;
          await tx`INSERT INTO ${tx.unsafe(table.events)} (alert_id, kind) VALUES (${incident.alert_id}, 'escalated')`;
          await queue(
            tx,
            {
              assetId: incident.asset_id,
              id: incident.alert_id,
              severity: incident.severity,
            },
            policy.configuration,
            "escalated",
            incident.occurrence_count,
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
      await ready();
      const tenants = tenantPredicate(tenantIds);
      const open = await sql<
        Pick<
          VulnerabilityAlertIncidentRow,
          | "alert_id"
          | "asset_id"
          | "occurrence_count"
          | "severity"
          | "tenant_id"
        >
      >`SELECT alert_id, asset_id, occurrence_count, severity, tenant_id FROM ${sql.unsafe(table.incidents)} WHERE status IN ('open', 'acknowledged') AND (${tenants}::jsonb IS NULL OR tenant_id IN (SELECT jsonb_array_elements_text(${tenants}::jsonb)))`;
      const at = resolvedAt ?? new Date().toISOString();
      let processed = 0;
      for (const incident of open) {
        if (activeAlertIds.has(incident.alert_id)) continue;
        const policy = policies.get(incident.tenant_id) ?? fallbackPolicy;
        if (!policy) continue;
        const changed = await transaction(sql, async (tx) => {
          const resolved =
            await tx`UPDATE ${tx.unsafe(table.incidents)} SET next_escalation_at = null, resolved_at = ${at}, status = 'resolved', updated_at = now() WHERE alert_id = ${incident.alert_id} AND status IN ('open', 'acknowledged') RETURNING alert_id`;
          if (resolved.length === 0) return false;
          await tx`INSERT INTO ${tx.unsafe(table.events)} (alert_id, kind) VALUES (${incident.alert_id}, 'resolved')`;
          await queue(
            tx,
            {
              assetId: incident.asset_id,
              id: incident.alert_id,
              severity: incident.severity,
            },
            policy.configuration,
            "resolved",
            incident.occurrence_count,
          );
          return true;
        });
        if (changed) processed += 1;
      }
      return processed;
    },
  };

  return { alertIncidents, alertPolicies, ensureAlertSchema };
};
