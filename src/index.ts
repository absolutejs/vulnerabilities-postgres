import {
  ManagedVulnerabilityFindingSchema,
  type FeedCursor,
  type FeedSnapshot,
  type FeedSnapshotStore,
  type FeedSyncRun,
  type FeedSyncRunFilter,
  type FeedSyncRunStore,
  type ManagedFindingFilter,
  type ManagedFindingStore,
  type ManagedVulnerabilityFinding,
} from "@absolutejs/vulnerabilities";
import { Value } from "@sinclair/typebox/value";

export type PostgresTag = {
  (strings: TemplateStringsArray, ...values: never[]): PromiseLike<unknown[]>;
  unsafe: (sql: string, ...args: never[]) => PromiseLike<unknown[]>;
};

type SqlTag = {
  <T = unknown>(
    strings: TemplateStringsArray,
    ...values: unknown[]
  ): PromiseLike<T[]>;
  unsafe: (sql: string) => PromiseLike<unknown[]>;
};

export type FeedLeaseRequest = {
  feedId: string;
  now?: Date;
  ownerId: string;
  ttlMs: number;
};

export type FeedLeaseStore = {
  acquire: (request: FeedLeaseRequest) => Promise<boolean>;
  release: (feedId: string, ownerId: string) => Promise<boolean>;
};

export type PostgresVulnerabilityStore = {
  ensureSchema: () => Promise<void>;
  findings: ManagedFindingStore;
  leases: FeedLeaseStore;
  snapshots: <T>() => FeedSnapshotStore<T>;
  syncRuns: FeedSyncRunStore;
};

export type CreatePostgresVulnerabilityStoreOptions = {
  ensureSchema?: boolean;
  sql: PostgresTag;
  tablePrefix?: string;
};

const IDENTIFIER = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
const SYNC_STATUSES = new Set<FeedSyncRun["status"]>([
  "failed",
  "not_modified",
  "stale",
  "updated",
]);

const requiredText = (value: string, label: string) => {
  const normalized = value.trim();
  if (normalized.length === 0) throw new Error(`${label} is required`);
  return normalized;
};

const limit = (value: number | undefined, fallback = 100) => {
  const normalized = value ?? fallback;
  if (!Number.isInteger(normalized) || normalized < 1 || normalized > 1_000)
    throw new Error(
      "Postgres query limit must be an integer from 1 through 1000",
    );
  return normalized;
};

const timestamp = (value: unknown, label: string) => {
  if (value instanceof Date) return value.toISOString();
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value)))
    throw new Error(`${label} must be a valid timestamp`);
  return new Date(value).toISOString();
};

const json = <T>(value: unknown, label: string): T => {
  if (typeof value === "string") {
    try {
      return JSON.parse(value) as T;
    } catch {
      throw new Error(`${label} must contain valid JSON`);
    }
  }
  return value as T;
};

const normalizeCursor = (value: unknown): FeedCursor => {
  const cursor = json<Record<string, unknown>>(value, "Feed cursor");
  const nullable = (entry: unknown, label: string) => {
    if (entry === null || typeof entry === "string") return entry;
    throw new Error(`${label} must be a string or null`);
  };
  return {
    etag: nullable(cursor.etag, "Feed cursor etag"),
    lastModified: nullable(cursor.lastModified, "Feed cursor lastModified"),
    token: nullable(cursor.token, "Feed cursor token"),
  };
};

const prefixTables = (prefix: string) => ({
  findings: `${prefix}_findings`,
  leases: `${prefix}_feed_leases`,
  records: `${prefix}_feed_records`,
  runs: `${prefix}_feed_sync_runs`,
  snapshots: `${prefix}_feed_snapshots`,
});

export const vulnerabilityPostgresSchemaSql = (
  tablePrefix = "vulnerability",
) => {
  if (!IDENTIFIER.test(tablePrefix))
    throw new Error(
      `[vulnerabilities-postgres] invalid tablePrefix "${tablePrefix}"; must match ${IDENTIFIER.source}`,
    );
  const table = prefixTables(tablePrefix);
  return `
    CREATE TABLE IF NOT EXISTS ${table.snapshots} (
      feed_id text PRIMARY KEY,
      feed_name text NOT NULL,
      feed_url text NOT NULL,
      cursor jsonb NOT NULL,
      fetched_at timestamptz NOT NULL,
      revision text,
      updated_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS ${table.records} (
      feed_id text NOT NULL REFERENCES ${table.snapshots}(feed_id) ON DELETE CASCADE,
      record_id text NOT NULL,
      modified_at timestamptz NOT NULL,
      value jsonb NOT NULL,
      PRIMARY KEY (feed_id, record_id)
    );
    CREATE INDEX IF NOT EXISTS ${table.records}_modified_idx
      ON ${table.records} (feed_id, modified_at DESC);
    CREATE TABLE IF NOT EXISTS ${table.runs} (
      id text PRIMARY KEY,
      feed_id text NOT NULL,
      started_at timestamptz NOT NULL,
      completed_at timestamptz NOT NULL,
      status text NOT NULL CHECK (status IN ('failed', 'not_modified', 'stale', 'updated')),
      error text,
      records integer NOT NULL CHECK (records >= 0),
      revision text
    );
    CREATE INDEX IF NOT EXISTS ${table.runs}_feed_started_idx
      ON ${table.runs} (feed_id, started_at DESC);
    CREATE INDEX IF NOT EXISTS ${table.runs}_status_started_idx
      ON ${table.runs} (status, started_at DESC);
    CREATE TABLE IF NOT EXISTS ${table.findings} (
      tenant_id text NOT NULL,
      finding_id text NOT NULL,
      asset_id text NOT NULL,
      component_id text NOT NULL,
      severity text NOT NULL,
      status text NOT NULL,
      first_seen_at timestamptz NOT NULL,
      last_seen_at timestamptz NOT NULL,
      value jsonb NOT NULL,
      updated_at timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY (tenant_id, finding_id)
    );
    CREATE INDEX IF NOT EXISTS ${table.findings}_tenant_status_idx
      ON ${table.findings} (tenant_id, status, last_seen_at DESC);
    CREATE INDEX IF NOT EXISTS ${table.findings}_tenant_severity_idx
      ON ${table.findings} (tenant_id, severity, last_seen_at DESC);
    CREATE INDEX IF NOT EXISTS ${table.findings}_tenant_asset_idx
      ON ${table.findings} (tenant_id, asset_id, last_seen_at DESC);
    CREATE TABLE IF NOT EXISTS ${table.leases} (
      feed_id text PRIMARY KEY,
      owner_id text NOT NULL,
      expires_at timestamptz NOT NULL,
      updated_at timestamptz NOT NULL DEFAULT now()
    );
  `;
};

export const createPostgresVulnerabilityStore = (
  options: CreatePostgresVulnerabilityStoreOptions,
): PostgresVulnerabilityStore => {
  const tablePrefix = options.tablePrefix ?? "vulnerability";
  const ddl = vulnerabilityPostgresSchemaSql(tablePrefix);
  const table = prefixTables(tablePrefix);
  const sql = options.sql as unknown as SqlTag;
  const shouldEnsureSchema = options.ensureSchema ?? true;
  let schemaPromise: Promise<void> | undefined;
  const ensureSchema = () => {
    if (!shouldEnsureSchema) return Promise.resolve();
    if (schemaPromise) return schemaPromise;
    schemaPromise = Promise.resolve(sql.unsafe(ddl)).then(() => undefined);
    return schemaPromise;
  };

  const snapshots = <T>(): FeedSnapshotStore<T> => ({
    load: async (feedId) => {
      await ensureSchema();
      const id = requiredText(feedId, "Feed id");
      const rows = await sql<{
        cursor: unknown;
        feed_id: string;
        feed_name: string;
        feed_url: string;
        fetched_at: string | Date;
        records: unknown;
        revision: string | null;
      }>`
        SELECT
          snapshot.feed_id,
          snapshot.feed_name,
          snapshot.feed_url,
          snapshot.cursor,
          snapshot.fetched_at,
          snapshot.revision,
          COALESCE((
            SELECT jsonb_agg(
              jsonb_build_object(
                'id', record.record_id,
                'modifiedAt', record.modified_at,
                'value', record.value
              ) ORDER BY record.record_id
            )
            FROM ${sql.unsafe(table.records)} record
            WHERE record.feed_id = snapshot.feed_id
          ), '[]'::jsonb) AS records
        FROM ${sql.unsafe(table.snapshots)} snapshot
        WHERE snapshot.feed_id = ${id}
      `;
      const row = rows[0];
      if (!row) return null;
      const records = json<
        Array<{ id: string; modifiedAt: string | Date; value: T }>
      >(row.records, "Feed records");
      if (!Array.isArray(records))
        throw new Error("Feed records must be an array");
      return {
        cursor: normalizeCursor(row.cursor),
        feed: {
          id: row.feed_id,
          name: row.feed_name,
          url: row.feed_url,
        },
        fetchedAt: timestamp(row.fetched_at, "Feed fetchedAt"),
        records: records.map((record) => ({
          id: requiredText(record.id, "Feed record id"),
          modifiedAt: timestamp(record.modifiedAt, "Feed record modifiedAt"),
          value: record.value,
        })),
        revision: row.revision,
      };
    },
    save: async (snapshot) => {
      await ensureSchema();
      const records = JSON.stringify(
        snapshot.records.map((record) => ({
          id: requiredText(record.id, "Feed record id"),
          modified_at: timestamp(record.modifiedAt, "Feed record modifiedAt"),
          value: record.value,
        })),
      );
      const cursor = JSON.stringify(snapshot.cursor);
      await sql`
        WITH saved_snapshot AS (
          INSERT INTO ${sql.unsafe(table.snapshots)} (
            feed_id, feed_name, feed_url, cursor, fetched_at, revision, updated_at
          ) VALUES (
            ${requiredText(snapshot.feed.id, "Feed id")},
            ${requiredText(snapshot.feed.name, "Feed name")},
            ${requiredText(snapshot.feed.url, "Feed URL")},
            ${cursor}::jsonb,
            ${timestamp(snapshot.fetchedAt, "Feed fetchedAt")}::timestamptz,
            ${snapshot.revision},
            now()
          )
          ON CONFLICT (feed_id) DO UPDATE SET
            feed_name = EXCLUDED.feed_name,
            feed_url = EXCLUDED.feed_url,
            cursor = EXCLUDED.cursor,
            fetched_at = EXCLUDED.fetched_at,
            revision = EXCLUDED.revision,
            updated_at = now()
          RETURNING feed_id
        ), incoming AS (
          SELECT item.id, item.modified_at::timestamptz, item.value
          FROM jsonb_to_recordset(${records}::jsonb)
            AS item(id text, modified_at text, value jsonb)
        ), removed AS (
          DELETE FROM ${sql.unsafe(table.records)} record
          WHERE record.feed_id = ${snapshot.feed.id}
            AND NOT EXISTS (
              SELECT 1 FROM incoming WHERE incoming.id = record.record_id
            )
          RETURNING record_id
        ), written AS (
          INSERT INTO ${sql.unsafe(table.records)} (
            feed_id, record_id, modified_at, value
          )
          SELECT saved_snapshot.feed_id, incoming.id, incoming.modified_at, incoming.value
          FROM saved_snapshot CROSS JOIN incoming
          ON CONFLICT (feed_id, record_id) DO UPDATE SET
            modified_at = EXCLUDED.modified_at,
            value = EXCLUDED.value
          RETURNING record_id
        )
        SELECT
          (SELECT count(*) FROM removed) AS removed,
          (SELECT count(*) FROM written) AS written
      `;
    },
  });

  const syncRuns: FeedSyncRunStore = {
    append: async (run) => {
      await ensureSchema();
      if (!SYNC_STATUSES.has(run.status))
        throw new Error(`Unsupported feed sync status: ${run.status}`);
      if (!Number.isInteger(run.records) || run.records < 0)
        throw new Error("Feed sync records must be a non-negative integer");
      await sql`
        INSERT INTO ${sql.unsafe(table.runs)} (
          id, feed_id, started_at, completed_at, status, error, records, revision
        ) VALUES (
          ${requiredText(run.id, "Feed sync run id")},
          ${requiredText(run.feedId, "Feed sync feed id")},
          ${timestamp(run.startedAt, "Feed sync startedAt")}::timestamptz,
          ${timestamp(run.completedAt, "Feed sync completedAt")}::timestamptz,
          ${run.status}, ${run.error}, ${run.records}, ${run.revision}
        )
        ON CONFLICT (id) DO UPDATE SET
          feed_id = EXCLUDED.feed_id,
          started_at = EXCLUDED.started_at,
          completed_at = EXCLUDED.completed_at,
          status = EXCLUDED.status,
          error = EXCLUDED.error,
          records = EXCLUDED.records,
          revision = EXCLUDED.revision
      `;
    },
    list: async (filter: FeedSyncRunFilter = {}) => {
      await ensureSchema();
      const feedId = filter.feedId?.trim() || null;
      const status = filter.status ?? null;
      const rows = await sql<{
        completed_at: string | Date;
        error: string | null;
        feed_id: string;
        id: string;
        records: number;
        revision: string | null;
        started_at: string | Date;
        status: FeedSyncRun["status"];
      }>`
        SELECT id, feed_id, started_at, completed_at, status, error, records, revision
        FROM ${sql.unsafe(table.runs)}
        WHERE (${feedId}::text IS NULL OR feed_id = ${feedId})
          AND (${status}::text IS NULL OR status = ${status})
        ORDER BY started_at DESC, id DESC
        LIMIT ${limit(filter.limit)}
      `;
      return rows.map((row) => ({
        completedAt: timestamp(row.completed_at, "Feed sync completedAt"),
        error: row.error,
        feedId: row.feed_id,
        id: row.id,
        records: Number(row.records),
        revision: row.revision,
        startedAt: timestamp(row.started_at, "Feed sync startedAt"),
        status: row.status,
      }));
    },
  };

  const saveFindings = async (
    findings: readonly ManagedVulnerabilityFinding[],
  ) => {
    await ensureSchema();
    if (findings.length === 0) return;
    for (const finding of findings) {
      const findingId = finding.id;
      if (!Value.Check(ManagedVulnerabilityFindingSchema, finding))
        throw new Error(`Managed finding ${findingId} is invalid`);
    }
    const payload = JSON.stringify(
      findings.map((finding) => ({
        asset_id: finding.assetId,
        component_id: finding.componentId,
        finding_id: finding.id,
        first_seen_at: finding.firstSeenAt,
        last_seen_at: finding.lastSeenAt,
        severity: finding.severity,
        status: finding.status,
        tenant_id: finding.tenantId,
        value: finding,
      })),
    );
    await sql`
      INSERT INTO ${sql.unsafe(table.findings)} (
        tenant_id, finding_id, asset_id, component_id, severity, status,
        first_seen_at, last_seen_at, value, updated_at
      )
      SELECT
        item.tenant_id, item.finding_id, item.asset_id, item.component_id,
        item.severity, item.status, item.first_seen_at::timestamptz,
        item.last_seen_at::timestamptz, item.value, now()
      FROM jsonb_to_recordset(${payload}::jsonb) AS item(
        tenant_id text, finding_id text, asset_id text, component_id text,
        severity text, status text, first_seen_at text, last_seen_at text,
        value jsonb
      )
      ON CONFLICT (tenant_id, finding_id) DO UPDATE SET
        asset_id = EXCLUDED.asset_id,
        component_id = EXCLUDED.component_id,
        severity = EXCLUDED.severity,
        status = EXCLUDED.status,
        first_seen_at = LEAST(${sql.unsafe(table.findings)}.first_seen_at, EXCLUDED.first_seen_at),
        last_seen_at = GREATEST(${sql.unsafe(table.findings)}.last_seen_at, EXCLUDED.last_seen_at),
        value = EXCLUDED.value,
        updated_at = now()
    `;
  };

  const parseFinding = (value: unknown) => {
    const finding = json<ManagedVulnerabilityFinding>(value, "Managed finding");
    if (!Value.Check(ManagedVulnerabilityFindingSchema, finding))
      throw new Error("Stored managed finding is invalid");
    return finding;
  };

  const findings: ManagedFindingStore = {
    get: async (tenantId, findingId) => {
      await ensureSchema();
      const rows = await sql<{ value: unknown }>`
        SELECT value FROM ${sql.unsafe(table.findings)}
        WHERE tenant_id = ${requiredText(tenantId, "Tenant id")}
          AND finding_id = ${requiredText(findingId, "Finding id")}
      `;
      return rows[0] ? parseFinding(rows[0].value) : null;
    },
    list: async (filter: ManagedFindingFilter) => {
      await ensureSchema();
      const tenantId = requiredText(filter.tenantId, "Tenant id");
      const assetId = filter.assetId?.trim() || null;
      const severity = filter.severity ?? null;
      const status = filter.status ?? null;
      const rows = await sql<{ value: unknown }>`
        SELECT value FROM ${sql.unsafe(table.findings)}
        WHERE tenant_id = ${tenantId}
          AND (${assetId}::text IS NULL OR asset_id = ${assetId})
          AND (${severity}::text IS NULL OR severity = ${severity})
          AND (${status}::text IS NULL OR status = ${status})
        ORDER BY last_seen_at DESC, finding_id
        LIMIT ${limit(filter.limit)}
      `;
      return rows.map(({ value }) => parseFinding(value));
    },
    save: async (finding) => saveFindings([finding]),
    saveMany: saveFindings,
  };

  const leases: FeedLeaseStore = {
    acquire: async (request) => {
      await ensureSchema();
      if (!Number.isFinite(request.ttlMs) || request.ttlMs <= 0)
        throw new Error("Feed lease ttlMs must be positive and finite");
      const now = request.now ?? new Date();
      const expiresAt = new Date(now.getTime() + request.ttlMs);
      const rows = await sql<{ owner_id: string }>`
        INSERT INTO ${sql.unsafe(table.leases)} (
          feed_id, owner_id, expires_at, updated_at
        ) VALUES (
          ${requiredText(request.feedId, "Feed lease feed id")},
          ${requiredText(request.ownerId, "Feed lease owner id")},
          ${expiresAt.toISOString()}::timestamptz,
          ${now.toISOString()}::timestamptz
        )
        ON CONFLICT (feed_id) DO UPDATE SET
          owner_id = EXCLUDED.owner_id,
          expires_at = EXCLUDED.expires_at,
          updated_at = EXCLUDED.updated_at
        WHERE ${sql.unsafe(table.leases)}.expires_at <= ${now.toISOString()}::timestamptz
          OR ${sql.unsafe(table.leases)}.owner_id = EXCLUDED.owner_id
        RETURNING owner_id
      `;
      return rows[0]?.owner_id === request.ownerId.trim();
    },
    release: async (feedId, ownerId) => {
      await ensureSchema();
      const rows = await sql<{ feed_id: string }>`
        DELETE FROM ${sql.unsafe(table.leases)}
        WHERE feed_id = ${requiredText(feedId, "Feed lease feed id")}
          AND owner_id = ${requiredText(ownerId, "Feed lease owner id")}
        RETURNING feed_id
      `;
      return rows.length > 0;
    },
  };

  return { ensureSchema, findings, leases, snapshots, syncRuns };
};
