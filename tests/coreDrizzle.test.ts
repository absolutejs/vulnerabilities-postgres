import {
  VULNERABILITY_CONTRACT_VERSION,
  createStableFindingId,
  type FeedSnapshot,
  type ManagedVulnerabilityFinding,
} from "@absolutejs/vulnerabilities";
import { PGlite } from "@electric-sql/pglite";
import { afterAll, beforeAll, expect, test } from "bun:test";
import { drizzle } from "drizzle-orm/pglite";
import {
  createDrizzleVulnerabilityStore,
  vulnerabilityPostgresSchemaSql,
} from "../src";

const timestamp = "2026-07-23T19:00:00.000Z";
const tenantId = "drizzle-core-test";
const findingId = createStableFindingId({
  assetId: "production-web-1",
  componentIdentity: "pkg:npm/elysia@1.4.29",
  tenantId,
  vulnerabilityIds: ["CVE-2026-0001"],
});
const finding: ManagedVulnerabilityFinding = {
  assetId: "production-web-1",
  componentId: "component-elysia",
  contract: VULNERABILITY_CONTRACT_VERSION,
  firstSeenAt: timestamp,
  id: findingId,
  lastSeenAt: timestamp,
  observationIds: ["observation-1"],
  severity: "high",
  status: "new",
  tenantId,
  vulnerabilityIds: ["CVE-2026-0001"],
};
const snapshot = (
  recordIds: readonly string[],
): FeedSnapshot<{ cve: string }> => ({
  cursor: { etag: '"2"', lastModified: null, token: "page-2" },
  feed: {
    id: "osv-drizzle",
    name: "Open Source Vulnerabilities",
    url: "https://api.osv.dev/v1",
  },
  fetchedAt: timestamp,
  records: recordIds.map((id, index) => ({
    id,
    modifiedAt: `2026-07-23T18:0${index}:00.000Z`,
    value: { cve: id },
  })),
  revision: "2",
});

const client = new PGlite();
const db = drizzle({ client });
const store = createDrizzleVulnerabilityStore(db);

beforeAll(async () => {
  await client.exec(vulnerabilityPostgresSchemaSql());
});

afterAll(async () => {
  await client.close();
});

test("runs the schema-derived intelligence lifecycle with native JSONB", async () => {
  const snapshots = store.snapshots<{ cve: string }>();
  await snapshots.save(snapshot(["CVE-2026-0001", "CVE-2026-0002"]));
  await snapshots.save(snapshot(["CVE-2026-0002"]));
  expect(await snapshots.load("osv-drizzle")).toMatchObject({
    records: [{ id: "CVE-2026-0002" }],
  });

  await store.syncRuns.append({
    completedAt: "2026-07-23T19:00:02.000Z",
    error: null,
    feedId: "osv-drizzle",
    id: "run-drizzle",
    records: 1,
    revision: "2",
    startedAt: timestamp,
    status: "updated",
  });
  expect(await store.syncRuns.list({ feedId: "osv-drizzle" })).toHaveLength(1);

  await store.findings.save(finding);
  expect(await store.findings.get(tenantId, findingId)).toEqual(finding);

  const now = new Date(timestamp);
  expect(
    await store.leases.acquire({
      feedId: "osv-drizzle",
      now,
      ownerId: "worker-1",
      ttlMs: 60_000,
    }),
  ).toBe(true);
  expect(
    await store.leases.acquire({
      feedId: "osv-drizzle",
      now,
      ownerId: "worker-2",
      ttlMs: 60_000,
    }),
  ).toBe(false);
  expect(await store.leases.release("osv-drizzle", "worker-1")).toBe(true);

  const types = await client.query<{
    cursor_type: string;
    finding_type: string;
    record_type: string;
  }>(`
		SELECT
			jsonb_typeof(snapshot.cursor) AS cursor_type,
			jsonb_typeof(record.value) AS record_type,
			jsonb_typeof(finding.value) AS finding_type
		FROM vulnerability_feed_snapshots snapshot
		JOIN vulnerability_feed_records record
			ON record.feed_id = snapshot.feed_id
		JOIN vulnerability_findings finding
			ON finding.tenant_id = '${tenantId}'
		LIMIT 1
	`);
  expect(types.rows[0]).toEqual({
    cursor_type: "object",
    finding_type: "object",
    record_type: "object",
  });
});
