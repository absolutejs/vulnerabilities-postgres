import { beforeEach, describe, expect, test } from "bun:test";
import {
  VULNERABILITY_CONTRACT_VERSION,
  createStableFindingId,
  type FeedSnapshot,
  type ManagedVulnerabilityFinding,
  type VulnerabilityObservation,
  type VulnerabilityRiskAssessment,
} from "@absolutejs/vulnerabilities";
import {
  createPostgresVulnerabilityStore,
  vulnerabilityPostgresSchemaSql,
} from "../src";
import { makePgliteTag } from "./pglite";

const timestamp = "2026-07-18T19:00:00Z";
const findingId = createStableFindingId({
  assetId: "production-web-1",
  componentIdentity: "pkg:deb/ubuntu/nginx@1.24.0-2ubuntu7.4",
  tenantId: "tenant-1",
  vulnerabilityIds: ["CVE-2026-0001"],
});
let store: ReturnType<typeof createPostgresVulnerabilityStore>;

beforeEach(() => {
  store = createPostgresVulnerabilityStore({ sql: makePgliteTag().sql });
});

const snapshot = (records = 2): FeedSnapshot<{ cve: string }> => ({
  cursor: { etag: '"2"', lastModified: null, token: "page-2" },
  feed: {
    id: "osv",
    name: "Open Source Vulnerabilities",
    url: "https://api.osv.dev/v1",
  },
  fetchedAt: timestamp,
  records: Array.from({ length: records }, (_, index) => ({
    id: `CVE-2026-000${index + 1}`,
    modifiedAt: `2026-07-18T18:0${index}:00Z`,
    value: { cve: `CVE-2026-000${index + 1}` },
  })),
  revision: "2",
});

const finding = (
  status: ManagedVulnerabilityFinding["status"] = "new",
): ManagedVulnerabilityFinding => ({
  assetId: "production-web-1",
  componentId: "component-nginx",
  contract: VULNERABILITY_CONTRACT_VERSION,
  firstSeenAt: timestamp,
  id: findingId,
  lastSeenAt: timestamp,
  observationIds: ["observation-1"],
  severity: "high" as const,
  status,
  tenantId: "tenant-1",
  vulnerabilityIds: ["CVE-2026-0001"],
});

const observation: VulnerabilityObservation = {
  advisoryIds: ["CVE-2026-0001"],
  assetId: "production-web-1",
  componentId: "component-nginx",
  contract: VULNERABILITY_CONTRACT_VERSION,
  evidence: [],
  id: "observation-1",
  observedAt: timestamp,
  scanner: "absolutejs-correlation",
  scannerRecordId: "CVE-2026-0001",
  severity: "high",
};
const assessment: VulnerabilityRiskAssessment = {
  assessedAt: timestamp,
  contract: VULNERABILITY_CONTRACT_VERSION,
  epssPercentile: 0.97,
  epssProbability: 0.31,
  findingId,
  fixAvailable: true,
  internetExposed: true,
  kev: true,
  policyVersion: "absolutejs-risk-v1",
  priority: "emergency",
  reachability: "reachable",
  reasons: ["kev_internet_exposed", "fix_available"],
  remediateBy: "2026-07-19T19:00:00Z",
};

describe("Postgres feed snapshots", () => {
  test("round-trips cursor, provenance, records, and values", async () => {
    const snapshots = store.snapshots<{ cve: string }>();
    await snapshots.save(snapshot());
    const loaded = await snapshots.load("osv");

    expect(loaded?.feed).toEqual(snapshot().feed);
    expect(loaded?.cursor).toEqual(snapshot().cursor);
    expect(loaded?.records.map(({ value }) => value.cve)).toEqual([
      "CVE-2026-0001",
      "CVE-2026-0002",
    ]);
  });

  test("atomically replaces obsolete records", async () => {
    const snapshots = store.snapshots<{ cve: string }>();
    await snapshots.save(snapshot(2));
    await snapshots.save({ ...snapshot(1), revision: "3" });
    const loaded = await snapshots.load("osv");

    expect(loaded?.records).toHaveLength(1);
    expect(loaded?.revision).toBe("3");
  });
});

describe("Postgres sync history", () => {
  test("persists and filters immutable sync evidence", async () => {
    await store.syncRuns.append({
      completedAt: "2026-07-18T19:00:02Z",
      error: null,
      feedId: "osv",
      id: "run-1",
      records: 2,
      revision: "2",
      startedAt: timestamp,
      status: "updated",
    });
    await store.syncRuns.append({
      completedAt: "2026-07-18T20:00:02Z",
      error: "provider unavailable",
      feedId: "kev",
      id: "run-2",
      records: 0,
      revision: null,
      startedAt: "2026-07-18T20:00:00Z",
      status: "failed",
    });

    expect((await store.syncRuns.list({ feedId: "osv" }))[0]).toMatchObject({
      feedId: "osv",
      records: 2,
      status: "updated",
    });
    expect(await store.syncRuns.list({ status: "failed" })).toHaveLength(1);
  });
});

describe("Postgres managed findings", () => {
  test("upserts, gets, and tenant-filters contract-valid findings", async () => {
    await store.findings.save(finding());
    expect(await store.findings.get("tenant-1", findingId)).toEqual(finding());
    await store.findings.save(finding("under_investigation"));
    expect(
      await store.findings.list({
        status: "under_investigation",
        tenantId: "tenant-1",
      }),
    ).toEqual([finding("under_investigation")]);
    expect(await store.findings.list({ tenantId: "tenant-2" })).toEqual([]);
  });
});

describe("Postgres vulnerability observations", () => {
  test("upserts evidence and enforces tenant filters", async () => {
    await store.observations.save("tenant-1", observation);
    expect(await store.observations.get("tenant-1", observation.id)).toEqual(
      observation,
    );
    expect(
      await store.observations.list({
        assetId: observation.assetId,
        tenantId: "tenant-1",
      }),
    ).toEqual([observation]);
    expect(await store.observations.list({ tenantId: "tenant-2" })).toEqual([]);
  });
});

describe("Postgres vulnerability risk assessments", () => {
  test("upserts assessments and filters tenant priorities", async () => {
    await store.riskAssessments.save("tenant-1", assessment);
    expect(await store.riskAssessments.get("tenant-1", findingId)).toEqual(
      assessment,
    );
    expect(
      await store.riskAssessments.list({
        priority: "emergency",
        tenantId: "tenant-1",
      }),
    ).toEqual([assessment]);
    expect(await store.riskAssessments.list({ tenantId: "tenant-2" })).toEqual(
      [],
    );
  });
});

describe("Postgres refresh leases", () => {
  test("excludes competing owners until expiry and supports release", async () => {
    const now = new Date(timestamp);
    expect(
      await store.leases.acquire({
        feedId: "osv",
        now,
        ownerId: "worker-1",
        ttlMs: 60_000,
      }),
    ).toBe(true);
    expect(
      await store.leases.acquire({
        feedId: "osv",
        now,
        ownerId: "worker-2",
        ttlMs: 60_000,
      }),
    ).toBe(false);
    expect(
      await store.leases.acquire({
        feedId: "osv",
        now: new Date("2026-07-18T19:01:01Z"),
        ownerId: "worker-2",
        ttlMs: 60_000,
      }),
    ).toBe(true);
    expect(await store.leases.release("osv", "worker-2")).toBe(true);
  });
});

describe("Postgres schema", () => {
  test("validates identifiers and emits every durable table", () => {
    const sql = vulnerabilityPostgresSchemaSql("security");
    expect(sql).toContain("security_feed_snapshots");
    expect(sql).toContain("security_feed_sync_runs");
    expect(sql).toContain("security_findings");
    expect(sql).toContain("security_observations");
    expect(sql).toContain("security_risk_assessments");
    expect(sql).toContain("security_feed_leases");
    expect(() => vulnerabilityPostgresSchemaSql("bad-prefix")).toThrow(
      "invalid tablePrefix",
    );
  });
});
