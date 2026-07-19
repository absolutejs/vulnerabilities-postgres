import { beforeEach, describe, expect, test } from "bun:test";
import {
  DEFAULT_VULNERABILITY_ALERT_CONFIGURATION,
  VULNERABILITY_CONTRACT_VERSION,
  createStableFindingId,
  type FeedSnapshot,
  type ManagedVulnerabilityFinding,
  type RemediationExecution,
  type RemediationPlan,
  type RemediationVerification,
  type VulnerabilityObservation,
  type VulnerabilityRiskAssessment,
  type VulnerabilityAlert,
  type VexDecision,
  type VexFindingApplication,
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
const vexDecision: VexDecision = {
  author: "security@example.com",
  contract: VULNERABILITY_CONTRACT_VERSION,
  createdAt: timestamp,
  evidence: [],
  expiresAt: null,
  id: "vex-1",
  justification: null,
  productId: "production-web-1",
  reviewedAt: null,
  statement: "Investigation in progress.",
  status: "under_investigation",
  vulnerabilityId: "CVE-2026-0001",
};
const vexApplication: VexFindingApplication = {
  appliedAt: timestamp,
  contract: VULNERABILITY_CONTRACT_VERSION,
  decisionId: vexDecision.id,
  endedAt: null,
  findingId,
  previousStatus: "new",
  resultingStatus: "under_investigation",
  tenantId: "tenant-1",
};
const remediationPlan: RemediationPlan = {
  actions: [
    {
      assetId: "production-web-1",
      componentId: "component-nginx",
      fromVersion: "release-1",
      id: "action-1",
      kind: "rebuild",
      requiresRestart: true,
      toVersion: "release-2",
    },
  ],
  approvedAt: timestamp,
  approvedBy: "operator-1",
  contract: VULNERABILITY_CONTRACT_VERSION,
  createdAt: timestamp,
  createdBy: "security-team",
  findingIds: [findingId],
  id: "plan-1",
  rollbackSummary: "Restore release-1.",
  status: "succeeded",
};
const remediationExecution: RemediationExecution = {
  completedAt: "2026-07-18T20:00:00Z",
  contract: VULNERABILITY_CONTRACT_VERSION,
  evidence: [],
  id: "execution-1",
  message: "Release activated.",
  planId: remediationPlan.id,
  startedAt: timestamp,
  status: "succeeded",
};
const remediationVerification: RemediationVerification = {
  contract: VULNERABILITY_CONTRACT_VERSION,
  deployments: [
    {
      activatedAt: "2026-07-18T20:00:00Z",
      assetId: "production-web-1",
      releaseId: "release-2",
    },
  ],
  evidence: [
    {
      collectedAt: "2026-07-18T21:00:00Z",
      digest: null,
      kind: "verification",
      source: "absolutejs-inventory",
      uri: null,
    },
  ],
  executionId: remediationExecution.id,
  fixedFindingIds: [findingId],
  id: "verification-1",
  observedAt: "2026-07-18T21:00:00Z",
  planId: remediationPlan.id,
  remainingFindingIds: [],
  status: "passed",
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

describe("Postgres VEX decisions", () => {
  test("persists tenant-scoped decisions and finding applications", async () => {
    await store.vexDecisions.save("tenant-1", vexDecision);
    expect(await store.vexDecisions.get("tenant-1", vexDecision.id)).toEqual(
      vexDecision,
    );
    expect(
      await store.vexDecisions.list({
        productId: vexDecision.productId,
        tenantId: "tenant-1",
      }),
    ).toEqual([vexDecision]);
    await store.vexApplications.save(vexApplication);
    expect(await store.vexApplications.get("tenant-1", findingId)).toEqual(
      vexApplication,
    );
    expect(await store.vexDecisions.list({ tenantId: "tenant-2" })).toEqual([]);
  });
});

describe("Postgres remediation lifecycle", () => {
  test("persists tenant-scoped plans, executions, and verifications", async () => {
    await store.remediationPlans.save("tenant-1", remediationPlan);
    await store.remediationExecutions.save("tenant-1", remediationExecution);
    await store.remediationVerifications.save(
      "tenant-1",
      remediationVerification,
    );
    expect(
      await store.remediationPlans.list({
        status: "succeeded",
        tenantId: "tenant-1",
      }),
    ).toEqual([remediationPlan]);
    expect(
      await store.remediationExecutions.list("tenant-1", remediationPlan.id),
    ).toEqual([remediationExecution]);
    expect(
      await store.remediationVerifications.list(
        "tenant-1",
        remediationExecution.id,
      ),
    ).toEqual([remediationVerification]);
    expect(await store.remediationPlans.list({ tenantId: "tenant-2" })).toEqual(
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
    expect(sql).toContain("security_remediation_plans");
    expect(sql).toContain("security_remediation_executions");
    expect(sql).toContain("security_remediation_verifications");
    expect(sql).toContain("security_vex_decisions");
    expect(sql).toContain("security_vex_applications");
    expect(sql).toContain("security_feed_leases");
    expect(() => vulnerabilityPostgresSchemaSql("bad-prefix")).toThrow(
      "invalid tablePrefix",
    );
  });
});

describe("Postgres vulnerability alert lifecycle", () => {
  const tenantId = "tenant-1";
  const actorId = "00000000-0000-4000-8000-000000000001";
  const alert: VulnerabilityAlert = {
    assetId: "project-1",
    body: "A reachable critical vulnerability requires remediation.",
    dueAt: "2026-07-19T19:00:00Z",
    findingId,
    fingerprint: "critical-finding",
    id: "alert-critical-finding",
    kind: "remediation_plan_overdue",
    observedAt: timestamp,
    planId: null,
    severity: "critical",
    sourceId: findingId,
    tenantId,
    title: "Critical vulnerability requires remediation",
  };

  test("versions policy and runs durable delivery, acknowledgement, resolution, and recurrence transitions", async () => {
    const first = await store.alertPolicies.activate({
      activatedAt: timestamp,
      activatedBy: actorId,
      configuration: structuredClone(DEFAULT_VULNERABILITY_ALERT_CONFIGURATION),
      reason: "Initial managed policy",
      tenantId,
    });
    const second = await store.alertPolicies.activate({
      activatedAt: "2026-07-18T20:00:00Z",
      activatedBy: actorId,
      configuration: structuredClone(DEFAULT_VULNERABILITY_ALERT_CONFIGURATION),
      reason: "Reviewed escalation policy",
      tenantId,
    });
    expect([first.version, second.version]).toEqual([1, 2]);
    expect(
      (await store.alertPolicies.list()).map(({ status }) => status),
    ).toEqual(["active", "superseded"]);

    expect(await store.alertIncidents.observe({ alert, policy: second })).toBe(
      "opened",
    );
    expect(await store.alertIncidents.observe({ alert, policy: second })).toBe(
      "observed",
    );
    expect((await store.alertIncidents.incidents())[0]?.observation_count).toBe(
      2,
    );
    expect(await store.alertIncidents.deliveries()).toHaveLength(1);

    const [delivery] = await store.alertIncidents.claimDeliveries();
    expect(delivery?.audience).toBe("owner");
    expect(
      await store.alertIncidents.completeDelivery({
        alertId: alert.id,
        audience: "owner",
        deliveryId: delivery!.id,
        kind: "opened",
      }),
    ).toBe(true);
    expect(
      await store.alertIncidents.acknowledge({
        acknowledgedAt: "2026-07-18T20:30:00Z",
        acknowledgedBy: actorId,
        alertId: alert.id,
      }),
    ).toBe(true);
    expect(
      await store.alertIncidents.acknowledge({
        acknowledgedAt: "2026-07-18T20:31:00Z",
        acknowledgedBy: actorId,
        alertId: alert.id,
      }),
    ).toBe(false);

    const policies = new Map([[tenantId, second]]);
    expect(
      await store.alertIncidents.resolveInactive({
        activeAlertIds: new Set(),
        policies,
        resolvedAt: "2026-07-18T21:00:00Z",
      }),
    ).toBe(1);
    expect(await store.alertIncidents.observe({ alert, policy: second })).toBe(
      "reopened",
    );
    const incident = (await store.alertIncidents.incidents())[0];
    expect(incident?.occurrence_count).toBe(2);
    expect(incident?.status).toBe("open");
    expect(
      (await store.alertIncidents.events()).map(({ kind }) => kind),
    ).toEqual(["opened", "resolved", "acknowledged", "delivered", "opened"]);
  });
});
