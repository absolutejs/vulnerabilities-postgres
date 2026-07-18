import { defineImplementation, defineManifest } from "@absolutejs/manifest";
import { Type } from "@sinclair/typebox";
import type { CreatePostgresVulnerabilityStoreOptions } from "./index";

export const manifest =
  defineManifest<CreatePostgresVulnerabilityStoreOptions>()({
    contract: 2,
    discovery: {
      audiences: ["platform-operators", "security-teams"],
      intents: [
        "persist vulnerability intelligence",
        "retain vulnerability sync history",
        "store managed vulnerability findings, VEX decisions, remediation evidence, and risk assessments",
      ],
      keywords: ["vulnerabilities", "Postgres", "CVE", "feed-history"],
      protocols: ["PostgreSQL", "AbsoluteJS vulnerability contracts"],
    },
    identity: {
      accent: "#336791",
      category: "operations",
      description:
        "Durable Postgres snapshots, findings, VEX decisions, remediation evidence, risk assessments, and distributed refresh leases.",
      docsUrl: "https://github.com/absolutejs/vulnerabilities-postgres",
      name: "@absolutejs/vulnerabilities-postgres",
      tagline: "Keep vulnerability intelligence durable and auditable.",
    },
    implements: [
      defineImplementation<CreatePostgresVulnerabilityStoreOptions>()({
        contract: "vulnerabilities/persistence",
        factory: "createPostgresVulnerabilityStore",
        from: "@absolutejs/vulnerabilities-postgres",
        requires: {
          env: [
            {
              description:
                "Postgres connection string for vulnerability intelligence, findings, VEX decisions, remediation evidence, and risk assessments",
              example: "postgres://user:pass@host/db",
              key: "DATABASE_URL",
              secret: true,
            },
          ],
          peers: [
            {
              name: "@neondatabase/serverless",
              range: ">=0.10.0",
              reason: "HTTP Postgres client for serverless environments",
            },
          ],
          services: [
            {
              description:
                "Stores vulnerability intelligence, findings, VEX decisions, remediation evidence, risk assessments, and leases",
              id: "postgres",
            },
          ],
        },
        settings: Type.Object({
          ensureSchema: Type.Optional(
            Type.Boolean({
              default: true,
              description:
                "Create vulnerability tables automatically on first use.",
              title: "Create tables automatically",
            }),
          ),
          tablePrefix: Type.Optional(
            Type.String({
              default: "vulnerability",
              description: "Prefix for all vulnerability persistence tables.",
              pattern: "^[a-zA-Z_][a-zA-Z0-9_]*$",
              title: "Table prefix",
            }),
          ),
        }),
        title: "Your Postgres database (durable vulnerability intelligence)",
        wiring: {
          code: "createPostgresVulnerabilityStore({ sql: neon(${env.DATABASE_URL} ?? ''), ...${settings} })",
          imports: [
            { from: "@neondatabase/serverless", names: ["neon"] },
            {
              from: "@absolutejs/vulnerabilities-postgres",
              names: ["createPostgresVulnerabilityStore"],
            },
          ],
        },
      }),
    ],
    settings: Type.Object({}),
    wiring: [],
  });
