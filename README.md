# @absolutejs/vulnerabilities-postgres

Durable Postgres persistence for `@absolutejs/vulnerabilities`.

```ts
import { createPostgresVulnerabilityStore } from "@absolutejs/vulnerabilities-postgres";
import postgres from "postgres";

const persistence = createPostgresVulnerabilityStore({
  sql: postgres(process.env.DATABASE_URL!),
});

const osvSnapshots = persistence.snapshots();
const alertPolicies = persistence.alertPolicies;
const alertIncidents = persistence.alertIncidents;
```

Applications already using Drizzle can keep the complete vulnerability
lifecycle schema-derived:

```ts
import {
  createDrizzleVulnerabilityStore,
  vulnerabilityCoreDrizzleSchema,
} from "@absolutejs/vulnerabilities-postgres";
import { drizzle } from "drizzle-orm/bun-sql";

export const schema = {
  ...vulnerabilityCoreDrizzleSchema,
  // ...the rest of your application's tables
};
const db = drizzle({ client: sql });
const persistence = createDrizzleVulnerabilityStore(db);
```

The Drizzle store targets the standard `vulnerability_*` tables. Custom table
prefixes and runtime schema bootstrap remain available through
`createPostgresVulnerabilityStore`.

The package stores complete provider snapshots and records, appendable sync
history, tenant-scoped managed findings, correlation observations, VEX decisions
and applications, remediation plans and evidence, risk assessments, immutable
alert-policy versions, incident timelines, and leased notification deliveries.
Snapshot replacement is one transaction, so readers never see a half-replaced
record set. Schema creation is lazy and idempotent for the tagged-template
adapter; Drizzle applications import the package tables and manage migrations.

The SQL surface is compatible with postgres.js and Neon-style tagged-template
clients. Table prefixes are strictly validated before identifiers are included
in SQL. Alert lifecycle mutations require a client with a `begin` transaction
method, such as postgres.js or Bun SQL.
