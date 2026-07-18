# @absolutejs/vulnerabilities-postgres

Durable Postgres persistence for `@absolutejs/vulnerabilities`.

```ts
import { createPostgresVulnerabilityStore } from "@absolutejs/vulnerabilities-postgres";
import postgres from "postgres";

const persistence = createPostgresVulnerabilityStore({
  sql: postgres(process.env.DATABASE_URL!),
});

const osvSnapshots = persistence.snapshots();
```

The package stores complete provider snapshots and records, appendable sync
history, tenant-scoped managed findings, correlation observations, VEX decisions
and applications, risk assessments, and expiring distributed refresh leases. Snapshot replacement is
one Postgres statement, so readers never see a half-replaced record set. Schema
creation is lazy and idempotent, or can be disabled when application migrations
own the tables.

The SQL surface is compatible with postgres.js and Neon-style tagged-template
clients. Table prefixes are strictly validated before identifiers are included
in SQL.
