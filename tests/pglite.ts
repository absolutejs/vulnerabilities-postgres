import { PGlite } from "@electric-sql/pglite";
import type { PostgresTag } from "../src";

type RawFragment = { __raw: string; then: Promise<unknown[]>["then"] };

const isRaw = (value: unknown): value is RawFragment =>
  typeof value === "object" && value !== null && "__raw" in value;

export const makePgliteTag = (): { db: PGlite; sql: PostgresTag } => {
  const db = new PGlite();
  const tag = ((strings: TemplateStringsArray, ...values: unknown[]) => {
    let text = "";
    const binds: unknown[] = [];
    strings.forEach((chunk, index) => {
      text += chunk;
      if (index >= values.length) return;
      const value = values[index];
      if (isRaw(value)) text += value.__raw;
      else {
        binds.push(value);
        text += `$${binds.length}`;
      }
    });
    return db.query(text, binds).then((result) => result.rows);
  }) as unknown as PostgresTag & { unsafe: PostgresTag["unsafe"] };
  tag.unsafe = (raw: string) => {
    const fragment: RawFragment = {
      __raw: raw,
      then: (onfulfilled, onrejected) =>
        db
          .exec(raw)
          .then(() => [] as unknown[])
          .then(onfulfilled, onrejected),
    };
    return fragment as unknown as ReturnType<PostgresTag["unsafe"]>;
  };
  tag.begin = async (callback) => {
    await db.exec("BEGIN");
    try {
      const result = await callback(tag);
      await db.exec("COMMIT");
      return result;
    } catch (error) {
      await db.exec("ROLLBACK");
      throw error;
    }
  };
  return { db, sql: tag };
};
