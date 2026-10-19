import { Kysely, PostgresDialect } from 'kysely';
import pg from 'pg';

export interface HealthProbe {
  id: number;
  checked_at: Date;
}

export interface Database {
  health_probe: HealthProbe;
}

let instance: Kysely<Database> | null = null;

export function getDb(): Kysely<Database> {
  if (instance) return instance;

  const url = process.env.DATABASE_URL;
  if (!url) throw new Error('DATABASE_URL tanimli degil');

  instance = new Kysely<Database>({
    dialect: new PostgresDialect({
      pool: new pg.Pool({
        connectionString: url,
        max: 10,
        idleTimeoutMillis: 30_000,
        connectionTimeoutMillis: 5_000,
      }),
    }),
  });

  return instance;
}

export async function closeDb(): Promise<void> {
  if (!instance) return;
  await instance.destroy();
  instance = null;
}
