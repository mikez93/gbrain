import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { PGLiteEngine } from '../src/core/pglite-engine.ts';
import { LATEST_VERSION, MIGRATIONS, runMigrations } from '../src/core/migrate.ts';

let engine: PGLiteEngine;
const migration = MIGRATIONS.find((item) => item.version === 143);
const columns = ['fleet_grant', 'fleet_grant_set_at', 'fleet_grant_set_by', 'fleet_grant_version'];

async function presentColumns(): Promise<string[]> {
  const rows = await engine.executeRaw<{ column_name: string }>(
    `SELECT column_name FROM information_schema.columns
      WHERE table_name = 'oauth_clients'
        AND column_name = ANY($1::text[])
      ORDER BY column_name`,
    [columns],
  );
  return rows.map((row) => row.column_name);
}

beforeAll(async () => {
  engine = new PGLiteEngine();
  await engine.connect({ database_url: '' });
  await engine.initSchema();
});

afterAll(async () => {
  await engine.disconnect();
});

describe('migration v143 — dedicated fleet-router grant', () => {
  test('has the canonical idempotent schema contract', () => {
    expect(migration).toBeDefined();
    expect(migration?.name).toBe('oauth_fleet_router_grant');
    expect(migration?.idempotent).toBeTrue();
    expect(migration?.sqlFor).toBeUndefined();
    expect(LATEST_VERSION).toBeGreaterThanOrEqual(143);
    for (const column of columns) expect(migration?.sql).toContain(`ADD COLUMN IF NOT EXISTS ${column}`);
    expect(migration?.sql).toContain("DEFAULT 'ordinary_remote'");
    expect(migration?.sql).toContain('fleet_grant_version INTEGER NOT NULL DEFAULT 0');
  });

  test('fresh schema defaults every client to ordinary version zero without proof', async () => {
    expect(await presentColumns()).toEqual(columns);
    await engine.executeRaw(
      `INSERT INTO oauth_clients (client_id, client_name) VALUES ('v143-fresh', 'v143-fresh')`,
    );
    const [row] = await engine.executeRaw<{
      fleet_grant: string; fleet_grant_version: number; fleet_grant_set_by: string | null; fleet_grant_set_at: string | null;
    }>(
      `SELECT fleet_grant, fleet_grant_version, fleet_grant_set_by, fleet_grant_set_at
         FROM oauth_clients WHERE client_id = 'v143-fresh'`,
    );
    expect(row).toEqual({
      fleet_grant: 'ordinary_remote', fleet_grant_version: 0,
      fleet_grant_set_by: null, fleet_grant_set_at: null,
    });
  });

  test('upgrades a stripped v142 shape and is ledger/SQL idempotent', async () => {
    await engine.executeRaw('ALTER TABLE oauth_clients DROP CONSTRAINT IF EXISTS oauth_clients_fleet_grant_active_chk');
    await engine.executeRaw('ALTER TABLE oauth_clients DROP CONSTRAINT IF EXISTS oauth_clients_fleet_grant_proof_chk');
    await engine.executeRaw('ALTER TABLE oauth_clients DROP CONSTRAINT IF EXISTS oauth_clients_fleet_grant_version_chk');
    await engine.executeRaw('ALTER TABLE oauth_clients DROP CONSTRAINT IF EXISTS oauth_clients_fleet_grant_state_chk');
    await engine.executeRaw('ALTER TABLE oauth_clients DROP COLUMN IF EXISTS fleet_grant_set_at');
    await engine.executeRaw('ALTER TABLE oauth_clients DROP COLUMN IF EXISTS fleet_grant_set_by');
    await engine.executeRaw('ALTER TABLE oauth_clients DROP COLUMN IF EXISTS fleet_grant_version');
    await engine.executeRaw('ALTER TABLE oauth_clients DROP COLUMN IF EXISTS fleet_grant');
    expect(await presentColumns()).toEqual([]);

    await engine.executeRaw(
      `INSERT INTO oauth_clients (client_id, client_name) VALUES ('v142-existing', 'v142-existing')`,
    );
    await engine.setConfig('version', '142');
    const upgraded = await runMigrations(engine);
    expect(upgraded.applied).toBe(1);
    expect(upgraded.current).toBe(LATEST_VERSION);
    expect(await presentColumns()).toEqual(columns);
    const [existing] = await engine.executeRaw<{
      fleet_grant: string; fleet_grant_version: number; fleet_grant_set_by: string | null; fleet_grant_set_at: string | null;
    }>(
      `SELECT fleet_grant, fleet_grant_version, fleet_grant_set_by, fleet_grant_set_at
         FROM oauth_clients WHERE client_id = 'v142-existing'`,
    );
    expect(existing).toEqual({
      fleet_grant: 'ordinary_remote', fleet_grant_version: 0,
      fleet_grant_set_by: null, fleet_grant_set_at: null,
    });
    expect((await runMigrations(engine)).applied).toBe(0);
    await engine.runMigration(143, migration!.sql!);
    expect(await presentColumns()).toEqual(columns);
  });
});
