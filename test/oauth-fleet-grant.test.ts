import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { vector } from '@electric-sql/pglite/vector';
import { pg_trgm } from '@electric-sql/pglite/contrib/pg_trgm';
import { GBrainOAuthProvider } from '../src/core/oauth-provider.ts';
import { PGLITE_SCHEMA_SQL } from '../src/core/pglite-schema.ts';
import { isFleetRouterContext } from '../src/core/ops/fleet-router-context.ts';
import type { AuthInfo, OperationContext } from '../src/core/operations.ts';
import { parseRegisterClientArgs, registerScopedClient } from '../src/commands/auth.ts';

let db: PGlite;
let sql: (strings: TemplateStringsArray, ...values: unknown[]) => Promise<any>;
let provider: GBrainOAuthProvider;

beforeAll(async () => {
  db = new PGlite({ extensions: { vector, pg_trgm } });
  await db.exec(PGLITE_SCHEMA_SQL);
  sql = async (strings: TemplateStringsArray, ...values: unknown[]) => {
    const query = strings.reduce((acc, str, i) => acc + str + (i < values.length ? `$${i + 1}` : ''), '');
    return (await db.query(query, values as any[])).rows;
  };
  provider = new GBrainOAuthProvider({ sql, tokenTtl: 60, refreshTtl: 300, allowClientCredentialsDcr: true });
}, 30_000);

afterAll(async () => {
  if (db) await db.close();
}, 15_000);

async function mint(name: string): Promise<{ clientId: string; token: string }> {
  const { clientId, clientSecret } = await provider.registerClientManual(
    name, ['client_credentials'], 'read', [], 'default', ['default'],
  );
  const tokens = await provider.exchangeClientCredentials(clientId, clientSecret!, 'read');
  return { clientId, token: tokens.access_token };
}

function context(auth: Partial<AuthInfo>): OperationContext {
  return {
    remote: true,
    auth: { token: 'fixture', clientId: 'fixture', scopes: ['read'], ...auth },
  } as unknown as OperationContext;
}

describe('dedicated fleet-router OAuth grant (v143)', () => {
  test('manual registration is ordinary by default and explicitly granted with one returned event', async () => {
    const ordinary = await registerScopedClient(sql, 'manual-ordinary', parseRegisterClientArgs([]));
    expect(ordinary).toMatchObject({ fleetGrant: 'ordinary_remote', fleetGrantVersion: 0 });
    expect(ordinary.fleetGrantEventId).toBeUndefined();

    const granted = await registerScopedClient(
      sql,
      'manual-fleet',
      parseRegisterClientArgs(['--fleet-router']),
    );
    expect(granted).toMatchObject({
      fleetGrant: 'fleet_router',
      fleetGrantVersion: 1,
      fleetGrantSetBy: 'operator',
    });
    expect(Number.isInteger(granted.fleetGrantEventId)).toBeTrue();
    expect(granted.fleetGrantEventId!).toBeGreaterThan(0);
    const [event] = await sql`
      SELECT id, params FROM mcp_request_log
       WHERE operation = 'fleet_grant_change' AND params->>'client_id' = ${granted.clientId}
    `;
    expect(Number(event.id)).toBe(granted.fleetGrantEventId!);
    expect(event.params.via).toBe('register_cli');
  });

  test('fresh and DCR clients default to ordinary_remote; names/surfaces cannot self-authorize', async () => {
    const fresh = await mint('brain-router-owner-0123456789ab');
    const freshInfo = await provider.verifyAccessToken(fresh.token) as unknown as AuthInfo;
    expect(freshInfo.fleetGrant).toBe('ordinary_remote');
    expect(freshInfo.fleetGrantSetBy).toBeUndefined();
    expect(freshInfo.fleetGrantSetAt).toBeUndefined();
    expect(isFleetRouterContext(context({
      clientName: 'brain-router-owner-0123456789ab',
      surface: 'full',
      surfaceSetBy: 'operator',
    }))).toBeFalse();

    const dcr = await provider.clientsStore.registerClient!({
      client_name: 'brain-router-owner-fedcba987654',
      redirect_uris: [],
      grant_types: ['client_credentials'],
      scope: 'read',
      token_endpoint_auth_method: 'client_secret_post',
      fleet_grant: 'fleet_router',
      fleet_grant_set_by: 'operator',
    } as any);
    const [dcrRow] = await sql`
      SELECT fleet_grant, fleet_grant_version, fleet_grant_set_by, fleet_grant_set_at
        FROM oauth_clients WHERE client_id = ${dcr.client_id}
    `;
    expect(dcrRow).toEqual({
      fleet_grant: 'ordinary_remote',
      fleet_grant_version: 0,
      fleet_grant_set_by: null,
      fleet_grant_set_at: null,
    });
    const dcrTokens = await provider.exchangeClientCredentials(
      dcr.client_id,
      dcr.client_secret!,
      'read',
    );
    const dcrInfo = await provider.verifyAccessToken(dcrTokens.access_token) as unknown as AuthInfo;
    expect(dcrInfo.fleetGrant).toBe('ordinary_remote');
    expect(dcrInfo.fleetGrantVersion).toBe(0);
    expect(isFleetRouterContext(context(dcrInfo))).toBeFalse();
  });

  test('operator grant is atomically audited, read back, and visible to an already-issued token', async () => {
    const { clientId, token } = await mint('fleet-grant-live-token');
    const granted = await provider.rescopeClient(clientId, { fleetGrant: 'fleet_router' });
    expect(granted.fleetGrantOld).toBe('ordinary_remote');
    expect(granted.fleetGrant).toBe('fleet_router');
    expect(granted.fleetGrantVersion).toBe(1);
    expect(granted.fleetGrantSetBy).toBe('operator');
    expect(granted.fleetGrantSetAt).toMatch(/^\d{4}-\d\d-\d\dT/);
    expect(granted.fleetGrantEventId).toBeInteger();

    const info = await provider.verifyAccessToken(token) as unknown as AuthInfo;
    expect(info.fleetGrant).toBe('fleet_router');
    expect(info.fleetGrantVersion).toBe(1);
    expect(info.fleetGrantSetBy).toBe('operator');
    expect(info.fleetGrantSetAt).toMatch(/^\d{4}-\d\d-\d\dT/);
    expect(isFleetRouterContext(context(info))).toBeTrue();

    const audits = await sql`
      SELECT params FROM mcp_request_log
       WHERE operation = 'fleet_grant_change'
         AND params->>'client_id' = ${clientId}
    `;
    expect(audits).toHaveLength(1);
    expect(audits[0].params).toMatchObject({
      actor: 'operator',
      client_id: clientId,
      old: 'ordinary_remote',
      new: 'fleet_router',
      new_version: 1,
      via: 'rescope_cli',
      new_set_by: 'operator',
    });
    const [auditId] = await sql`
      SELECT id FROM mcp_request_log
       WHERE operation = 'fleet_grant_change' AND params->>'client_id' = ${clientId}
    `;
    expect(Number(auditId.id)).toBe(granted.fleetGrantEventId!);
  });

  test('clear revokes on the next verification without renaming or reissuing', async () => {
    const { clientId, token } = await mint('fleet-clear-live-token');
    await provider.rescopeClient(clientId, { fleetGrant: 'fleet_router' });
    const cleared = await provider.rescopeClient(clientId, { fleetGrant: null, fleetGrantActor: 'admin-api' });
    expect(cleared.fleetGrantOld).toBe('fleet_router');
    expect(cleared.fleetGrant).toBe('ordinary_remote');
    expect(cleared.fleetGrantVersion).toBe(1);
    expect(cleared.fleetGrantEventId).toBeInteger();
    expect(cleared.fleetGrantSetBy).toBe('operator');
    const info = await provider.verifyAccessToken(token) as unknown as AuthInfo;
    expect(info.fleetGrant).toBe('ordinary_remote');
    expect(isFleetRouterContext(context(info))).toBeFalse();

    const [lastAudit] = await sql`
      SELECT params FROM mcp_request_log
       WHERE operation = 'fleet_grant_change'
         AND params->>'client_id' = ${clientId}
       ORDER BY id DESC LIMIT 1
    `;
    expect(lastAudit.params).toMatchObject({
      actor: 'admin-api',
      old: 'fleet_router',
      new: 'ordinary_remote',
      via: 'admin_api',
    });
  });

  test('predicate honors the scope hierarchy and fails closed for missing proof or degraded projection', () => {
    const proof = {
      fleetGrant: 'fleet_router' as const,
      fleetGrantVersion: 1 as const,
      fleetGrantSetBy: 'operator' as const,
      fleetGrantSetAt: '2026-08-29T12:00:00.000Z',
    };
    expect(isFleetRouterContext(context({ ...proof, scopes: ['write'] }))).toBeTrue();
    expect(isFleetRouterContext(context({ ...proof, scopes: ['agent'] }))).toBeFalse();
    expect(isFleetRouterContext({ ...context(proof), remote: undefined } as unknown as OperationContext)).toBeFalse();
    expect(isFleetRouterContext(context({ ...proof, fleetGrantSetBy: undefined }))).toBeFalse();
    expect(isFleetRouterContext(context({ ...proof, fleetGrantSetAt: undefined }))).toBeFalse();
    expect(isFleetRouterContext(context({ ...proof, fleetGrantVersion: undefined }))).toBeFalse();
    expect(isFleetRouterContext(context({ ...proof, fleetGrantSetAt: 'not-a-date' }))).toBeFalse();
    expect(isFleetRouterContext(context({}))).toBeFalse();
  });

  test('name and surface cross-product never substitutes for the grant axis', () => {
    const names = ['brain-router-imekka-0123456789ab', 'ordinary-client', '', undefined];
    const surfaces = [undefined, 'verbs', 'starter', 'full'];
    const setters = [undefined, 'operator', 'self', 'dcr_default'];
    for (const clientName of names) {
      for (const surface of surfaces) {
        for (const surfaceSetBy of setters) {
          const ordinary = context({ clientName, surface, surfaceSetBy });
          expect(isFleetRouterContext(ordinary)).toBeFalse();
          expect(isFleetRouterContext(context({
            clientName,
            surface,
            surfaceSetBy,
            fleetGrant: 'fleet_router',
            fleetGrantVersion: 1,
            fleetGrantSetBy: 'operator',
            fleetGrantSetAt: '2026-08-29T12:00:00.000Z',
          }))).toBeTrue();
        }
      }
    }
  });

  test('audit insertion failure rolls back the grant and leaves no partial event', async () => {
    const { clientId } = await mint('fleet-audit-rollback');
    await db.exec(`
      CREATE FUNCTION reject_fleet_grant_audit() RETURNS trigger AS $$
      BEGIN
        IF NEW.operation = 'fleet_grant_change' THEN
          RAISE EXCEPTION 'injected fleet audit failure';
        END IF;
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql;
      CREATE TRIGGER reject_fleet_grant_audit_trigger
        BEFORE INSERT ON mcp_request_log
        FOR EACH ROW EXECUTE FUNCTION reject_fleet_grant_audit();
    `);
    try {
      await expect(provider.rescopeClient(clientId, { fleetGrant: 'fleet_router' }))
        .rejects.toThrow(/injected fleet audit failure/);
    } finally {
      await db.exec(`
        DROP TRIGGER reject_fleet_grant_audit_trigger ON mcp_request_log;
        DROP FUNCTION reject_fleet_grant_audit();
      `);
    }
    const [row] = await sql`
      SELECT fleet_grant, fleet_grant_version, fleet_grant_set_by, fleet_grant_set_at
        FROM oauth_clients WHERE client_id = ${clientId}
    `;
    expect(row).toEqual({
      fleet_grant: 'ordinary_remote', fleet_grant_version: 0,
      fleet_grant_set_by: null, fleet_grant_set_at: null,
    });
    const events = await sql`
      SELECT id FROM mcp_request_log
       WHERE operation = 'fleet_grant_change' AND params->>'client_id' = ${clientId}
    `;
    expect(events).toHaveLength(0);
  });

  test('ordinary-first registration failure cannot leave a granted row without an event', async () => {
    await db.exec(`
      CREATE FUNCTION reject_fleet_registration_audit() RETURNS trigger AS $$
      BEGIN
        IF NEW.operation = 'fleet_grant_change' THEN
          RAISE EXCEPTION 'injected fleet registration audit failure';
        END IF;
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql;
      CREATE TRIGGER reject_fleet_registration_audit_trigger
        BEFORE INSERT ON mcp_request_log
        FOR EACH ROW EXECUTE FUNCTION reject_fleet_registration_audit();
    `);
    try {
      await expect(registerScopedClient(
        sql,
        'manual-fleet-failure',
        parseRegisterClientArgs(['--fleet-router']),
      )).rejects.toThrow(/injected fleet registration audit failure/);
    } finally {
      await db.exec(`
        DROP TRIGGER reject_fleet_registration_audit_trigger ON mcp_request_log;
        DROP FUNCTION reject_fleet_registration_audit();
      `);
    }
    const [row] = await sql`
      SELECT client_id, fleet_grant, fleet_grant_version, fleet_grant_set_by, fleet_grant_set_at
        FROM oauth_clients WHERE client_name = 'manual-fleet-failure'
    `;
    expect(row).toMatchObject({
      fleet_grant: 'ordinary_remote', fleet_grant_version: 0,
      fleet_grant_set_by: null, fleet_grant_set_at: null,
    });
    const events = await sql`
      SELECT id FROM mcp_request_log
       WHERE operation = 'fleet_grant_change' AND params->>'client_id' = ${row.client_id}
    `;
    expect(events).toHaveLength(0);
  });

  test('grant update failure writes no audit event', async () => {
    const { clientId } = await mint('fleet-update-rollback');
    await db.exec(`
      CREATE FUNCTION reject_fleet_grant_update() RETURNS trigger AS $$
      BEGIN
        IF NEW.client_name = 'fleet-update-rollback' THEN
          RAISE EXCEPTION 'injected fleet update failure';
        END IF;
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql;
      CREATE TRIGGER reject_fleet_grant_update_trigger
        BEFORE UPDATE ON oauth_clients
        FOR EACH ROW EXECUTE FUNCTION reject_fleet_grant_update();
    `);
    try {
      await expect(provider.rescopeClient(clientId, { fleetGrant: 'fleet_router' }))
        .rejects.toThrow(/injected fleet update failure/);
    } finally {
      await db.exec(`
        DROP TRIGGER reject_fleet_grant_update_trigger ON oauth_clients;
        DROP FUNCTION reject_fleet_grant_update();
      `);
    }
    const events = await sql`
      SELECT id FROM mcp_request_log
       WHERE operation = 'fleet_grant_change' AND params->>'client_id' = ${clientId}
    `;
    expect(events).toHaveLength(0);
  });

  test('pre-v143 projection keeps authentication/surface behavior but omits fleet authorization', async () => {
    const { token } = await mint('fleet-degraded-projection');
    await db.exec(`
      ALTER TABLE oauth_clients DROP CONSTRAINT IF EXISTS oauth_clients_fleet_grant_active_chk;
      ALTER TABLE oauth_clients DROP CONSTRAINT IF EXISTS oauth_clients_fleet_grant_proof_chk;
      ALTER TABLE oauth_clients DROP CONSTRAINT IF EXISTS oauth_clients_fleet_grant_version_chk;
      ALTER TABLE oauth_clients DROP CONSTRAINT IF EXISTS oauth_clients_fleet_grant_state_chk;
      ALTER TABLE oauth_clients DROP COLUMN IF EXISTS fleet_grant_set_at;
      ALTER TABLE oauth_clients DROP COLUMN IF EXISTS fleet_grant_set_by;
      ALTER TABLE oauth_clients DROP COLUMN IF EXISTS fleet_grant_version;
      ALTER TABLE oauth_clients DROP COLUMN IF EXISTS fleet_grant;
    `);
    const info = await provider.verifyAccessToken(token) as unknown as AuthInfo;
    expect(info.clientId).toBeString();
    expect(info.fleetGrant).toBeUndefined();
    expect(info.fleetGrantVersion).toBeUndefined();
    expect(info.fleetGrantSetBy).toBeUndefined();
    expect(info.fleetGrantSetAt).toBeUndefined();
    expect(isFleetRouterContext(context(info))).toBeFalse();
  });
});
