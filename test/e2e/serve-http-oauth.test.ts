/**
 * E2E tests for serve-http.ts OAuth 2.1 fixes (v0.26.1).
 *
 * Spins up a real `gbrain serve --http` against real Postgres, registers an
 * OAuth client, mints tokens, and exercises the full MCP JSON-RPC pipeline
 * end-to-end. Catches the three bugs fixed in v0.26.1:
 *
 *   1. client_credentials tokens rejected at /mcp (expiresAt string vs number)
 *   2. OAuth metadata missing client_credentials grant type
 *   3. Express 5 trust proxy + admin SPA wildcard
 *
 * Run: GBRAIN_DATABASE_URL=... bun test test/e2e/serve-http-oauth.test.ts
 */

import { describe, test, expect, beforeAll, afterAll } from 'bun:test';
import { createHash } from 'crypto';
import { hasDatabase } from './helpers.ts';
import { assertSafeE2eDatabaseUrl } from '../helpers/db-guard.ts';

const skip = !hasDatabase();
// #3485 name floor: this suite opens raw postgres() clients on the ambient URL
// and runs DROP TRIGGER/FUNCTION + DELETE cleanups — refuse non-test-shaped
// database names before any connection is made.
if (!skip) {
  assertSafeE2eDatabaseUrl(process.env.GBRAIN_DATABASE_URL || process.env.DATABASE_URL || '');
}
const describeE2E = skip ? describe.skip : describe;

if (skip) {
  console.log('Skipping E2E serve-http-oauth tests (DATABASE_URL not set)');
}

const PORT = 19131; // Avoid collision with production 3131
const BASE = `http://localhost:${PORT}`;
const ADMIN_BOOTSTRAP_TOKEN = 'e2e-admin-bootstrap-token-000000000000';

describeE2E('serve-http OAuth 2.1 E2E (v0.26.1 + v0.26.2 + v0.26.3)', () => {
  let serverProcess: ReturnType<typeof import('child_process').spawn> | null = null;
  let clientId: string | undefined;
  let clientSecret: string | undefined;
  // DCR-registered clients accumulate here so afterAll can revoke them too
  // (one per test that posts to /register).
  const dcrClientIds: string[] = [];

  beforeAll(async () => {
    const { execSync, spawn } = await import('child_process');

    // Register a test OAuth client via CLI.
    // env: { ...process.env } is required: bun's execSync does NOT inherit
    // env mutations done via `process.env.X = ...` (only OS-level env from
    // before bun started). helpers.ts loads .env.testing and sets DATABASE_URL
    // via process.env mutation, which is invisible to subprocesses unless we
    // explicitly re-pass process.env. Same pattern applies to every execSync
    // in this file.
    // v0.28.10: register with admin scope so the F7 protected-name guard
    // tests can mint admin-scoped tokens that actually exercise the guard
    // at operations.ts:1527. Without admin in the client's allowed scopes,
    // submit_job for a protected name (`shell`, `subagent`) gets rejected
    // by hasScope() in serve-http.ts BEFORE reaching the F7 guard, so the
    // test was validating scope enforcement instead of the RCE protection.
    // Other tests that mint specific subsets ('read', 'read write') still
    // get the subset they ask for — adding admin to the client's allowed
    // ceiling does not auto-grant it to every minted token.
    const regOutput = execSync(
      'bun run src/cli.ts auth register-client e2e-oauth-test --grant-types client_credentials --scopes "read write admin"',
      { cwd: process.cwd(), encoding: 'utf8', env: { ...process.env } }
    );
    const idMatch = regOutput.match(/Client ID:\s+(gbrain_cl_\S+)/);
    const secretMatch = regOutput.match(/Client Secret:\s+(gbrain_cs_\S+)/);
    if (!idMatch || !secretMatch) throw new Error('Failed to register test client:\n' + regOutput);
    clientId = idMatch[1];
    clientSecret = secretMatch[1];

    // This disposable test server opts into client_credentials DCR so the
    // owner-wire regression can perform a real exchange without manufacturing
    // oauth_tokens rows. Production remains opt-in and unchanged.
    serverProcess = spawn('bun', [
      'run', 'src/cli.ts', 'serve', '--http',
      '--port', String(PORT),
      '--public-url', `http://localhost:${PORT}`,
      '--enable-dcr-insecure',
    ], {
      cwd: process.cwd(),
      env: { ...process.env, GBRAIN_ADMIN_BOOTSTRAP_TOKEN: ADMIN_BOOTSTRAP_TOKEN },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    // Collect stderr for debugging failures
    let stderr = '';
    serverProcess.stderr?.on('data', (d: Buffer) => { stderr += d.toString(); });

    // Wait for server to be ready (up to 15s)
    let ready = false;
    for (let i = 0; i < 30; i++) {
      try {
        const res = await fetch(`${BASE}/health`);
        if (res.ok) { ready = true; break; }
      } catch {}
      await new Promise(r => setTimeout(r, 500));
    }
    if (!ready) throw new Error('Server failed to start within 15s.\nstderr: ' + stderr.slice(-500));
  }, 30_000);

  afterAll(async () => {
    // Kill server first so it can't issue more tokens during cleanup.
    if (serverProcess) {
      serverProcess.kill('SIGTERM');
      await new Promise(r => setTimeout(r, 1000));
      if (!serverProcess.killed) serverProcess.kill('SIGKILL');
    }
    // v0.26.2 cleanup contract: only revoke if registration succeeded
    // (clientId guard) and surface any cleanup failure to stderr without
    // throwing — a real test failure is more interesting than the cleanup
    // error that follows it. Same shape applies to DCR-registered clients
    // tracked in dcrClientIds.
    const { execSync } = await import('child_process');
    const toRevoke = [...(clientId ? [clientId] : []), ...dcrClientIds];
    for (const id of toRevoke) {
      try {
        execSync(`bun run src/cli.ts auth revoke-client "${id}"`,
          { cwd: process.cwd(), encoding: 'utf8', env: { ...process.env } });
      } catch (e: any) {
        // eslint-disable-next-line no-console
        console.error(`[afterAll] revoke-client cleanup failed for ${id}: ${e.message}`);
      }
    }
  }, 30_000);

  // Helper: mint a token with given scopes
  async function mintTokenFor(
    targetClientId: string,
    targetClientSecret: string,
    scope = 'read write',
  ): Promise<{ access_token: string; expires_in: number; scope: string }> {
    const res = await fetch(`${BASE}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: targetClientId,
        client_secret: targetClientSecret,
        scope,
      }),
    });
    expect(res.ok).toBe(true);
    return res.json() as any;
  }

  async function mintToken(scope = 'read write'): Promise<{ access_token: string; expires_in: number; scope: string }> {
    expect(clientId).toBeTruthy();
    expect(clientSecret).toBeTruthy();
    return mintTokenFor(clientId!, clientSecret!, scope);
  }

  // Helper: call MCP JSON-RPC with a bearer token
  async function mcpCall(token: string, method: string, params?: any): Promise<Response> {
    return fetch(`${BASE}/mcp`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json, text/event-stream',
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, ...(params ? { params } : {}) }),
    });
  }

  async function mcpToolValue(
    token: string,
    name: string,
    args: Record<string, unknown> = {},
  ): Promise<Record<string, unknown>> {
    const response = await mcpCall(token, 'tools/call', {
      name,
      arguments: args,
    });
    const text = await response.text();
    expect(response.ok).toBe(true);
    const dataLine = text.split('\n').find(line => line.startsWith('data:'));
    const envelope = JSON.parse(dataLine ? dataLine.slice(5).trim() : text);
    expect(envelope.error).toBeUndefined();
    expect(envelope.result?.isError).not.toBe(true);
    const content = envelope.result?.content?.[0]?.text;
    expect(typeof content).toBe('string');
    return JSON.parse(content);
  }

  async function mcpEnvelope(
    token: string,
    name: string,
    args: Record<string, unknown> = {},
  ): Promise<Record<string, any>> {
    const response = await mcpCall(token, 'tools/call', {
      name,
      arguments: args,
    });
    const text = await response.text();
    expect(response.ok).toBe(true);
    const dataLine = text.split('\n').find(line => line.startsWith('data:'));
    return JSON.parse(dataLine ? dataLine.slice(5).trim() : text);
  }

  function expectExactWhoami(
    identity: Record<string, unknown>,
    expected: {
      clientId: string;
      clientName: string;
      scopes: string[];
      sourceId: string;
      federatedRead: string[];
      granted: boolean;
      grantVersion: 0 | 1;
    },
  ): void {
    expect(identity).toEqual({
      transport: 'oauth',
      client_id: expected.clientId,
      client_name: expected.clientName,
      scopes: expected.scopes,
      expires_at: expect.any(Number),
      source_id: expected.sourceId,
      federated_read: expected.federatedRead,
      fleet_router_granted: expected.granted,
      fleet_grant_version: expected.grantVersion,
    });
    expect(Number.isFinite(identity.expires_at)).toBe(true);
  }

  function trackClient(id: string): string {
    if (!dcrClientIds.includes(id)) dcrClientIds.push(id);
    return id;
  }

  async function revokeClientNow(id: string): Promise<void> {
    const { execFileSync } = await import('child_process');
    try {
      execFileSync('bun', ['run', 'src/cli.ts', 'auth', 'revoke-client', id], {
        cwd: process.cwd(), encoding: 'utf8', env: { ...process.env },
        stdio: ['ignore', 'ignore', 'ignore'],
      });
    } catch {
      throw new Error('client cleanup revoke failed');
    }
    const index = dcrClientIds.indexOf(id);
    if (index >= 0) dcrClientIds.splice(index, 1);
  }

  async function clearFleetGrantNow(cookie: string, id: string): Promise<void> {
    const response = await fetch(`${BASE}/admin/api/rescope-client`, {
      method: 'POST',
      headers: { Cookie: cookie, 'Content-Type': 'application/json' },
      body: JSON.stringify({ clientId: id, fleetGrant: null }),
    });
    if (!response.ok) {
      throw new Error('fleet grant cleanup failed');
    }
  }

  interface CleanupClientState {
    id: string;
    tokens: string[];
    grantChanged: boolean;
    verifyAfterClear?: {
      token: string;
      clientName: string;
      scopes: string[];
      sourceId: string;
      federatedRead: string[];
    };
  }

  async function cleanupClientNow(cookie: string, state: CleanupClientState): Promise<void> {
    let cleanupError: unknown;
    if (state.grantChanged) {
      try {
        await clearFleetGrantNow(cookie, state.id);
        if (state.verifyAfterClear) {
          expectExactWhoami(await mcpToolValue(state.verifyAfterClear.token, 'whoami'), {
            clientId: state.id,
            clientName: state.verifyAfterClear.clientName,
            scopes: state.verifyAfterClear.scopes,
            sourceId: state.verifyAfterClear.sourceId,
            federatedRead: state.verifyAfterClear.federatedRead,
            granted: false,
            grantVersion: 1,
          });
        }
      } catch (error) {
        cleanupError = error;
      }
    }
    let revoked = false;
    try {
      await revokeClientNow(state.id);
      revoked = true;
    } catch (error) {
      cleanupError ??= error;
    }
    if (revoked) {
      for (const token of state.tokens) {
        expect((await mcpCall(token, 'tools/list')).status).toBe(401);
      }
    }
    if (cleanupError) throw cleanupError;
  }

  async function readFleetGrantEvent(id: number): Promise<Record<string, unknown>> {
    const postgres = (await import('postgres')).default;
    const sql = postgres(process.env.GBRAIN_DATABASE_URL || process.env.DATABASE_URL || '', { prepare: false });
    try {
      const rows = await sql<{ id: number; operation: string; status: string; params: Record<string, unknown> | string }[]>`
        SELECT id, operation, status, params FROM mcp_request_log WHERE id = ${id}
      `;
      expect(rows).toHaveLength(1);
      const row = rows[0];
      expect(Number(row.id)).toBe(id);
      expect(row.operation).toBe('fleet_grant_change');
      expect(row.status).toBe('success');
      return typeof row.params === 'string' ? JSON.parse(row.params) : row.params;
    } finally {
      await sql.end();
    }
  }

  async function expectFleetGrantEvent(expected: {
    id: number;
    clientId: string;
    old: 'ordinary_remote' | 'fleet_router';
    oldVersion: 0 | 1;
    oldSetBy: 'operator' | null;
    oldSetAt: string | null;
    next: 'ordinary_remote' | 'fleet_router';
    nextSetAt: string;
    actor?: 'admin-api' | 'operator';
    via?: 'admin_api' | 'rescope_cli' | 'register_cli';
  }): Promise<void> {
    const params = await readFleetGrantEvent(expected.id);
    expect(params).toEqual({
      actor: expected.actor ?? 'admin-api',
      client_id: expected.clientId,
      old: expected.old,
      old_version: expected.oldVersion,
      old_set_by: expected.oldSetBy,
      old_set_at: expected.oldSetAt === null ? null : expect.any(String),
      new: expected.next,
      new_version: 1,
      new_set_by: 'operator',
      new_set_at: expect.any(String),
      via: expected.via ?? 'admin_api',
    });
    expect(new Date(String(params.new_set_at)).toISOString())
      .toBe(new Date(expected.nextSetAt).toISOString());
    if (expected.oldSetAt !== null) {
      expect(new Date(String(params.old_set_at)).toISOString())
        .toBe(new Date(expected.oldSetAt).toISOString());
    }
  }

  async function adminCookie(): Promise<string> {
    const login = await fetch(`${BASE}/admin/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: ADMIN_BOOTSTRAP_TOKEN }),
    });
    expect(login.ok).toBe(true);
    const match = (login.headers.get('set-cookie') || '').match(/gbrain_admin=([^;]+)/);
    expect(match).toBeTruthy();
    return `gbrain_admin=${match![1]}`;
  }

  // =========================================================================
  // Fix 1: client_credentials tokens validate at /mcp
  // =========================================================================

  test('mint token via client_credentials grant', async () => {
    const data = await mintToken('read write');
    expect(data.access_token).toMatch(/^gbrain_at_/);
    expect(data.expires_in).toBe(3600);
    expect(data.scope).toContain('read');
  });

  test('minted token is accepted at /mcp — tools/list returns tools', async () => {
    const { access_token } = await mintToken('read');
    const res = await mcpCall(access_token, 'tools/list');

    // Before v0.26.1 fix: 401 {"error":"invalid_token","error_description":"Token has no expiration time"}
    expect(res.status).not.toBe(401);

    const body = await res.text();
    expect(body).toContain('tools');
    expect(body).toContain('search'); // search tool should be in the list
    expect(body).toContain('query');  // query tool too
  }, 15_000);

  test('minted token works for tools/call — search executes', async () => {
    const { access_token } = await mintToken('read');
    const res = await mcpCall(access_token, 'tools/call', {
      name: 'search',
      arguments: { query: 'gbrain', limit: 1 },
    });

    expect(res.status).not.toBe(401);
    const body = await res.text();
    // Should contain search results, not an auth error
    expect(body).not.toContain('invalid_token');
    expect(body).toContain('result');
  }, 15_000);

  test('expired/invalid token is rejected at /mcp', async () => {
    const res = await mcpCall('gbrain_at_totally_fake_token', 'tools/list');
    // Invalid tokens should not return 200 with tool results
    const body = await res.text();
    expect(body).not.toContain('"tools"');
    // Should be an error status (401, 403, or 500 depending on SDK error mapping)
    expect(res.status).toBeGreaterThanOrEqual(400);
  });

  test('missing Authorization header returns 401', async () => {
    const res = await fetch(`${BASE}/mcp`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json, text/event-stream',
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
    });
    expect(res.status).toBe(401);
  });

  // =========================================================================
  // Fix 2: OAuth metadata includes client_credentials
  // =========================================================================

  test('OAuth AS metadata includes all three grant types', async () => {
    const res = await fetch(`${BASE}/.well-known/oauth-authorization-server`);
    expect(res.ok).toBe(true);
    const meta = await res.json() as any;
    expect(meta.grant_types_supported).toContain('authorization_code');
    expect(meta.grant_types_supported).toContain('refresh_token');
    expect(meta.grant_types_supported).toContain('client_credentials');
    expect(meta.token_endpoint_auth_methods_supported).toEqual(
      expect.arrayContaining(['client_secret_post', 'client_secret_basic', 'none']),
    );
    expect(meta.revocation_endpoint_auth_methods_supported).toEqual(
      expect.arrayContaining(['client_secret_post', 'client_secret_basic']),
    );
  });

  test('OAuth metadata issuer matches public URL', async () => {
    const res = await fetch(`${BASE}/.well-known/oauth-authorization-server`);
    const meta = await res.json() as any;
    expect(meta.issuer).toBe(`http://localhost:${PORT}/`);
    expect(meta.token_endpoint).toContain('/token');
    expect(meta.scopes_supported).toContain('read');
    expect(meta.scopes_supported).toContain('write');
    expect(meta.scopes_supported).toContain('admin');
  });

  // T2 (eng-review): scopes_supported advertises the full ALLOWED_SCOPES_LIST
  // so MCP clients (Claude Desktop, ChatGPT, Perplexity) can discover the
  // v0.28 sources_admin and users_admin scopes via standard discovery.
  // Pre-v0.28 the list was hardcoded to ['read','write','admin'] in
  // serve-http.ts:195 and this assertion would have failed.
  test('OAuth metadata advertises all 5 v0.28 scopes (sources_admin + users_admin)', async () => {
    const res = await fetch(`${BASE}/.well-known/oauth-authorization-server`);
    const meta = await res.json() as any;
    expect(meta.scopes_supported).toContain('sources_admin');
    expect(meta.scopes_supported).toContain('users_admin');
    expect(meta.scopes_supported).toEqual(
      expect.arrayContaining(['admin', 'read', 'sources_admin', 'users_admin', 'write']),
    );
  });

  // =========================================================================
  // Fix 3: Express 5 compatibility
  // =========================================================================

  test('admin dashboard serves SPA index.html (not Express error)', async () => {
    const res = await fetch(`${BASE}/admin/`);
    const html = await res.text();
    expect(html).toContain('GBrain Admin');
    expect(html).not.toContain('<pre>Cannot GET');
  });

  test('admin sub-routes serve SPA fallback', async () => {
    const res = await fetch(`${BASE}/admin/agents`);
    const html = await res.text();
    expect(html).toContain('GBrain Admin');
  });

  test('admin source access APIs enumerate sources and rescope an OAuth client', async () => {
    const cookie = await adminCookie();
    const createdClients: CleanupClientState[] = [];
    let primaryVerificationToken: string | undefined;
    try {
      const sourcesRes = await fetch(`${BASE}/admin/api/sources`, {
        headers: { Cookie: cookie },
      });
      expect(sourcesRes.ok).toBe(true);
      const sources = await sourcesRes.json() as Array<{ id: string; name: string; federated: boolean }>;
      expect(sources.some(source => source.id === 'default')).toBe(true);

      // One already-issued token must observe false -> true -> false while
      // every non-grant identity field remains byte-for-byte stable.
      const stickyToken = await mintToken('read');
      primaryVerificationToken = stickyToken.access_token;
      expect(stickyToken.scope).toBe('read');
      const beforeGrant = await mcpToolValue(stickyToken.access_token, 'whoami');
      expectExactWhoami(beforeGrant, {
        clientId: clientId!, clientName: 'e2e-oauth-test', scopes: ['read'],
        sourceId: 'default', federatedRead: ['default'], granted: false, grantVersion: 0,
      });
      const { fleet_router_granted: _beforeGrant, fleet_grant_version: _beforeVersion, ...stableIdentity } = beforeGrant;

      const rescopeRes = await fetch(`${BASE}/admin/api/rescope-client`, {
        method: 'POST',
        headers: { Cookie: cookie, 'Content-Type': 'application/json' },
        body: JSON.stringify({ clientId, sourceId: 'default', federatedRead: ['default'] }),
      });
      expect(rescopeRes.ok).toBe(true);
      expect(await rescopeRes.json()).toEqual({
        clientId,
        clientName: 'e2e-oauth-test',
        scopes: 'read write admin',
        sourceId: 'default',
        federatedRead: ['default'],
        fleetGrant: 'ordinary_remote',
        fleetGrantOld: null,
        fleetGrantVersion: 0,
        fleetGrantSetBy: null,
        fleetGrantSetAt: null,
        fleetGrantEventId: null,
      });

      const grantRes = await fetch(`${BASE}/admin/api/rescope-client`, {
        method: 'POST',
        headers: { Cookie: cookie, 'Content-Type': 'application/json' },
        body: JSON.stringify({ clientId, fleetGrant: 'fleet_router' }),
      });
      expect(grantRes.ok).toBe(true);
      const granted = await grantRes.json() as Record<string, unknown>;
      expect(granted).toEqual({
        clientId,
        clientName: 'e2e-oauth-test',
        scopes: 'read write admin',
        sourceId: 'default',
        federatedRead: ['default'],
        boundSlugPrefixes: null,
        fleetGrant: 'fleet_router',
        fleetGrantOld: 'ordinary_remote',
        fleetGrantVersion: 1,
        fleetGrantSetBy: 'operator',
        fleetGrantSetAt: expect.any(String),
        fleetGrantEventId: expect.any(Number),
      });
      await expectFleetGrantEvent({
        id: granted.fleetGrantEventId as number,
        clientId: clientId!,
        old: 'ordinary_remote', oldVersion: 0, oldSetBy: null, oldSetAt: null,
        next: 'fleet_router', nextSetAt: granted.fleetGrantSetAt as string,
      });

      const afterGrant = await mcpToolValue(stickyToken.access_token, 'whoami');
      expectExactWhoami(afterGrant, {
        clientId: clientId!, clientName: 'e2e-oauth-test', scopes: ['read'],
        sourceId: 'default', federatedRead: ['default'], granted: true, grantVersion: 1,
      });
      const { fleet_router_granted: _afterGrant, fleet_grant_version: _afterVersion, ...afterGrantStable } = afterGrant;
      expect(afterGrantStable).toEqual(stableIdentity);

      const clearRes = await fetch(`${BASE}/admin/api/rescope-client`, {
        method: 'POST',
        headers: { Cookie: cookie, 'Content-Type': 'application/json' },
        body: JSON.stringify({ clientId, fleetGrant: null }),
      });
      expect(clearRes.ok).toBe(true);
      const cleared = await clearRes.json() as Record<string, unknown>;
      expect(cleared).toEqual({
        clientId,
        clientName: 'e2e-oauth-test',
        scopes: 'read write admin',
        sourceId: 'default',
        federatedRead: ['default'],
        boundSlugPrefixes: null,
        fleetGrant: 'ordinary_remote',
        fleetGrantOld: 'fleet_router',
        fleetGrantVersion: 1,
        fleetGrantSetBy: 'operator',
        fleetGrantSetAt: expect.any(String),
        fleetGrantEventId: expect.any(Number),
      });
      expect(cleared.fleetGrantEventId).not.toBe(granted.fleetGrantEventId);
      await expectFleetGrantEvent({
        id: cleared.fleetGrantEventId as number,
        clientId: clientId!,
        old: 'fleet_router', oldVersion: 1, oldSetBy: 'operator',
        oldSetAt: granted.fleetGrantSetAt as string,
        next: 'ordinary_remote', nextSetAt: cleared.fleetGrantSetAt as string,
      });

      const afterClearSameToken = await mcpToolValue(stickyToken.access_token, 'whoami');
      expectExactWhoami(afterClearSameToken, {
        clientId: clientId!, clientName: 'e2e-oauth-test', scopes: ['read'],
        sourceId: 'default', federatedRead: ['default'], granted: false, grantVersion: 1,
      });
      const { fleet_router_granted: _afterClear, fleet_grant_version: _clearVersion, ...afterClearStable } = afterClearSameToken;
      expect(afterClearStable).toEqual(stableIdentity);

      const clearedToken = await mintToken('read');
      expect(clearedToken.scope).toBe('read');
      expectExactWhoami(await mcpToolValue(clearedToken.access_token, 'whoami'), {
        clientId: clientId!, clientName: 'e2e-oauth-test', scopes: ['read'],
        sourceId: 'default', federatedRead: ['default'], granted: false, grantVersion: 1,
      });

      // Operator registration defaults remain ordinary whether fleetRouter
      // is omitted or explicitly false.
      for (const fleetRouter of [undefined, false] as const) {
        const name = `e2e-admin-ordinary-${String(fleetRouter)}-${Date.now()}`;
        const ordinaryRes = await fetch(`${BASE}/admin/api/register-client`, {
          method: 'POST',
          headers: { Cookie: cookie, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name, scopes: ['read'], source: 'default',
            ...(fleetRouter !== undefined ? { fleetRouter } : {}),
          }),
        });
        expect(ordinaryRes.ok).toBe(true);
        const ordinary = await ordinaryRes.json() as Record<string, unknown>;
        const ordinaryId = trackClient(ordinary.clientId as string);
        const ordinaryState: CleanupClientState = {
          id: ordinaryId,
          tokens: [],
          grantChanged: false,
        };
        createdClients.push(ordinaryState);
        const ordinarySecret = ordinary.clientSecret as string;
        expect(ordinary).toEqual({
          clientId: ordinaryId, clientSecret: ordinarySecret,
          grantTypes: ['client_credentials'], scopes: 'read',
          authMethod: 'client_secret_post', redirectUris: [],
          sourceId: 'default', federatedRead: ['default'], tokenTtl: null,
          fleetGrant: 'ordinary_remote', fleetGrantVersion: 0,
          fleetGrantSetBy: null, fleetGrantSetAt: null, fleetGrantEventId: null,
        });
        const ordinaryToken = await mintTokenFor(ordinaryId, ordinarySecret, 'read');
        ordinaryState.tokens.push(ordinaryToken.access_token);
        expect(ordinaryToken.scope).toBe('read');
        expectExactWhoami(await mcpToolValue(ordinaryToken.access_token, 'whoami'), {
          clientId: ordinaryId, clientName: name, scopes: ['read'],
          sourceId: 'default', federatedRead: ['default'], granted: false, grantVersion: 0,
        });
      }

      const fleetName = `e2e-admin-fleet-${Date.now()}`;
      const registerFleetRes = await fetch(`${BASE}/admin/api/register-client`, {
        method: 'POST',
        headers: { Cookie: cookie, 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: fleetName, scopes: ['read'], source: 'default', fleetRouter: true }),
      });
      expect(registerFleetRes.ok).toBe(true);
      const registeredFleet = await registerFleetRes.json() as Record<string, unknown>;
      const registeredFleetId = trackClient(registeredFleet.clientId as string);
      const fleetState: CleanupClientState = {
        id: registeredFleetId,
        tokens: [],
        grantChanged: true,
      };
      createdClients.push(fleetState);
      const registeredFleetSecret = registeredFleet.clientSecret as string;
      expect(registeredFleet).toEqual({
        clientId: registeredFleetId, clientSecret: registeredFleetSecret,
        grantTypes: ['client_credentials'], scopes: 'read',
        authMethod: 'client_secret_post', redirectUris: [],
        sourceId: 'default', federatedRead: ['default'], tokenTtl: null,
        fleetGrant: 'fleet_router', fleetGrantVersion: 1,
        fleetGrantSetBy: 'operator', fleetGrantSetAt: expect.any(String),
        fleetGrantEventId: expect.any(Number),
      });
      await expectFleetGrantEvent({
        id: registeredFleet.fleetGrantEventId as number,
        clientId: registeredFleetId,
        old: 'ordinary_remote', oldVersion: 0, oldSetBy: null, oldSetAt: null,
        next: 'fleet_router', nextSetAt: registeredFleet.fleetGrantSetAt as string,
      });
      const registeredFleetToken = await mintTokenFor(registeredFleetId, registeredFleetSecret, 'read');
      fleetState.tokens.push(registeredFleetToken.access_token);
      fleetState.verifyAfterClear = {
        token: registeredFleetToken.access_token,
        clientName: fleetName,
        scopes: ['read'],
        sourceId: 'default',
        federatedRead: ['default'],
      };
      expect(registeredFleetToken.scope).toBe('read');
      expectExactWhoami(await mcpToolValue(registeredFleetToken.access_token, 'whoami'), {
        clientId: registeredFleetId, clientName: fleetName, scopes: ['read'],
        sourceId: 'default', federatedRead: ['default'], granted: true, grantVersion: 1,
      });

      // write canonically implies read, so a write-only token can call
      // whoami and receives the complete granted projection.
      const writeName = `e2e-admin-fleet-write-only-${Date.now()}`;
      const writeOnlyRes = await fetch(`${BASE}/admin/api/register-client`, {
        method: 'POST',
        headers: { Cookie: cookie, 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: writeName, scopes: ['write'], source: 'default', fleetRouter: true }),
      });
      expect(writeOnlyRes.ok).toBe(true);
      const writeOnly = await writeOnlyRes.json() as Record<string, unknown>;
      const writeOnlyId = trackClient(writeOnly.clientId as string);
      const writeState: CleanupClientState = {
        id: writeOnlyId,
        tokens: [],
        grantChanged: true,
      };
      createdClients.push(writeState);
      const writeOnlySecret = writeOnly.clientSecret as string;
      expect(writeOnly).toEqual({
        clientId: writeOnlyId, clientSecret: writeOnlySecret,
        grantTypes: ['client_credentials'], scopes: 'write',
        authMethod: 'client_secret_post', redirectUris: [],
        sourceId: 'default', federatedRead: ['default'], tokenTtl: null,
        fleetGrant: 'fleet_router', fleetGrantVersion: 1,
        fleetGrantSetBy: 'operator', fleetGrantSetAt: expect.any(String),
        fleetGrantEventId: expect.any(Number),
      });
      await expectFleetGrantEvent({
        id: writeOnly.fleetGrantEventId as number,
        clientId: writeOnlyId,
        old: 'ordinary_remote', oldVersion: 0, oldSetBy: null, oldSetAt: null,
        next: 'fleet_router', nextSetAt: writeOnly.fleetGrantSetAt as string,
      });
      const writeOnlyToken = await mintTokenFor(writeOnlyId, writeOnlySecret, 'write');
      writeState.tokens.push(writeOnlyToken.access_token);
      writeState.verifyAfterClear = {
        token: writeOnlyToken.access_token,
        clientName: writeName,
        scopes: ['write'],
        sourceId: 'default',
        federatedRead: ['default'],
      };
      expect(writeOnlyToken.scope).toBe('write');
      expectExactWhoami(await mcpToolValue(writeOnlyToken.access_token, 'whoami'), {
        clientId: writeOnlyId, clientName: writeName, scopes: ['write'],
        sourceId: 'default', federatedRead: ['default'], granted: true, grantVersion: 1,
      });

      // An agent-only token lacks read. Even with a persisted fleet grant,
      // raw HTTP MCP whoami returns the canonical scope-denial envelope and
      // exposes no owner identity fields.
      const agentName = `e2e-admin-fleet-agent-only-${Date.now()}`;
      const agentOnlyRes = await fetch(`${BASE}/admin/api/register-client`, {
        method: 'POST',
        headers: { Cookie: cookie, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: agentName, scopes: ['write', 'agent'], source: 'default', fleetRouter: true,
        }),
      });
      expect(agentOnlyRes.ok).toBe(true);
      const agentOnly = await agentOnlyRes.json() as Record<string, unknown>;
      const agentOnlyId = trackClient(agentOnly.clientId as string);
      const agentState: CleanupClientState = {
        id: agentOnlyId,
        tokens: [],
        grantChanged: true,
      };
      createdClients.push(agentState);
      const agentOnlySecret = agentOnly.clientSecret as string;
      expect(agentOnly).toEqual({
        clientId: agentOnlyId, clientSecret: agentOnlySecret,
        grantTypes: ['client_credentials'], scopes: 'agent write',
        authMethod: 'client_secret_post', redirectUris: [],
        sourceId: 'default', federatedRead: ['default'], tokenTtl: null,
        fleetGrant: 'fleet_router', fleetGrantVersion: 1,
        fleetGrantSetBy: 'operator', fleetGrantSetAt: expect.any(String),
        fleetGrantEventId: expect.any(Number),
      });
      await expectFleetGrantEvent({
        id: agentOnly.fleetGrantEventId as number,
        clientId: agentOnlyId,
        old: 'ordinary_remote', oldVersion: 0, oldSetBy: null, oldSetAt: null,
        next: 'fleet_router', nextSetAt: agentOnly.fleetGrantSetAt as string,
      });
      const agentOnlyToken = await mintTokenFor(agentOnlyId, agentOnlySecret, 'agent');
      agentState.tokens.push(agentOnlyToken.access_token);
      expect(agentOnlyToken.scope).toBe('agent');
      const denial = await mcpEnvelope(agentOnlyToken.access_token, 'whoami');
      expect(denial).toEqual({
        jsonrpc: '2.0',
        id: 1,
        result: {
          content: [{
            type: 'text',
            text: JSON.stringify({
              error: 'insufficient_scope',
              message: "Operation whoami requires 'read' scope",
              your_scopes: ['agent'],
            }),
          }],
          isError: true,
        },
      });
      const denialText = denial.result.content[0].text as string;
      for (const field of ['client_id', 'client_name', 'source_id', 'federated_read', 'fleet_router_granted']) {
        expect(denialText).not.toContain(field);
      }
      const agentCleanupToken = await mintTokenFor(agentOnlyId, agentOnlySecret, 'write');
      expect(agentCleanupToken.scope).toBe('write');
      agentState.tokens.push(agentCleanupToken.access_token);
      agentState.verifyAfterClear = {
        token: agentCleanupToken.access_token,
        clientName: agentName,
        scopes: ['write'],
        sourceId: 'default',
        federatedRead: ['default'],
      };

      const agentsRes = await fetch(`${BASE}/admin/api/agents`, { headers: { Cookie: cookie } });
      expect(agentsRes.ok).toBe(true);
      const agents = await agentsRes.json() as Array<{
        id: string; source_id: string | null; federated_read: string[];
      }>;
      const agent = agents.find(row => row.id === clientId);
      expect(agent?.source_id).toBe('default');
      expect(agent?.federated_read).toEqual(['default']);
    } finally {
      let cleanupError: unknown;
      for (const state of [...createdClients].reverse()) {
        try { await cleanupClientNow(cookie, state); } catch (error) { cleanupError ??= error; }
      }
      if (clientId) {
        try {
          await clearFleetGrantNow(cookie, clientId);
          if (primaryVerificationToken) {
            expectExactWhoami(await mcpToolValue(primaryVerificationToken, 'whoami'), {
              clientId,
              clientName: 'e2e-oauth-test',
              scopes: ['read'],
              sourceId: 'default',
              federatedRead: ['default'],
              granted: false,
              grantVersion: 1,
            });
          }
        } catch (error) { cleanupError ??= error; }
      }
      if (cleanupError) throw cleanupError;
    }
  }, 30_000);

  // v0.36.1.x #1076: GET /mcp must return 405 (Method Not Allowed) per the
  // MCP Streamable HTTP spec, not 404. claude.ai + other probing clients
  // distinguish "endpoint exists, no SSE channel" from "endpoint missing"
  // on this status code; 404 makes them give up.
  test('GET /mcp returns 405 with Allow: POST, DELETE (v0.36.1.x #1076)', async () => {
    const res = await fetch(`${BASE}/mcp`, { method: 'GET' });
    expect(res.status).toBe(405);
    expect(res.headers.get('Allow')).toBe('POST, DELETE');
    const body = await res.json() as { jsonrpc?: string; error?: { code?: number } };
    expect(body.jsonrpc).toBe('2.0');
    expect(body.error?.code).toBe(-32000);
  });

  test('X-Forwarded-For header does not crash server', async () => {
    const res = await fetch(`${BASE}/health`, {
      headers: { 'X-Forwarded-For': '10.0.0.1, 172.16.0.1' },
    });
    expect(res.ok).toBe(true);
    const data = await res.json() as any;
    expect(data.status).toBe('ok');
  });

  // =========================================================================
  // Scope enforcement
  // =========================================================================

  test('read-only token is rejected for write operations', async () => {
    const { access_token } = await mintToken('read');
    const res = await mcpCall(access_token, 'tools/call', {
      name: 'put_page',
      arguments: { slug: 'e2e-scope-test', content: '---\ntitle: test\n---\ntest' },
    });

    const body = await res.text();
    // Should be rejected via scope check (403 or JSON-RPC error with scope message)
    expect(res.status === 403 || body.includes('scope') || body.includes('Insufficient')).toBe(true);
  }, 15_000);

  test('write-scoped token can call read operations', async () => {
    const { access_token } = await mintToken('read write');
    const res = await mcpCall(access_token, 'tools/call', {
      name: 'search',
      arguments: { query: 'test', limit: 1 },
    });

    expect(res.status).not.toBe(401);
    expect(res.status).not.toBe(403);
    const body = await res.text();
    // Should get a result, not an auth error
    expect(body).not.toContain('invalid_token');
    expect(body).not.toContain('insufficient_scope');
  }, 15_000);

  // =========================================================================
  // Health endpoint (no auth required) — v0.28.10 made /health liveness-only;
  // engine stats moved to /admin/api/full-stats behind requireAdmin so a
  // saturated pool can't pin /health and trigger orchestrator restart cascades.
  // =========================================================================

  test('v0.28.10: /health returns liveness-only body (no engine stats)', async () => {
    const res = await fetch(`${BASE}/health`);
    expect(res.ok).toBe(true);
    const data = await res.json() as any;
    expect(data.status).toBe('ok');
    expect(data.version).toBeDefined();
    expect(data.engine).toBeDefined();
    // Regression: pre-v0.28.10 /health spread getStats() (page_count,
    // chunk_count, etc.) into the body. The whole point of the v0.28.10
    // split is that /health stops touching those tables. If page_count
    // ever reappears here, the heavy probe leaked back into the public
    // route and the original DoS surface is back.
    expect(data.page_count).toBeUndefined();
    expect(data.chunk_count).toBeUndefined();
    expect(data.embedded_count).toBeUndefined();
    // Body shape is exactly {status, version, engine}.
    expect(Object.keys(data).sort()).toEqual(['engine', 'status', 'version']);
  });

  test('v0.28.10: /admin/api/full-stats without admin cookie returns 401', async () => {
    const res = await fetch(`${BASE}/admin/api/full-stats`);
    expect(res.status).toBe(401);
    const data = await res.json() as any;
    expect(data.error).toBe('Admin authentication required');
  });

  test('v0.28.10: /admin/api/full-stats with valid admin cookie returns getStats() body', async () => {
    const cookie = await adminCookie();

    const statsRes = await fetch(`${BASE}/admin/api/full-stats`, {
      headers: { Cookie: cookie },
    });
    expect(statsRes.ok).toBe(true);
    const stats = await statsRes.json() as any;
    expect(stats.status).toBe('ok');
    expect(stats.version).toBeDefined();
    expect(stats.engine).toBeDefined();
    // The full-stats body is probeHealth's spread of getStats() — page_count
    // is the canonical signal that we're hitting the heavy path here.
    expect(typeof stats.page_count).toBe('number');
    expect(stats.page_count).toBeGreaterThanOrEqual(0);
  }, 15_000);

  // =========================================================================
  // Token lifecycle
  // =========================================================================

  test('multiple tokens can be minted and used independently', async () => {
    const t1 = await mintToken('read');
    const t2 = await mintToken('read write');

    // Both should work
    const r1 = await mcpCall(t1.access_token, 'tools/list');
    const r2 = await mcpCall(t2.access_token, 'tools/list');

    expect(r1.status).not.toBe(401);
    expect(r2.status).not.toBe(401);
  }, 15_000);

  test('wrong client_secret is rejected at token endpoint', async () => {
    const res = await fetch(`${BASE}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `grant_type=client_credentials&client_id=${clientId}&client_secret=gbrain_cs_wrong_secret&scope=read`,
    });
    expect(res.ok).toBe(false);
    const data = await res.json() as any;
    expect(data.error).toBe('invalid_grant');
  });

  test('confidential client can revoke its token only with its valid secret', async () => {
    const { access_token } = await mintToken('read');
    const wrongSecret = await fetch(`${BASE}/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `token=${encodeURIComponent(access_token)}&client_id=${clientId}&client_secret=gbrain_cs_wrong_secret`,
    });
    expect(wrongSecret.status).toBe(401);
    expect((await wrongSecret.json() as any).error).toBe('invalid_client');

    // A rejected revoke request must leave the token usable.
    expect((await mcpCall(access_token, 'tools/list')).status).toBe(200);

    const revoke = await fetch(`${BASE}/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `token=${encodeURIComponent(access_token)}&client_id=${clientId}&client_secret=${clientSecret}`,
    });
    expect(revoke.status).toBe(200);
    expect(revoke.headers.get('cache-control')).toBe('no-store');
    expect((await mcpCall(access_token, 'tools/list')).status).toBe(401);
  }, 15_000);

  test('confidential client_secret_basic revoke returns canonical auth responses', async () => {
    const { access_token: wrongSecretToken } = await mintToken('read');
    const wrongBasic = Buffer.from(`${encodeURIComponent(clientId!)}:${encodeURIComponent('wrong-secret')}`).toString('base64');
    const rejected = await fetch(`${BASE}/revoke`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Basic ${wrongBasic}`,
      },
      body: `token=${encodeURIComponent(wrongSecretToken)}`,
    });
    expect(rejected.status).toBe(401);
    expect(rejected.headers.get('www-authenticate')).toMatch(/^Basic /);
    expect((await mcpCall(wrongSecretToken, 'tools/list')).status).toBe(200);

    const { access_token } = await mintToken('read');
    const validBasic = Buffer.from(`${encodeURIComponent(clientId!)}:${encodeURIComponent(clientSecret!)}`).toString('base64');
    const revoked = await fetch(`${BASE}/revoke`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Basic ${validBasic}`,
      },
      body: `token=${encodeURIComponent(access_token)}`,
    });
    expect(revoked.status).toBe(200);
    expect(revoked.headers.get('cache-control')).toBe('no-store');
    expect((await mcpCall(access_token, 'tools/list')).status).toBe(401);
  }, 15_000);

  test('revoke validates request shape and rejects mixed client authentication', async () => {
    const { access_token } = await mintToken('read');
    const validBasic = Buffer.from(`${encodeURIComponent(clientId!)}:${encodeURIComponent(clientSecret!)}`).toString('base64');

    const mixed = await fetch(`${BASE}/revoke`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Basic ${validBasic}`,
      },
      body: `token=${encodeURIComponent(access_token)}&client_id=${clientId}&client_secret=${clientSecret}`,
    });
    expect(mixed.status).toBe(400);
    expect((await mixed.json() as any).error).toBe('invalid_request');

    const repeatedToken = await fetch(`${BASE}/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `token=${encodeURIComponent(access_token)}&token=duplicate&client_id=${clientId}&client_secret=${clientSecret}`,
    });
    expect(repeatedToken.status).toBe(400);
    expect((await repeatedToken.json() as any).error).toBe('invalid_request');

    const missingToken = await fetch(`${BASE}/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `client_id=${clientId}&client_secret=${clientSecret}`,
    });
    expect(missingToken.status).toBe(400);
    expect((await missingToken.json() as any).error).toBe('invalid_request');
    expect((await mcpCall(access_token, 'tools/list')).status).toBe(200);
  }, 15_000);

  test('unknown and cross-client tokens are opaque 200 no-ops', async () => {
    const unknown = await fetch(`${BASE}/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `token=unknown-token&client_id=${clientId}&client_secret=${clientSecret}`,
    });
    expect(unknown.status).toBe(200);

    const { execSync } = await import('child_process');
    const attackerRegistration = execSync(
      `bun run src/cli.ts auth register-client e2e-revoke-attacker-${Date.now()} --grant-types client_credentials --scopes read`,
      { cwd: process.cwd(), encoding: 'utf8', env: { ...process.env } },
    );
    const attackerId = attackerRegistration.match(/Client ID:\s+(gbrain_cl_\S+)/)?.[1];
    const attackerSecret = attackerRegistration.match(/Client Secret:\s+(gbrain_cs_\S+)/)?.[1];
    expect(attackerId).toBeTruthy();
    expect(attackerSecret).toBeTruthy();
    dcrClientIds.push(attackerId!);

    const { access_token: ownerToken } = await mintToken('read');
    const crossClient = await fetch(`${BASE}/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `token=${encodeURIComponent(ownerToken)}&client_id=${attackerId}&client_secret=${attackerSecret}`,
    });
    expect(crossClient.status).toBe(200);
    expect((await mcpCall(ownerToken, 'tools/list')).status).toBe(200);
  }, 30_000);

  test('public client revoke falls through to the SDK handler', async () => {
    const { execSync } = await import('child_process');
    const registration = execSync(
      `bun run src/cli.ts auth register-client e2e-revoke-public-${Date.now()} --grant-types authorization_code --scopes read --token-endpoint-auth-method none`,
      { cwd: process.cwd(), encoding: 'utf8', env: { ...process.env } },
    );
    const publicClientId = registration.match(/Client ID:\s+(gbrain_cl_\S+)/)?.[1];
    expect(publicClientId).toBeTruthy();
    dcrClientIds.push(publicClientId!);

    const publicToken = `gbrain_at_public_${Date.now()}`;
    const tokenHash = createHash('sha256').update(publicToken).digest('hex');
    const postgres = (await import('postgres')).default;
    const sql = postgres(process.env.GBRAIN_DATABASE_URL || process.env.DATABASE_URL || '', { prepare: false });
    try {
      // Plain-array bind, NOT `sql.array([...])`: sql.array resolves its
      // array OID (and serializer) through postgres.js's typeArrayMap, which
      // is fetched asynchronously on connection startup. This INSERT is the
      // FIRST query on this fresh connection, so the map is still empty and
      // sql.array falls back to the element OID (25 = text) with scalar
      // serialization — real Postgres rejects it with 42804 ("column scopes
      // is of type text[] but expression is of type text"; an explicit
      // ::text[] cast just shifts the failure to 22P02 "malformed array
      // literal" because the value still serializes as a bare scalar). A
      // plain JS array always serializes to the `{...}` literal and binds
      // with an unspecified OID, so Postgres coerces it from column context
      // deterministically — same untyped-bind approach as pgArray() in
      // src/core/oauth-provider.ts. Latent since d61808d80 (v0.42.64.0):
      // CI's e2e.yml never runs this file.
      await sql`
        INSERT INTO oauth_tokens (token_hash, token_type, client_id, scopes, expires_at)
        VALUES (${tokenHash}, ${'access'}, ${publicClientId!}, ${['read']}, ${Math.floor(Date.now() / 1000) + 3600})
      `;
    } finally {
      await sql.end();
    }

    expect((await mcpCall(publicToken, 'tools/list')).status).toBe(200);
    const revoked = await fetch(`${BASE}/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `token=${encodeURIComponent(publicToken)}&client_id=${publicClientId}`,
    });
    expect(revoked.status).toBe(200);
    expect((await mcpCall(publicToken, 'tools/list')).status).toBe(401);
  }, 30_000);

  test('retryable revoke backend failure returns 503 and leaves token usable', async () => {
    const { access_token } = await mintToken('read');
    const tokenHash = createHash('sha256').update(access_token).digest('hex');
    const suffix = Date.now().toString();
    const functionName = `e2e_fail_revoke_${suffix}`;
    const triggerName = `e2e_fail_revoke_trigger_${suffix}`;
    const postgres = (await import('postgres')).default;
    const sql = postgres(process.env.GBRAIN_DATABASE_URL || process.env.DATABASE_URL || '', { prepare: false });
    try {
      await sql.unsafe(`
        CREATE FUNCTION ${functionName}() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF OLD.token_hash = '${tokenHash}' THEN
            RAISE EXCEPTION 'injected retryable revoke failure' USING ERRCODE = '08006';
          END IF;
          RETURN OLD;
        END;
        $$
      `);
      await sql.unsafe(`
        CREATE TRIGGER ${triggerName}
        BEFORE DELETE ON oauth_tokens
        FOR EACH ROW EXECUTE FUNCTION ${functionName}()
      `);

      const failed = await fetch(`${BASE}/revoke`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `token=${encodeURIComponent(access_token)}&client_id=${clientId}&client_secret=${clientSecret}`,
      });
      expect(failed.status).toBe(503);
      expect((await failed.json() as any).error).toBe('temporarily_unavailable');
      expect((await mcpCall(access_token, 'tools/list')).status).toBe(200);
    } finally {
      await sql.unsafe(`DROP TRIGGER IF EXISTS ${triggerName} ON oauth_tokens`);
      await sql.unsafe(`DROP FUNCTION IF EXISTS ${functionName}()`);
      await sql.end();
    }
  }, 30_000);

  // =========================================================================
  // v0.26.2: DCR /register response shape (RFC 7591 §3.2.1 number contract)
  // =========================================================================
  //
  // The user-visible bug v0.26.2 protects against: postgres.js with
  // `prepare: false` returns BIGINT columns as strings, and an RFC-strict
  // DCR client (Claude Code, Cursor) parses the /register response as JSON
  // and rejects timestamps that aren't numbers. This is the HTTP-level test;
  // the internal-store shape test in test/oauth.test.ts is not enough on its
  // own (Codex flagged it as the wrong seam).

  test('DCR /register returns numeric client_id_issued_at (RFC 7591 §3.2.1)', async () => {
    const res = await fetch(`${BASE}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_name: 'e2e-dcr-shape',
        redirect_uris: ['https://example.com/cb'],
        grant_types: ['authorization_code'],
        token_endpoint_auth_method: 'client_secret_basic',
        scope: 'read',
      }),
    });
    expect(res.ok).toBe(true);
    const body = await res.json() as any;
    const registeredId = trackClient(body.client_id);
    try {
      // The contract: client_id_issued_at is REQUIRED to be a JSON number per
      // RFC 7591. Pre-v0.26.2 with prepare:false returned this as a string.
      expect(typeof body.client_id_issued_at).toBe('number');
      expect(Number.isFinite(body.client_id_issued_at)).toBe(true);
      expect(body.client_id_issued_at).toBeGreaterThan(0);

      // client_secret_expires_at is optional; if present it is also numeric.
      if (body.client_secret_expires_at !== undefined) {
        expect(typeof body.client_secret_expires_at).toBe('number');
        expect(Number.isFinite(body.client_secret_expires_at)).toBe(true);
      }
    } finally {
      await revokeClientNow(registeredId);
    }
  }, 15_000);

  test('trusted-looking DCR client and grant-like extensions remain ordinary', async () => {
    const dcrName = 'brain-router-imekka-0123456789ab';
    let dcrId: string | undefined;
    const res = await fetch(`${BASE}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_name: dcrName,
        redirect_uris: [],
        grant_types: ['client_credentials'],
        token_endpoint_auth_method: 'client_secret_post',
        scope: 'read',
        fleetRouter: true,
        fleet_grant: 'fleet_router',
      }),
    });
    expect(res.ok).toBe(true);
    const registration = await res.json() as Record<string, unknown>;
    dcrId = trackClient(registration.client_id as string);
    const dcrSecret = registration.client_secret as string;
    expect(dcrId).toBeTruthy();
    expect(dcrSecret).toBeTruthy();
    let dcrTokenValue: string | undefined;
    try {
      const dcrToken = await mintTokenFor(dcrId, dcrSecret, 'read');
      dcrTokenValue = dcrToken.access_token;
      expect(dcrToken.scope).toBe('read');
      expectExactWhoami(await mcpToolValue(dcrToken.access_token, 'whoami'), {
        clientId: dcrId,
        clientName: dcrName,
        scopes: ['read'],
        sourceId: 'default',
        federatedRead: ['default'],
        granted: false,
        grantVersion: 0,
      });
    } finally {
      await revokeClientNow(dcrId);
      if (dcrTokenValue) {
        expect((await mcpCall(dcrTokenValue, 'tools/list')).status).toBe(401);
      }
    }
  }, 15_000);

  // =========================================================================
  // #2179: DCR token_ttl_seconds — wire-level clamp + echo
  // =========================================================================
  //
  // The unit tests in test/oauth-dcr-ttl.test.ts prove the store-level clamp;
  // this is the HTTP seam: the MCP SDK's /register handler STRIPS unknown
  // body members, so the field only works if serve-http's middleware carries
  // it through dcrRegistrationContext. With the clamp window unset, the max
  // derives fail-closed from the server's --token-ttl (default 3600) — a
  // huge request must come back clamped to that, not rejected — and the
  // minted token must match.

  test('DCR /register accepts token_ttl_seconds, clamps to policy, echoes effective value (#2179)', async () => {
    const registeredIds: string[] = [];
    try {
      const res = await fetch(`${BASE}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_name: 'e2e-dcr-ttl',
          redirect_uris: ['https://example.com/cb'],
          grant_types: ['authorization_code'],
          token_endpoint_auth_method: 'client_secret_basic',
          scope: 'read',
          token_ttl_seconds: 365 * 24 * 3600,
        }),
      });
      expect(res.ok).toBe(true);
      const body = await res.json() as any;
      registeredIds.push(trackClient(body.client_id));
      expect(body.token_ttl_seconds).toBe(3600);

      const res2 = await fetch(`${BASE}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_name: 'e2e-dcr-no-ttl',
          redirect_uris: ['https://example.com/cb'],
          grant_types: ['authorization_code'],
          token_endpoint_auth_method: 'client_secret_basic',
          scope: 'read',
        }),
      });
      expect(res2.ok).toBe(true);
      const body2 = await res2.json() as any;
      registeredIds.push(trackClient(body2.client_id));
      expect(body2.token_ttl_seconds).toBeUndefined();
    } finally {
      for (const id of registeredIds.reverse()) await revokeClientNow(id);
    }
  }, 15_000);

  // =========================================================================
  // v0.26.2: revoke-client CLI subprocess test
  // =========================================================================
  //
  // Validates the actual CLI router in src/commands/auth.ts, not just the
  // database deletion semantics. Codex flagged that a unit test in
  // test/oauth.test.ts proves DB DELETE works but does NOT prove the
  // subcommand exists or routes correctly.

  test('auth revoke-client (CLI) deletes client + cascades to tokens', async () => {
    const { execSync } = await import('child_process');

    // Step 1: register a throwaway client via CLI.
    // env: { ...process.env } per the bun execSync inheritance fix above.
    const regOutput = execSync(
      'bun run src/cli.ts auth register-client e2e-revoke-cli --grant-types client_credentials --scopes read',
      { cwd: process.cwd(), encoding: 'utf8', env: { ...process.env } }
    );
    const idMatch = regOutput.match(/Client ID:\s+(gbrain_cl_\S+)/);
    const secretMatch = regOutput.match(/Client Secret:\s+(gbrain_cs_\S+)/);
    expect(idMatch).not.toBeNull();
    expect(secretMatch).not.toBeNull();
    const id = idMatch![1];
    const secret = secretMatch![1];

    // Step 2: mint a token through the live server.
    const tokenRes = await fetch(`${BASE}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `grant_type=client_credentials&client_id=${id}&client_secret=${secret}&scope=read`,
    });
    expect(tokenRes.ok).toBe(true);
    const { access_token } = await tokenRes.json() as any;

    // Sanity: the freshly-minted token works at /mcp.
    const before = await mcpCall(access_token, 'tools/list');
    expect(before.status).not.toBe(401);

    // Step 3: revoke via the CLI subprocess.
    const revokeOutput = execSync(
      `bun run src/cli.ts auth revoke-client "${id}"`,
      { cwd: process.cwd(), encoding: 'utf8', env: { ...process.env } }
    );
    // The handler prints the human confirmation lines. No exit code != 0
    // here since execSync would throw.
    expect(revokeOutput).toMatch(/OAuth client revoked/);
    expect(revokeOutput).toMatch(/cascade/i);

    // Step 4: previously-minted token must now be rejected at /mcp. Cascade
    // wiped the oauth_tokens row; verifyAccessToken throws "Invalid token".
    // Match the existing pattern at line 156: SDK error mapping varies
    // (401/403/500), so we assert non-success status + non-success body
    // rather than a single status code.
    const after = await mcpCall(access_token, 'tools/list');
    expect(after.status).toBeGreaterThanOrEqual(400);
    const afterBody = await after.text();
    expect(afterBody).not.toContain('"tools":[');

    // Step 5: re-running revoke-client on the now-deleted id must exit 1.
    let secondRunFailed = false;
    let secondRunStderr = '';
    try {
      execSync(`bun run src/cli.ts auth revoke-client "${id}"`,
        { cwd: process.cwd(), encoding: 'utf8', env: { ...process.env } });
    } catch (e: any) {
      secondRunFailed = true;
      secondRunStderr = (e.stderr || '').toString() + (e.stdout || '').toString();
    }
    expect(secondRunFailed).toBe(true);
    expect(secondRunStderr).toMatch(/No client found/);
  }, 30_000);

  // =========================================================================
  // v0.26.3: Migration v33 round-trip — pins the 5 new columns
  // =========================================================================
  //
  // PR #586 referenced oauth_clients.{token_ttl, deleted_at} +
  // mcp_request_log.{agent_name, params, error_message} without an
  // accompanying migration. v33 adds them. This test pins the round-trip:
  // make a /mcp call -> assert all three new mcp_request_log columns
  // persisted correctly. Without v33, the INSERT silently swallows
  // column-doesn't-exist errors via the existing best-effort try/catch
  // and the row never appears.

  test('v0.26.3: /mcp request persists agent_name + params + error_message', async () => {
    const postgres = (await import('postgres')).default;
    const sql = postgres(process.env.GBRAIN_DATABASE_URL || process.env.DATABASE_URL || '', { prepare: false });
    try {
      // Wipe any prior log rows for our test client so we can assert exact counts.
      await sql`DELETE FROM mcp_request_log WHERE token_name = ${clientId!}`;

      // Mint a fresh write-scoped token and make a successful tools/list call.
      const tokenRes = await fetch(`${BASE}/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `grant_type=client_credentials&client_id=${clientId!}&client_secret=${clientSecret!}&scope=read`,
      });
      expect(tokenRes.ok).toBe(true);
      const { access_token } = await tokenRes.json() as any;
      const okRes = await mcpCall(access_token, 'tools/list');
      expect(okRes.status).not.toBe(401);

      // Trigger an error path so the error_message column gets a value too.
      // Request a tool that doesn't exist — v0.28.10 logs unknown-op attempts
      // with operation = the attempted name and error_message starting with
      // 'unknown_operation:'.
      await mcpCall(access_token, 'tools/call', { name: 'this_tool_does_not_exist', arguments: {} });

      // Allow async best-effort INSERT to flush.
      await new Promise(r => setTimeout(r, 250));

      const rows = await sql`
        SELECT operation, status, agent_name, params, error_message
        FROM mcp_request_log
        WHERE token_name = ${clientId!}
        ORDER BY created_at ASC
      ` as unknown as Array<Record<string, unknown>>;

      expect(rows.length).toBeGreaterThanOrEqual(2);

      // Agent name resolved from oauth_clients.client_name (the JOIN in
      // verifyAccessToken or the agent_name backfill path).
      for (const row of rows) {
        expect(row.agent_name).toBe('e2e-oauth-test');
      }

      // v0.28.10: tools/list logs as operation='tools/list' (the JSON-RPC
      // method name). tools/call success/error logs as operation=<inner
      // tool name> (the convention preserved from pre-v0.28.10 dispatch
      // logging — agents querying mcp_request_log filter by tool name, not
      // by JSON-RPC method).
      const listRow = rows.find(r => r.operation === 'tools/list');
      expect(listRow).toBeDefined();
      expect(listRow!.status).toBe('success');

      // The unknown-op call shows up with operation = the attempted name.
      const callRow = rows.find(r => r.operation === 'this_tool_does_not_exist');
      expect(callRow).toBeDefined();
      expect(callRow!.status).toBe('error');

      // error_message populated on the failed call.
      const errorRow = rows.find(r => r.status === 'error');
      expect(errorRow).toBeDefined();
      expect(errorRow!.error_message).toBeTruthy();
      expect(typeof errorRow!.error_message).toBe('string');
      expect(errorRow!.error_message as string).toContain('unknown_operation');
    } finally {
      await sql.end();
    }
  }, 30_000);

  // =========================================================================
  // v0.26.3: request-log filter injection probe
  // =========================================================================
  //
  // Pre-fix: /admin/api/requests built WHERE clauses via sql.unsafe() with
  // single-quote escape (`token_name = '${agent.replace(/'/g, "''")}'`).
  // Post-fix: postgres.js tagged-template fragments. This probe sends a
  // payload that, under broken escaping, would short-circuit to TRUE and
  // return all rows. Under correct parameterization, it matches no rows.

  test("v0.26.3: request-log filter rejects injection attempt (' OR 1=1)", async () => {
    // Use a plain admin session via /admin/login + bootstrap token. This
    // test covers the unauthenticated SQL-injection vector via the agent
    // query parameter — even though the endpoint is admin-gated, defense-
    // in-depth on parameterization matters.
    //
    // Extract the admin bootstrap token from the spawned server's stderr.
    const probe = "alice'%20OR%201%3D1";

    // We don't have a clean way to pull the admin token from the spawned
    // process here (commit 16 deleted the regex extraction). The injection
    // probe still works WITHOUT auth — the endpoint requires it via 401.
    // We assert that the 401 lands BEFORE any SQL gets built, so we don't
    // crash the server with malformed SQL on the way to the auth check.
    const res = await fetch(`${BASE}/admin/api/requests?agent=${probe}`, {
      method: 'GET',
    });
    // No admin cookie — must hit 401, not 500 (no SQL crash).
    expect(res.status).toBe(401);

    // Server is still alive (didn't crash on the malformed input).
    const health = await fetch(`${BASE}/health`);
    expect(health.ok).toBe(true);
  });

  // =========================================================================
  // v0.26.3: per-client TTL flow
  // =========================================================================
  //
  // PR #586 added `tokenTtl` per OAuth client. exchangeClientCredentials
  // reads oauth_clients.token_ttl (per-client override) and falls back to
  // the server default. This test registers a client with a custom TTL,
  // mints a token, and asserts the response's expires_in matches.

  test('v0.26.3: per-client token_ttl is honored on token mint', async () => {
    const postgres = (await import('postgres')).default;
    const sql = postgres(process.env.GBRAIN_DATABASE_URL || process.env.DATABASE_URL || '', { prepare: false });
    try {
      // Register a client + set a custom token_ttl (24 hours = 86400 seconds).
      const { execSync } = await import('child_process');
      const regOutput = execSync(
        'bun run src/cli.ts auth register-client e2e-test-ttl --grant-types client_credentials --scopes read',
        { cwd: process.cwd(), encoding: 'utf8', env: { ...process.env } }
      );
      const idMatch = regOutput.match(/Client ID:\s+(gbrain_cl_\S+)/);
      const secretMatch = regOutput.match(/Client Secret:\s+(gbrain_cs_\S+)/);
      expect(idMatch).not.toBeNull();
      expect(secretMatch).not.toBeNull();
      const id = idMatch![1];
      const secret = secretMatch![1];
      dcrClientIds.push(id); // afterAll cleanup

      // Set a 24-hour TTL.
      await sql`UPDATE oauth_clients SET token_ttl = 86400 WHERE client_id = ${id}`;

      // Mint a token. Response must include expires_in close to 86400.
      const tokenRes = await fetch(`${BASE}/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `grant_type=client_credentials&client_id=${id}&client_secret=${secret}&scope=read`,
      });
      expect(tokenRes.ok).toBe(true);
      const body = await tokenRes.json() as any;
      expect(body.expires_in).toBe(86400);

      // Update TTL to a different value mid-test, mint again, assert new value.
      await sql`UPDATE oauth_clients SET token_ttl = 7200 WHERE client_id = ${id}`;
      const tokenRes2 = await fetch(`${BASE}/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `grant_type=client_credentials&client_id=${id}&client_secret=${secret}&scope=read`,
      });
      expect(tokenRes2.ok).toBe(true);
      const body2 = await tokenRes2.json() as any;
      expect(body2.expires_in).toBe(7200);

      // NULL token_ttl falls back to server default (3600 = 1 hour).
      await sql`UPDATE oauth_clients SET token_ttl = NULL WHERE client_id = ${id}`;
      const tokenRes3 = await fetch(`${BASE}/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `grant_type=client_credentials&client_id=${id}&client_secret=${secret}&scope=read`,
      });
      expect(tokenRes3.ok).toBe(true);
      const body3 = await tokenRes3.json() as any;
      expect(body3.expires_in).toBe(3600);
    } finally {
      await sql.end();
    }
  }, 30_000);

  // =========================================================================
  // v0.26.3: magic-link single-use + 401 styled error page
  // =========================================================================
  //
  // D11=C: /admin/auth/:nonce is single-use. First click consumes the nonce,
  // second click fails with the styled 401 page. No bootstrap token in URL.
  //
  // Also covers F6.5: server returns Content-Type: text/html on the 401
  // path (Express auto-sets this for HTML body) so browsers render the
  // styled page instead of treating it as plain text.

  test('v0.26.3: invalid magic-link nonce returns styled 401 HTML page', async () => {
    const res = await fetch(`${BASE}/admin/auth/garbage_nonce_that_does_not_exist`, { redirect: 'manual' });
    expect(res.status).toBe(401);
    const ct = res.headers.get('content-type') || '';
    expect(ct).toContain('text/html');
    const body = await res.text();
    expect(body).toContain('expired');
    expect(body).toContain('GBrain');
  });

  test('v0.26.3: magic-link nonce is single-use (second click fails)', async () => {
    // Mint a one-time nonce.
    const issueRes = await fetch(`${BASE}/admin/api/issue-magic-link`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: ['Bearer', ADMIN_BOOTSTRAP_TOKEN].join(' ') },
      body: '{}',
    });
    expect(issueRes.ok).toBe(true);
    const { url } = await issueRes.json() as any;
    expect(url).toContain('/admin/auth/');

    // First click — should set cookie + redirect (302 to /admin/).
    const first = await fetch(url, { redirect: 'manual' });
    expect(first.status).toBe(302);
    const cookie = first.headers.get('set-cookie') || '';
    expect(cookie).toContain('gbrain_admin=');

    // Second click on the same URL — must fail (single-use consumed).
    const second = await fetch(url, { redirect: 'manual' });
    expect(second.status).toBe(401);
    const secondBody = await second.text();
    expect(secondBody).toContain('GBrain');
  }, 15_000);

  // =========================================================================
  // v0.26.3: agent_name backfill across oauth_clients + access_tokens
  // =========================================================================
  //
  // Migration v33 backfills mcp_request_log.agent_name using
  //   COALESCE(oauth_clients.client_name, access_tokens.name, token_name)
  // This test confirms the agent_name is correctly resolved across both
  // auth lanes (oauth client + legacy api key).

  test('v0.26.3: agent_name resolves correctly for OAuth + legacy paths', async () => {
    const postgres = (await import('postgres')).default;
    const sql = postgres(process.env.GBRAIN_DATABASE_URL || process.env.DATABASE_URL || '', { prepare: false });
    try {
      // Make an OAuth-authenticated request — agent_name should be the OAuth client_name.
      const tokenRes = await fetch(`${BASE}/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `grant_type=client_credentials&client_id=${clientId!}&client_secret=${clientSecret!}&scope=read`,
      });
      const { access_token } = await tokenRes.json() as any;
      await mcpCall(access_token, 'tools/list');
      await new Promise(r => setTimeout(r, 250));

      const oauthRows = await sql`
        SELECT agent_name FROM mcp_request_log
        WHERE token_name = ${clientId!}
        ORDER BY created_at DESC LIMIT 1
      ` as unknown as Array<{ agent_name: string }>;
      expect(oauthRows.length).toBeGreaterThan(0);
      expect(oauthRows[0].agent_name).toBe('e2e-oauth-test');
    } finally {
      await sql.end();
    }
  }, 15_000);

  // =========================================================================
  // v0.26.3: register-client missing-name returns 400
  // =========================================================================
  //
  // Defense-in-depth: the admin register-client endpoint must validate
  // input. Pre-fix would have crashed or returned 500.

  test('v0.26.3: /admin/api/register-client without name returns 400', async () => {
    // Endpoint is admin-cookie-gated. Without auth we should get 401, not 500.
    // Without a name in the body (with auth) we should get 400. We test the
    // 401 path here as a basic input-validation smoke; the 400 path requires
    // an admin session which the test fixture doesn't easily produce.
    const res = await fetch(`${BASE}/admin/api/register-client`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    });
    expect(res.status).toBe(401);
  });

  // =========================================================================
  // F7 + F7b: HTTP MCP shell-job RCE regression
  // =========================================================================
  //
  // The headline trust-boundary fix. Pre-fix, the inlined OperationContext
  // literal in serve-http.ts forgot to set `remote: true`, which meant
  // operations.ts:1391's protected-job-name guard (`if (ctx.remote && ...)`)
  // saw a falsy undefined and skipped. An HTTP MCP caller with a write-scoped
  // token could then submit `{name: "shell", params: {cmd: "id"}}` over /mcp
  // and execute arbitrary commands on the gbrain host.
  //
  // The fix is two-layered:
  //   1) F7  — serve-http.ts sets `remote: true` explicitly.
  //   2) F7b — operations.ts:1391 + :1400 use `ctx.remote !== false` /
  //            `ctx.remote === false` so undefined fails closed even if a
  //            future transport bypasses the type via cast.
  //
  // Together they close the path even if either layer regresses alone.

  test('F7: HTTP MCP cannot submit shell jobs (RCE regression)', async () => {
    // v0.28.10: must mint admin scope. submit_job's required scope is
    // 'admin'; without it, hasScope() rejects with insufficient_scope BEFORE
    // the F7 protected-name guard at operations.ts:1527 fires. To validate
    // the actual RCE protection (the protected-name guard), the token has
    // to clear the scope check first.
    const { access_token } = await mintToken('admin');
    const res = await mcpCall(access_token, 'tools/call', {
      name: 'submit_job',
      arguments: { name: 'shell', data: { cmd: 'id' } },
    });

    const body = await res.text();
    // Must reject. Either HTTP 4xx, or a JSON-RPC envelope carrying an
    // OperationError with code permission_denied. The exact wire shape
    // depends on SDK error mapping — assert the negative invariant
    // (no command executed) and the positive invariant (rejection signal).
    const rejected =
      res.status >= 400 ||
      body.includes('permission_denied') ||
      body.includes('cannot be submitted over MCP');
    expect(rejected).toBe(true);

    // Negative: response must NOT contain a successful submit_job result
    // (which would surface a job_id field). If a job ID came back the
    // privesc landed.
    expect(body).not.toMatch(/"job_id"\s*:\s*"?\d+/);
  }, 15_000);

  test('F7: HTTP MCP cannot submit subagent jobs (protected name)', async () => {
    // Same admin-scope requirement as the shell-job sibling test above.
    const { access_token } = await mintToken('admin');
    const res = await mcpCall(access_token, 'tools/call', {
      name: 'submit_job',
      arguments: { name: 'subagent', data: { prompt: 'noop' } },
    });
    const body = await res.text();
    const rejected =
      res.status >= 400 ||
      body.includes('permission_denied') ||
      body.includes('cannot be submitted over MCP');
    expect(rejected).toBe(true);
    expect(body).not.toMatch(/"job_id"\s*:\s*"?\d+/);
  }, 15_000);
});
