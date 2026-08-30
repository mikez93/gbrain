import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { PGLiteEngine } from '../src/core/pglite-engine.ts';
import {
  factPageBindingsFor,
  loadFactPageBindings,
  stampFactPageBindings,
} from '../src/core/facts/page-bindings.ts';
import { operationsByName, type OperationContext } from '../src/core/operations.ts';
import { canReadFactBindings } from '../src/core/ops/fleet-router-context.ts';
import type { SearchResult } from '../src/core/types.ts';

let engine: PGLiteEngine;

const captureA = 'daily/hermes/owner-a/0123456789abcdef0123/turn-a';
const sessionA = '0123456789abcdef0123';
const entityA = 'people/example-owner';
const captureB = 'daily/hermes/owner-b/fedcba9876543210fedc/turn-b';
const sessionB = 'fedcba9876543210fedc';
const entityB = 'companies/example-company';

beforeAll(async () => {
  engine = new PGLiteEngine();
  await engine.connect({});
  await engine.initSchema();
  await engine.executeRaw(
    "INSERT INTO sources (id, name, config) VALUES ('owner-b', 'Owner B', '{}'::jsonb) ON CONFLICT (id) DO NOTHING",
  );
  await engine.putPage(captureA, { title: 'Capture A', type: 'note', compiled_truth: 'capture a', timeline: '', frontmatter: {} });
  await engine.putPage(entityA, { title: 'Entity A', type: 'person', compiled_truth: 'entity a', timeline: '', frontmatter: {} });
  await engine.putPage(captureB, { title: 'Capture B', type: 'note', compiled_truth: 'capture b', timeline: '', frontmatter: {} }, { sourceId: 'owner-b' });
  await engine.putPage(entityB, { title: 'Entity B', type: 'company', compiled_truth: 'entity b', timeline: '', frontmatter: {} }, { sourceId: 'owner-b' });
  await engine.executeRaw(
    `INSERT INTO facts
       (source_id, entity_slug, fact, kind, visibility, notability, source,
        source_session, context, source_markdown_slug, confidence)
     VALUES
       ('default', $1, 'binding-private', 'fact', 'private', 'high', 'mcp:put_page', $2, $3, $1, 1),
       ('owner-b', $4, 'binding-world', 'fact', 'world', 'high', 'mcp:put_page', $5, $6, $4, 1),
       ('default', $1, 'binding-incomplete', 'fact', 'private', 'high', 'mcp:put_page', NULL, $3, $1, 1)`,
    [entityA, sessionA, captureA, entityB, sessionB, captureB],
  );
});

afterAll(async () => {
  await engine.disconnect();
});

describe('fact page/session bindings', () => {
  test('keeps capture origin separate from the physical entity fence across sources', async () => {
    const map = await loadFactPageBindings(engine, [
      { sourceId: 'default', slug: captureA },
      { sourceId: 'default', slug: entityA },
      { sourceId: 'owner-b', slug: captureB },
      { sourceId: 'owner-b', slug: entityB },
    ], { authorized: true });
    expect(factPageBindingsFor(map, 'default', captureA)[0]).toMatchObject({
      capture_page_slug: captureA,
      hermes_session_ref: sessionA,
      matched_via: 'capture_page',
    });
    expect(factPageBindingsFor(map, 'default', entityA)[0]).toMatchObject({
      capture_page_slug: captureA,
      hermes_session_ref: sessionA,
      matched_via: 'entity_fence',
    });
    expect(factPageBindingsFor(map, 'owner-b', entityB)[0]).toMatchObject({
      capture_page_slug: captureB,
      hermes_session_ref: sessionB,
    });
    expect(factPageBindingsFor(map, 'default', captureA)).toHaveLength(1);
  });

  test('ordinary remote callers receive no capture metadata, including for world facts', async () => {
    const map = await loadFactPageBindings(engine, [
      { sourceId: 'default', slug: captureA },
      { sourceId: 'owner-b', slug: captureB },
    ], { authorized: false });
    expect(factPageBindingsFor(map, 'default', captureA)).toEqual([]);
    expect(factPageBindingsFor(map, 'owner-b', captureB)).toEqual([]);
  });

  test('missing, malformed, or out-of-scope remote auth never queries binding storage', async () => {
    let rawQueries = 0;
    const noQueryEngine = {
      async executeRaw() {
        rawQueries += 1;
        throw new Error('binding storage must not be queried');
      },
    } as unknown as PGLiteEngine;
    const denied = [
      { remote: true },
      { remote: true, auth: { clientName: 'ordinary-client', scopes: ['read'] } },
      { remote: true, auth: { clientName: 'brain-router-owner-not-hex', scopes: ['read'] } },
      { remote: true, auth: { clientName: 'brain-router-owner-0123456789ab', scopes: ['write'] } },
      { remote: undefined, auth: { clientName: 'brain-router-owner-0123456789ab', scopes: ['read'] } },
      { remote: true, auth: { clientName: 'brain-router-owner-0123456789ab', scopes: ['read'] } },
      { remote: true, auth: { clientName: 'brain-router-owner-0123456789ab', scopes: ['read'], surfaceSetBy: 'dcr_default' } },
      { remote: true, auth: { clientName: 'brain-router-owner-0123456789ab', scopes: ['read'], surfaceSetBy: 'self' } },
    ] as unknown as OperationContext[];
    for (const ctx of denied) {
      expect(canReadFactBindings(ctx)).toBeFalse();
      const map = await loadFactPageBindings(
        noQueryEngine,
        [{ sourceId: 'default', slug: captureA }],
        { authorized: canReadFactBindings(ctx) },
      );
      expect(map.size).toBe(0);
    }
    expect(rawQueries).toBe(0);
  });

  test('authorized bindings are capped at 25, deterministic, and duplicate-free', async () => {
    const capture = 'daily/hermes/owner-c/aaaaaaaaaaaaaaaaaaaa/turn-cap';
    const session = 'aaaaaaaaaaaaaaaaaaaa';
    const params: unknown[] = [];
    const values = Array.from({ length: 30 }, (_, index) => {
      params.push(`binding-cap-${index}`, session, capture);
      const offset = index * 3;
      return `('default', $${offset + 1}, 'fact', 'private', 'high', 'mcp:put_page', $${offset + 2}, $${offset + 3}, 1)`;
    }).join(',');
    await engine.executeRaw(
      `INSERT INTO facts
         (source_id, fact, kind, visibility, notability, source,
          source_session, context, confidence)
       VALUES ${values}`,
      params,
    );
    const map = await loadFactPageBindings(
      engine,
      [{ sourceId: 'default', slug: capture }],
      { authorized: true },
    );
    const bindings = factPageBindingsFor(map, 'default', capture);
    expect(bindings).toHaveLength(25);
    expect(bindings.map((binding) => binding.fact_id))
      .toEqual([...bindings.map((binding) => binding.fact_id)].sort((a, b) => b - a));
    expect(new Set(bindings.map((binding) => `${binding.fact_id}:${binding.matched_via}`)).size)
      .toBe(25);
    expect(bindings.every((binding) => binding.matched_via === 'capture_page')).toBeTrue();
  });

  test('search result stamping carries the exact fact binding', async () => {
    const results = [{
      slug: entityA,
      page_id: 1,
      title: 'Entity A',
      type: 'person',
      chunk_text: 'entity a',
      chunk_source: 'compiled_truth',
      chunk_id: 1,
      chunk_index: 0,
      score: 1,
      stale: false,
      source_id: 'default',
    }] as SearchResult[];
    await stampFactPageBindings(engine, results, { authorized: true });
    const bindings = (results[0] as SearchResult & {
      fact_bindings?: Array<{ capture_page_slug: string; hermes_session_ref: string }>;
    }).fact_bindings;
    expect(bindings?.[0].capture_page_slug).toBe(captureA);
    expect(bindings?.[0].hermes_session_ref).toBe(sessionA);
  });

  test('get_page exposes the same binding used by owner brain_read', async () => {
    const ctx = {
      engine,
      config: {},
      logger: { info() {}, warn() {}, error() {}, debug() {} },
      dryRun: false,
      remote: false,
      sourceId: 'default',
    } as unknown as OperationContext;
    const page = await operationsByName.get_page.handler(ctx, { slug: entityA }) as Record<string, unknown>;
    const bindings = page.fact_bindings as Array<Record<string, unknown>>;
    expect(bindings[0]).toMatchObject({
      capture_page_slug: captureA,
      hermes_session_ref: sessionA,
      matched_via: 'entity_fence',
    });
    expect(bindings[0]).not.toHaveProperty('entity_page_slug');
  });

  test('authenticated fleet-router get_page receives private binding; ordinary remote gets no oracle', async () => {
    const remoteContext = (clientName: string, surfaceSetBy?: string) => ({
      engine,
      config: {},
      logger: { info() {}, warn() {}, error() {}, debug() {} },
      dryRun: false,
      remote: true,
      sourceId: 'default',
      auth: {
        token: 'fixture-token',
        clientId: 'fixture-client',
        clientName,
        scopes: ['read'],
        ...(surfaceSetBy ? { surfaceSetBy } : {}),
      },
    }) as unknown as OperationContext;
    const fleetPage = await operationsByName.get_page.handler(
      remoteContext('brain-router-owner-0123456789ab', 'operator'),
      { slug: entityA },
    ) as Record<string, unknown>;
    expect(fleetPage.fact_bindings).toBeArray();
    expect((fleetPage.fact_bindings as Array<Record<string, unknown>>)[0])
      .not.toHaveProperty('entity_page_slug');

    const ordinaryPage = await operationsByName.get_page.handler(
      remoteContext('ordinary-client'),
      { slug: entityA },
    ) as Record<string, unknown>;
    expect(ordinaryPage.fact_bindings).toBeUndefined();

    const selfNamedDcrPage = await operationsByName.get_page.handler(
      remoteContext('brain-router-owner-0123456789ab', 'dcr_default'),
      { slug: entityA },
    ) as Record<string, unknown>;
    expect(selfNamedDcrPage.fact_bindings).toBeUndefined();
  });
});
