import { afterAll, afterEach, beforeAll, describe, expect, test } from 'bun:test';
import { configureGateway, resetGateway } from '../src/core/ai/gateway.ts';
import { PGLiteEngine } from '../src/core/pglite-engine.ts';
import { operationsByName, type OperationContext } from '../src/core/operations.ts';
import type { SearchResult } from '../src/core/types.ts';

let engine: PGLiteEngine;
let entityPageId: number;
const originalFetch = globalThis.fetch;
const entitySlug = 'people/binding-privacy-fixture';
const captureSlug = 'daily/hermes/privacy-owner/0123456789abcdef0123/turn-a';
const sessionRef = '0123456789abcdef0123';
const privateEntitySlug = 'people/private-binding-target';
const privateCaptureSlug = 'daily/hermes/privacy-owner/fedcba9876543210fedc/private-turn';
const privateSessionRef = 'fedcba9876543210fedc';

function remoteContext(authorized: boolean): OperationContext {
  return {
    engine,
    config: { embedding_dimensions: 1536 },
    logger: { info() {}, warn() {}, error() {}, debug() {} },
    dryRun: false,
    remote: true,
    sourceId: 'default',
    auth: {
      token: 'fixture-token',
      clientId: `fixture-${authorized ? 'fleet' : 'ordinary'}`,
      clientName: 'brain-router-owner-0123456789ab',
      scopes: ['read'],
      sourceId: 'default',
      allowedSources: ['default'],
      ...(authorized ? {
        fleetGrant: 'fleet_router' as const,
        fleetGrantVersion: 1 as const,
        fleetGrantSetBy: 'operator' as const,
        fleetGrantSetAt: '2026-08-29T12:00:00.000Z',
      } : {}),
    },
  } as unknown as OperationContext;
}

function bindingsOf(results: SearchResult[]): unknown[] | undefined {
  return (results.find((result) => result.slug === entitySlug) as
    | (SearchResult & { fact_bindings?: unknown[] })
    | undefined)?.fact_bindings;
}

function fixtureSearchResult(): SearchResult {
  return {
    slug: entitySlug,
    page_id: entityPageId,
    title: 'Binding Privacy Fixture',
    type: 'person',
    chunk_text: 'binding privacy fixture searchable text',
    chunk_source: 'compiled_truth',
    chunk_id: 1,
    chunk_index: 0,
    score: 1,
    stale: false,
    source_id: 'default',
  };
}

async function expectOperatorOnly(
  run: (ctx: OperationContext) => Promise<SearchResult[]>,
): Promise<void> {
  const originalExecuteRaw = engine.executeRaw.bind(engine);
  let bindingSqlCalls = 0;
  engine.executeRaw = (async (sql: string, params?: unknown[]) => {
    if (sql.includes('WITH refs(source_id, slug)')) bindingSqlCalls += 1;
    return originalExecuteRaw(sql, params);
  }) as typeof engine.executeRaw;
  try {
    const operatorResults = await run(remoteContext(true));
    const bindings = bindingsOf(operatorResults);
    expect(bindings).toEqual([{
      fact_id: expect.any(Number),
      capture_page_slug: captureSlug,
      hermes_session_ref: sessionRef,
      matched_via: 'entity_fence',
    }]);
    expect(Object.keys(bindings![0] as Record<string, unknown>).sort()).toEqual([
      'capture_page_slug', 'fact_id', 'hermes_session_ref', 'matched_via',
    ]);
    expect(bindingSqlCalls).toBe(1);

    const beforeOrdinary = bindingSqlCalls;
    const selfNamedDcrResults = await run(remoteContext(false));
    expect(bindingsOf(selfNamedDcrResults)).toBeUndefined();
    expect(JSON.stringify(selfNamedDcrResults)).not.toContain(captureSlug);
    expect(JSON.stringify(selfNamedDcrResults)).not.toContain(sessionRef);
    expect(bindingSqlCalls).toBe(beforeOrdinary);

    // Binding-store failures omit the additive private coordinates while
    // preserving the already-authorized underlying search result.
    engine.executeRaw = (async (sql: string, params?: unknown[]) => {
      if (sql.includes('WITH refs(source_id, slug)')) {
        bindingSqlCalls += 1;
        throw new Error('fact-binding storage unavailable');
      }
      return originalExecuteRaw(sql, params);
    }) as typeof engine.executeRaw;
    const degraded = await run(remoteContext(true));
    expect(bindingsOf(degraded)).toBeUndefined();
    expect(degraded.length).toBeGreaterThan(0);
    expect(JSON.stringify(degraded)).not.toContain(captureSlug);
    expect(JSON.stringify(degraded)).not.toContain(sessionRef);
  } finally {
    engine.executeRaw = originalExecuteRaw as typeof engine.executeRaw;
  }
}

beforeAll(async () => {
  engine = new PGLiteEngine();
  await engine.connect({});
  await engine.initSchema();
  await engine.putPage(entitySlug, {
    title: 'Binding Privacy Fixture',
    type: 'person',
    compiled_truth: 'binding privacy fixture searchable text',
    timeline: '',
    frontmatter: {},
  });
  await engine.putPage(captureSlug, {
    title: 'Private Capture Origin',
    type: 'note',
    compiled_truth: 'capture origin',
    timeline: '',
    frontmatter: { hermes_session_ref: sessionRef },
  });
  await engine.putPage(privateEntitySlug, {
    title: 'Synthetic Private Binding Needle ZXQ-491',
    type: 'person',
    compiled_truth: 'synthetic private binding needle zxq-491',
    timeline: '',
    frontmatter: { visibility: 'private' },
  });
  await engine.putPage(privateCaptureSlug, {
    title: 'Private Capture Origin',
    type: 'note',
    compiled_truth: 'private capture origin',
    timeline: '',
    frontmatter: { visibility: 'private', hermes_session_ref: privateSessionRef },
  });
  const [page] = await engine.executeRaw<{ id: number }>(
    'SELECT id FROM pages WHERE source_id = $1 AND slug = $2',
    ['default', entitySlug],
  );
  entityPageId = page.id;
  await engine.executeRaw(
    `INSERT INTO facts
       (source_id, entity_slug, fact, kind, visibility, notability, source,
        source_session, context, source_markdown_slug, confidence)
     VALUES ('default', $1, 'binding privacy fact', 'fact', 'private', 'high',
             'mcp:put_page', $2, $3, $1, 1)`,
    [entitySlug, sessionRef, captureSlug],
  );
  await engine.executeRaw(
    `INSERT INTO facts
       (source_id, entity_slug, fact, kind, visibility, notability, source,
        source_session, context, source_markdown_slug, confidence)
     VALUES ('default', $1, 'private binding fact', 'fact', 'private', 'high',
             'mcp:put_page', $2, $3, $1, 1)`,
    [privateEntitySlug, privateSessionRef, privateCaptureSlug],
  );
  await engine.setConfig('search.cache.enabled', 'false');
  await engine.setConfig('search.mode', 'conservative');
  await engine.setConfig('search.crag_escalation', 'false');
  await engine.setConfig('search.crag_think', 'false');
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  resetGateway();
});

afterAll(async () => {
  await engine.disconnect();
});

describe('search branch fact-binding privacy', () => {
  test('search keyword-only branch requires operator-provisioned router identity', async () => {
    await engine.setConfig('search.mcp_keyword_only', 'true');
    const originalSearchKeyword = engine.searchKeyword.bind(engine);
    engine.searchKeyword = (async () => [fixtureSearchResult()]) as typeof engine.searchKeyword;
    try {
      await expectOperatorOnly(async (ctx) => operationsByName.search.handler(ctx, {
        query: 'searchable text',
        limit: 5,
      }) as Promise<SearchResult[]>);
    } finally {
      engine.searchKeyword = originalSearchKeyword;
    }
  });

  test('search hybrid branch requires operator-provisioned router identity', async () => {
    await engine.setConfig('search.mcp_keyword_only', 'false');
    await expectOperatorOnly(async (ctx) => operationsByName.search.handler(ctx, {
      query: 'binding privacy fixture',
      limit: 5,
    }) as Promise<SearchResult[]>);
  });

  test('query text branch requires operator-provisioned router identity', async () => {
    await expectOperatorOnly(async (ctx) => operationsByName.query.handler(ctx, {
      query: 'binding privacy fixture',
      expand: false,
      use_cache: false,
      limit: 5,
    }) as Promise<SearchResult[]>);
  });

  test('query image branch requires operator-provisioned router identity', async () => {
    configureGateway({
      embedding_model: 'openai:text-embedding-3-large',
      embedding_dimensions: 1536,
      embedding_multimodal_model: 'voyage:voyage-multimodal-3',
      env: {
        OPENAI_API_KEY: 'test-key',
        VOYAGE_API_KEY: 'test-key',
      },
    });
    globalThis.fetch = (async () => new Response(JSON.stringify({
      data: [{ embedding: Array.from({ length: 1024 }, () => 0.1) }],
    }), { status: 200, headers: { 'Content-Type': 'application/json' } })) as unknown as typeof fetch;

    const originalSearchVector = engine.searchVector.bind(engine);
    engine.searchVector = (async () => [fixtureSearchResult()]) as typeof engine.searchVector;
    try {
      await expectOperatorOnly(async (ctx) => operationsByName.query.handler(ctx, {
        image: 'c3ludGhldGljLWltYWdl',
        image_mime: 'image/png',
        limit: 5,
      }) as Promise<SearchResult[]>);
    } finally {
      engine.searchVector = originalSearchVector;
    }
  });

  test('fleet grant cannot bypass private-page visibility and hidden results never reach binding SQL', async () => {
    const originalExecuteRaw = engine.executeRaw.bind(engine);
    let bindingSqlCalls = 0;
    engine.executeRaw = (async (sql: string, params?: unknown[]) => {
      if (sql.includes('WITH refs(source_id, slug)')) bindingSqlCalls += 1;
      return originalExecuteRaw(sql, params);
    }) as typeof engine.executeRaw;
    try {
      await expect(operationsByName.get_page.handler(remoteContext(true), {
        slug: privateEntitySlug,
      })).rejects.toMatchObject({ code: 'page_not_found' });
      expect(bindingSqlCalls).toBe(0);

      await engine.setConfig('search.mcp_keyword_only', 'true');
      const keyword = await operationsByName.search.handler(remoteContext(true), {
        query: 'ZXQ-491',
        limit: 5,
      }) as SearchResult[];
      expect(keyword.find((row) => row.slug === privateEntitySlug)).toBeUndefined();
      expect(JSON.stringify(keyword)).not.toContain(privateCaptureSlug);
      expect(JSON.stringify(keyword)).not.toContain(privateSessionRef);
      expect(bindingSqlCalls).toBe(0);

      await engine.setConfig('search.mcp_keyword_only', 'false');
      const text = await operationsByName.query.handler(remoteContext(true), {
        query: 'ZXQ-491',
        expand: false,
        use_cache: false,
        limit: 5,
      }) as SearchResult[];
      expect(text.find((row) => row.slug === privateEntitySlug)).toBeUndefined();
      expect(JSON.stringify(text)).not.toContain(privateCaptureSlug);
      expect(JSON.stringify(text)).not.toContain(privateSessionRef);
      expect(bindingSqlCalls).toBe(0);

      configureGateway({
        embedding_model: 'openai:text-embedding-3-large',
        embedding_dimensions: 1536,
        embedding_multimodal_model: 'voyage:voyage-multimodal-3',
        env: { OPENAI_API_KEY: 'test-key', VOYAGE_API_KEY: 'test-key' },
      });
      globalThis.fetch = (async () => new Response(JSON.stringify({
        data: [{ embedding: Array.from({ length: 1024 }, () => 0.1) }],
      }), { status: 200, headers: { 'Content-Type': 'application/json' } })) as unknown as typeof fetch;
      const originalSearchVector = engine.searchVector.bind(engine);
      engine.searchVector = (async (_vector, opts) => {
        expect(opts?.excludePrivate).toBeTrue();
        return [];
      }) as typeof engine.searchVector;
      try {
        const image = await operationsByName.query.handler(remoteContext(true), {
          image: 'c3ludGhldGljLWltYWdl',
          image_mime: 'image/png',
          limit: 5,
        }) as SearchResult[];
        expect(image).toEqual([]);
        expect(bindingSqlCalls).toBe(0);
      } finally {
        engine.searchVector = originalSearchVector;
      }
    } finally {
      engine.executeRaw = originalExecuteRaw as typeof engine.executeRaw;
    }
  });
});
