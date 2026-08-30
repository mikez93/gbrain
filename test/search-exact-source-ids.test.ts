import { describe, expect, test } from 'bun:test';
import { operationsByName, type OperationContext } from '../src/core/operations.ts';
import {
  normalizeTrustedQueryEmbedding,
  normalizeFleetRouterKeywordFallback,
  resolvePrecomputedQueryReranker,
  resolveSearchModeForCaller,
} from '../src/core/ops/search.ts';
import type { SearchOpts, SearchResult } from '../src/core/types.ts';

const row: SearchResult = {
  slug: 'notes/example',
  page_id: 7,
  title: 'Example',
  type: 'note',
  chunk_text: 'exact source scope fixture',
  chunk_source: 'compiled_truth',
  chunk_id: 11,
  chunk_index: 0,
  score: 1,
  stale: false,
  source_id: 'source-a',
};

function context(
  remote: boolean,
  clientName?: string,
  fleetGrant?: 'fleet_router' | 'ordinary_remote',
): { ctx: OperationContext; calls: SearchOpts[] } {
  const calls: SearchOpts[] = [];
  const engine = {
    getConfig: async (key: string) => {
      if (key === 'search.mcp_keyword_only') return 'true';
      if (key === 'search.mode') return 'conservative';
      if (key === 'search.reranker.enabled') return 'false';
      if (key === 'search.reranker.model') {
        return 'openrouter:voyageai/rerank-2.5-lite';
      }
      if (key === 'search.reranker.top_n_in') return '5';
      return null;
    },
    searchKeyword: async (_query: string, opts: SearchOpts) => {
      calls.push(opts);
      return [{ ...row }];
    },
    executeRaw: async (sql: string) => {
      if (sql.startsWith('SELECT id, updated_at FROM pages')) {
        return [{ id: 7, updated_at: new Date('2026-08-28T12:34:56.000Z') }];
      }
      if (sql.includes('WITH refs(source_id, slug)')) {
        return [{
          ref_source_id: 'source-a',
          ref_slug: row.slug,
          fact_id: 77,
          capture_page_slug: 'daily/hermes/owner-a/0123456789abcdef0123/turn-a',
          hermes_session_ref: '0123456789abcdef0123',
          matched_via: 'entity_fence',
        }];
      }
      return [];
    },
  };
  return {
    calls,
    ctx: {
      engine,
      config: { embedding_dimensions: 3 },
      logger: { info() {}, warn() {}, error() {}, debug() {} },
      dryRun: false,
      remote,
      sourceId: 'default',
      ...(clientName ? {
        auth: {
          token: 'fixture-token',
          clientId: 'fixture-client',
          clientName,
          scopes: ['read'],
          ...(fleetGrant ? { fleetGrant } : {}),
          ...(fleetGrant === 'fleet_router' ? {
            fleetGrantVersion: 1 as const,
            fleetGrantSetBy: 'operator' as const,
            fleetGrantSetAt: '2026-08-29T12:00:00.000Z',
          } : {}),
        },
      } : {}),
    } as unknown as OperationContext,
  };
}

describe('search source_ids trusted-local contract', () => {
  test('passes one exact source array to the retrieval engine and returns freshness', async () => {
    const { ctx, calls } = context(false);
    const result = await operationsByName.search.handler(ctx, {
      query: 'fixture',
      source_ids: ['source-a', 'source-b', 'source-a'],
    }) as SearchResult[];

    expect(calls).toHaveLength(1);
    expect(calls[0].sourceIds).toEqual(['source-a', 'source-b']);
    expect(calls[0].sourceId).toBeUndefined();
    expect(result[0].updated_at).toBe('2026-08-28T12:34:56.000Z');
  });

  test('remote callers cannot replace their server-assigned scope', async () => {
    const { ctx, calls } = context(true);
    await expect(operationsByName.search.handler(ctx, {
      query: 'fixture',
      source_ids: ['source-a'],
    })).rejects.toMatchObject({ code: 'permission_denied' });
    expect(calls).toHaveLength(0);
  });

  test('rejects malformed or conflicting exact scopes', async () => {
    const { ctx } = context(false);
    await expect(operationsByName.search.handler(ctx, {
      query: 'fixture',
      source_ids: ['NOT_VALID'],
    })).rejects.toMatchObject({ code: 'invalid_params' });

    await expect(operationsByName.query.handler(ctx, {
      query: 'fixture',
      source_id: 'source-a',
      source_ids: ['source-b'],
    })).rejects.toMatchObject({ code: 'invalid_params' });
  });

  test('accepts vectors locally and from the exact fleet-router OAuth identity', () => {
    const vector = [0.1, 0.2, 0.3];
    expect(normalizeTrustedQueryEmbedding(context(false).ctx, vector)).toHaveLength(3);
    expect(() => normalizeTrustedQueryEmbedding(
      context(true, 'brain-router-imekka-0123456789ab').ctx,
      vector,
    )).toThrow();
    expect(() => normalizeTrustedQueryEmbedding(
      context(true, 'brain-router-imekka-0123456789ab', 'ordinary_remote').ctx,
      vector,
    )).toThrow();
    expect(normalizeTrustedQueryEmbedding(
      context(true, 'brain-router-imekka-0123456789ab', 'fleet_router').ctx,
      vector,
    )).toHaveLength(3);
  });

  test('rejects vectors from ordinary remote clients and on width mismatch', () => {
    expect(() => normalizeTrustedQueryEmbedding(
      context(true, 'ordinary-client').ctx,
      [0.1, 0.2, 0.3],
    )).toThrow();
    expect(() => normalizeTrustedQueryEmbedding(context(false).ctx, [0.1, 0.2])).toThrow();
  });

  test('fleet router quality mode keeps reranking enabled with a 25-row-or-larger pool', async () => {
    const { ctx } = context(true, 'brain-router-imekka-0123456789ab', 'fleet_router');
    const mode = resolveSearchModeForCaller(ctx, 'balanced');
    const reranker = await resolvePrecomputedQueryReranker(ctx, mode, 10);

    expect(mode).toBe('balanced');
    expect(reranker.enabled).toBe(true);
    expect(reranker.topNIn).toBeGreaterThanOrEqual(25);
    expect(reranker.model).toBe('openrouter:voyageai/rerank-2.5-lite');
  });

  test('fleet router rejects conservative mode while ordinary remote mode stays ignored', () => {
    const fleet = context(true, 'brain-router-imekka-0123456789ab', 'fleet_router').ctx;
    const ordinary = context(true, 'ordinary-client').ctx;

    expect(() => resolveSearchModeForCaller(fleet, 'conservative')).toThrow();
    expect(resolveSearchModeForCaller(ordinary, 'balanced')).toBeUndefined();
  });

  test('remote ordinary search rejects a vector before retrieval', async () => {
    const { ctx, calls } = context(true, 'ordinary-client');
    await expect(operationsByName.search.handler(ctx, {
      query: 'fixture',
      query_embedding: [0.1, 0.2, 0.3],
    })).rejects.toMatchObject({ code: 'permission_denied' });
    expect(calls).toHaveLength(0);
  });

  test('fleet router may request the bounded keyword fallback', () => {
    const { ctx } = context(true, 'brain-router-imekka-0123456789ab', 'fleet_router');
    expect(normalizeFleetRouterKeywordFallback(ctx, true)).toBe(true);
  });

  test('ordinary remote clients cannot request the keyword fallback', () => {
    const { ctx } = context(true, 'ordinary-client');
    expect(() => normalizeFleetRouterKeywordFallback(ctx, true)).toThrow();
  });

  test('self-named DCR clients cannot request fleet-router controls', async () => {
    const { ctx } = context(
      true,
      'brain-router-imekka-0123456789ab',
      'ordinary_remote',
    );
    expect(() => normalizeFleetRouterKeywordFallback(ctx, true)).toThrow();
    expect(resolveSearchModeForCaller(ctx, 'balanced')).toBeUndefined();
    const reranker = await resolvePrecomputedQueryReranker(ctx, undefined, 10);
    expect(reranker.enabled).toBe(false);
    expect(reranker.topNIn).toBe(10);
  });

  test('search emits private capture bindings only for the authenticated fleet router', async () => {
    const fleet = context(true, 'brain-router-owner-0123456789ab', 'fleet_router');
    const fleetResults = await operationsByName.search.handler(fleet.ctx, {
      query: 'fixture',
    }) as SearchResult[];
    expect((fleetResults[0] as SearchResult & { fact_bindings?: unknown[] }).fact_bindings).toHaveLength(1);

    const ordinary = context(true, 'ordinary-client');
    const ordinaryResults = await operationsByName.search.handler(ordinary.ctx, {
      query: 'fixture',
    }) as SearchResult[];
    expect((ordinaryResults[0] as SearchResult & { fact_bindings?: unknown[] }).fact_bindings).toBeUndefined();

    const selfNamedDcr = context(
      true,
      'brain-router-owner-0123456789ab',
      'ordinary_remote',
    );
    const dcrResults = await operationsByName.search.handler(selfNamedDcr.ctx, {
      query: 'fixture',
    }) as SearchResult[];
    expect((dcrResults[0] as SearchResult & { fact_bindings?: unknown[] }).fact_bindings).toBeUndefined();
  });
});
