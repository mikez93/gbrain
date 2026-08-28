import { describe, expect, test } from 'bun:test';
import { operationsByName, type OperationContext } from '../src/core/operations.ts';
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

function context(remote: boolean): { ctx: OperationContext; calls: SearchOpts[] } {
  const calls: SearchOpts[] = [];
  const engine = {
    getConfig: async (key: string) => key === 'search.mcp_keyword_only' ? 'true' : null,
    searchKeyword: async (_query: string, opts: SearchOpts) => {
      calls.push(opts);
      return [{ ...row }];
    },
    executeRaw: async (sql: string) => {
      if (sql.startsWith('SELECT id, updated_at FROM pages')) {
        return [{ id: 7, updated_at: new Date('2026-08-28T12:34:56.000Z') }];
      }
      return [];
    },
  };
  return {
    calls,
    ctx: {
      engine,
      config: {},
      logger: { info() {}, warn() {}, error() {}, debug() {} },
      dryRun: false,
      remote,
      sourceId: 'default',
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
});
