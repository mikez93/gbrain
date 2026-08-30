import { describe, expect, test } from 'bun:test';
import { operationsByName, type OperationContext } from '../src/core/operations.ts';

describe('fleet grant never widens source authority', () => {
  test('get_page/search/text-query/image-query deny out-of-grant sources before every backend and without an identifier oracle', async () => {
    const calls = { page: 0, keyword: 0, vector: 0, raw: 0 };
    const engine = {
      getConfig: async () => null,
      getPage: async () => { calls.page += 1; throw new Error('page backend must not run'); },
      searchKeyword: async () => { calls.keyword += 1; throw new Error('keyword backend must not run'); },
      searchVector: async () => { calls.vector += 1; throw new Error('vector backend must not run'); },
      executeRaw: async () => { calls.raw += 1; throw new Error('binding SQL must not run'); },
    };
    const ctx = {
      engine,
      config: { embedding_dimensions: 3 },
      logger: { info() {}, warn() {}, error() {}, debug() {} },
      dryRun: false,
      remote: true,
      sourceId: 'source-a',
      auth: {
        token: 'fixture',
        clientId: 'fleet-source-scope',
        scopes: ['read'],
        sourceId: 'source-a',
        allowedSources: ['source-a'],
        fleetGrant: 'fleet_router',
        fleetGrantVersion: 1,
        fleetGrantSetBy: 'operator',
        fleetGrantSetAt: '2026-08-29T12:00:00.000Z',
      },
    } as unknown as OperationContext;
    const privateSource = 'source-b';
    const privateSlug = 'private-target-do-not-echo';
    const attempts: Array<() => Promise<unknown>> = [
      () => operationsByName.get_page.handler(ctx, { slug: privateSlug, source_id: privateSource }),
      () => operationsByName.search.handler(ctx, { query: privateSlug, source_ids: [privateSource] }),
      () => operationsByName.query.handler(ctx, { query: privateSlug, source_id: privateSource }),
      () => operationsByName.query.handler(ctx, {
        image: 'cHJpdmF0ZS10YXJnZXQ=',
        image_mime: 'image/png',
        source_id: privateSource,
      }),
    ];
    for (const attempt of attempts) {
      let thrown: unknown;
      try {
        await attempt();
      } catch (error) {
        thrown = error;
      }
      expect(thrown).toMatchObject({ code: 'permission_denied' });
      const serialized = JSON.stringify(thrown);
      expect(serialized).not.toContain(privateSource);
      expect(serialized).not.toContain(privateSlug);
    }
    expect(calls).toEqual({ page: 0, keyword: 0, vector: 0, raw: 0 });
  });
});
