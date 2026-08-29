import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { PGLiteEngine } from '../src/core/pglite-engine.ts';
import { operationsByName } from '../src/core/operations.ts';
import type { OperationContext } from '../src/core/operations.ts';
import { resetPgliteState } from './helpers/reset-pglite.ts';
import {
  getPageDisposition,
  listPageDispositions,
  reverseDispositionBatch,
  reverseDuplicateSet,
  setDispositionBatch,
  setDuplicateSet,
  setPageDisposition,
} from '../src/core/disposition/service.ts';

let engine: PGLiteEngine;

beforeAll(async () => {
  engine = new PGLiteEngine();
  await engine.connect({});
  await engine.initSchema();
}, 120_000);

afterAll(async () => {
  await engine.disconnect();
});

beforeEach(async () => {
  await resetPgliteState(engine);
});

async function seedPages(...slugs: string[]) {
  for (const slug of slugs) {
    await engine.putPage(slug, {
      type: 'concept',
      title: slug.split('/').at(-1) ?? slug,
      compiled_truth: `shared disposition fixture ${slug}`,
      timeline: '',
    }, { sourceId: 'default' });
  }
}

const actor = 'kepler' as const;

function dispositionContext(overrides: Partial<OperationContext> = {}): OperationContext {
  return {
    engine,
    config: {},
    logger: { info: () => {}, warn: () => {}, error: () => {} },
    dryRun: false,
    remote: true,
    transport: 'http',
    sourceId: 'default',
    auth: {
      token: 'test-token',
      clientId: 'kepler-test-client',
      clientName: 'kepler',
      scopes: ['write'],
      sourceId: 'default',
    },
    ...overrides,
  } as OperationContext;
}

describe('page disposition ledger', () => {
  test('creates one canonical plus superseded members atomically', async () => {
    await seedPages('fixtures/canonical', 'fixtures/duplicate-a', 'fixtures/duplicate-b');

    const receipt = await setDuplicateSet(engine, {
      actor,
      sourceId: 'default',
      canonicalSlug: 'fixtures/canonical',
      supersededSlugs: ['fixtures/duplicate-a', 'fixtures/duplicate-b'],
      reason: 'verified duplicate fixture',
      idempotencyKey: 'set-fixture-1',
    });

    expect(receipt.idempotent_replay).toBe(false);
    expect(receipt.events).toHaveLength(3);
    expect(receipt.projections.filter(p => p.state === 'canonical')).toHaveLength(1);
    expect(receipt.projections.filter(p => p.state === 'superseded')).toHaveLength(2);
    expect(new Set(receipt.projections.map(p => p.duplicate_set_id))).toEqual(
      new Set([receipt.projections[0]!.duplicate_set_id]),
    );

    const listed = await listPageDispositions(engine, { sourceId: 'default', limit: 20 });
    expect(listed.items).toHaveLength(3);
    expect(listed.generation).toBe(1);
  });

  test('same idempotency key replays; a different request conflicts', async () => {
    await seedPages('fixtures/canonical', 'fixtures/duplicate');
    const request = {
      actor,
      sourceId: 'default',
      canonicalSlug: 'fixtures/canonical',
      supersededSlugs: ['fixtures/duplicate'],
      reason: 'verified duplicate fixture',
      idempotencyKey: 'set-fixture-replay',
    } as const;

    const first = await setDuplicateSet(engine, request);
    const replay = await setDuplicateSet(engine, request);
    expect(replay.operation_uuid).toBe(first.operation_uuid);
    expect(replay.idempotent_replay).toBe(true);
    expect(replay.events.map(e => e.event_uuid)).toEqual(first.events.map(e => e.event_uuid));

    await expect(setDuplicateSet(engine, {
      ...request,
      reason: 'different normalized request',
    })).rejects.toMatchObject({ code: 'idempotency_conflict' });

    const generation = await engine.executeRaw<{ generation: number }>(
      `SELECT generation FROM page_disposition_state WHERE id = 1`,
    );
    expect(Number(generation[0]!.generation)).toBe(1);
  });

  test('reversal reconstructs members and restores their prior states', async () => {
    await seedPages('fixtures/canonical', 'fixtures/duplicate');
    const created = await setDuplicateSet(engine, {
      actor,
      sourceId: 'default',
      canonicalSlug: 'fixtures/canonical',
      supersededSlugs: ['fixtures/duplicate'],
      reason: 'verified duplicate fixture',
      idempotencyKey: 'set-fixture-reverse',
    });

    const reversed = await reverseDuplicateSet(engine, {
      actor,
      operationUuid: created.operation_uuid,
      reason: 'fixture reversal',
      idempotencyKey: 'reverse-fixture-1',
    });
    expect(reversed.events).toHaveLength(2);
    expect(reversed.events.every(e => e.resulting_state === 'undispositioned')).toBe(true);
    expect(reversed.projections).toHaveLength(0);
    expect((await getPageDisposition(engine, {
      sourceId: 'default', slug: 'fixtures/canonical', historyLimit: 10,
    })).projection.state).toBe('undispositioned');
  });

  test('rejects a bare canonical reversal while superseded members depend on it', async () => {
    await seedPages('fixtures/canonical', 'fixtures/duplicate');
    const created = await setDuplicateSet(engine, {
      actor,
      sourceId: 'default',
      canonicalSlug: 'fixtures/canonical',
      supersededSlugs: ['fixtures/duplicate'],
      reason: 'verified duplicate fixture',
      idempotencyKey: 'set-fixture-dependent',
    });
    const canonicalEvent = created.events.find(e => e.slug === 'fixtures/canonical')!;

    const { reversePageDisposition } = await import('../src/core/disposition/service.ts');
    await expect(reversePageDisposition(engine, {
      actor,
      sourceId: 'default',
      slug: 'fixtures/canonical',
      eventId: canonicalEvent.event_id,
      reason: 'invalid partial reversal',
      idempotencyKey: 'reverse-fixture-dependent',
    })).rejects.toMatchObject({ code: 'canonical_has_dependents' });
  });

  test('prevents ledger mutation and hard deletion of referenced pages', async () => {
    await seedPages('fixtures/quarantined');
    await setPageDisposition(engine, {
      actor,
      sourceId: 'default',
      slug: 'fixtures/quarantined',
      state: 'quarantined',
      reason: 'fixture quarantine',
      idempotencyKey: 'quarantine-fixture-1',
    });

    await expect(engine.executeRaw(`UPDATE page_disposition_events SET event_kind = 'reverse'`))
      .rejects.toThrow(/append-only/);
    await expect(engine.executeRaw(`DELETE FROM page_disposition_operations`))
      .rejects.toThrow(/append-only/);
    await expect(engine.executeRaw(`DELETE FROM pages WHERE slug = 'fixtures/quarantined'`))
      .rejects.toThrow();
  });

  test('creates and reverses a cross-source duplicate set inside one brain', async () => {
    await engine.executeRaw(
      `INSERT INTO sources (id, name, config) VALUES ('other', 'other', '{}'::jsonb)`,
    );
    await seedPages('fixtures/canonical');
    await engine.putPage('fixtures/duplicate', {
      type: 'concept', title: 'duplicate', compiled_truth: 'duplicate fixture', timeline: '',
    }, { sourceId: 'other' });

    const created = await setDuplicateSet(engine, {
      actor,
      sourceId: 'default',
      canonicalSlug: 'fixtures/canonical',
      superseded: [{ sourceId: 'other', slug: 'fixtures/duplicate' }],
      reason: 'verified cross-source set',
      idempotencyKey: 'cross-source-fixture-1',
    });
    expect(created.events).toHaveLength(2);
    const duplicate = await getPageDisposition(engine, {
      sourceId: 'other', slug: 'fixtures/duplicate',
    });
    expect(duplicate.projection.state).toBe('superseded');
    expect(duplicate.projection.canonical).toMatchObject({
      source_id: 'default', slug: 'fixtures/canonical',
    });

    const reversed = await reverseDuplicateSet(engine, {
      actor,
      operationUuid: created.operation_uuid,
      reason: 'verified cross-source reversal',
      idempotencyKey: 'cross-source-fixture-reverse-1',
    });
    expect(reversed.events.every(event => event.resulting_state === 'undispositioned')).toBe(true);
  });

  test('applies and reverses 160 pages across 33 groups with one receipt per batch', async () => {
    const items: Array<{
      kind: 'duplicate_set';
      sourceId: string;
      canonicalSlug: string;
      supersededSlugs: string[];
    }> = [];
    const allSlugs: string[] = [];
    for (let group = 0; group < 33; group += 1) {
      const memberCount = group < 28 ? 5 : 4;
      const slugs = Array.from(
        { length: memberCount },
        (_, member) => `batch/group-${group}/member-${member}`,
      );
      allSlugs.push(...slugs);
      items.push({
        kind: 'duplicate_set',
        sourceId: 'default',
        canonicalSlug: slugs[0]!,
        supersededSlugs: slugs.slice(1),
      });
    }
    expect(allSlugs).toHaveLength(160);
    await seedPages(...allSlugs);

    const created = await setDispositionBatch(engine, {
      actor,
      items,
      reason: 'bounded fleet-scale fixture batch',
      idempotencyKey: 'batch-fixture-160-pages',
    });
    expect(created.kind).toBe('set_batch');
    expect(created.events).toHaveLength(160);
    expect(created.projections).toHaveLength(160);
    expect(created.projections.filter(item => item.state === 'canonical')).toHaveLength(33);

    const replay = await setDispositionBatch(engine, {
      actor,
      items,
      reason: 'bounded fleet-scale fixture batch',
      idempotencyKey: 'batch-fixture-160-pages',
    });
    expect(replay.idempotent_replay).toBe(true);
    expect(replay.operation_uuid).toBe(created.operation_uuid);

    const reversed = await reverseDispositionBatch(engine, {
      actor,
      operationUuid: created.operation_uuid,
      reason: 'fleet-scale fixture batch reversal',
      idempotencyKey: 'reverse-batch-fixture-160-pages',
    });
    expect(reversed.kind).toBe('reverse_batch');
    expect(reversed.events).toHaveLength(160);
    expect(reversed.events.every(event => event.resulting_state === 'undispositioned')).toBe(true);
    expect(reversed.projections).toHaveLength(0);

    const operationRows = await engine.executeRaw<{ n: number }>(
      `SELECT COUNT(*)::int AS n FROM page_disposition_operations`,
    );
    const generationRows = await engine.executeRaw<{ generation: number }>(
      `SELECT generation FROM page_disposition_state WHERE id = 1`,
    );
    expect(Number(operationRows[0]!.n)).toBe(2);
    expect(Number(generationRows[0]!.generation)).toBe(2);
  }, 120_000);

  test('rolls back the complete batch when any requested page is missing', async () => {
    await seedPages('batch/valid-canonical', 'batch/valid-duplicate');
    await expect(setDispositionBatch(engine, {
      actor,
      reason: 'atomic failure fixture',
      idempotencyKey: 'batch-atomic-failure',
      items: [
        {
          kind: 'duplicate_set', sourceId: 'default',
          canonicalSlug: 'batch/valid-canonical', supersededSlugs: ['batch/valid-duplicate'],
        },
        { kind: 'page', sourceId: 'default', slug: 'batch/missing', state: 'quarantined' },
      ],
    })).rejects.toMatchObject({ code: 'page_not_found' });

    const rows = await engine.executeRaw<{ n: number }>(
      `SELECT COUNT(*)::int AS n FROM page_disposition_operations`,
    );
    expect(Number(rows[0]!.n)).toBe(0);
  });

  test('registers the exact authenticated owner-curation operation catalog', () => {
    const names = [
      'set_page_disposition',
      'set_duplicate_set',
      'set_disposition_batch',
      'reverse_page_disposition',
      'reverse_duplicate_set',
      'reverse_disposition_batch',
      'get_page_disposition',
      'list_page_dispositions',
    ];
    for (const name of names) {
      expect(operationsByName[name]).toBeDefined();
      expect(operationsByName[name]!.area).toBe('dispositions');
    }
    expect(names.filter(name => operationsByName[name]!.scope === 'write')).toHaveLength(6);
    expect(names.filter(name => operationsByName[name]!.scope === 'read')).toHaveLength(2);
  });

  test('accepts prepared owner page-ID records directly with derived apply and reversal idempotency', async () => {
    await engine.executeRaw(
      `INSERT INTO sources (id, name, config) VALUES ('capture', 'capture', '{}'::jsonb)`,
    );
    await seedPages('prepared/canonical');
    await engine.putPage('prepared/capture', {
      type: 'concept', title: 'captured draft', compiled_truth: 'captured draft fixture', timeline: '',
    }, { sourceId: 'capture' });
    const pages = await engine.executeRaw<{ id: number; source_id: string }>(
      `SELECT id, source_id FROM pages WHERE slug IN ('prepared/canonical', 'prepared/capture')`,
    );
    const canonicalId = Number(pages.find(page => page.source_id === 'default')!.id);
    const captureId = Number(pages.find(page => page.source_id === 'capture')!.id);
    const records = [{
      priority: 1,
      value_class: 'same-logical duplicate pair',
      page_ids: [String(canonicalId), String(captureId)],
      disposition: {
        operation: 'set_duplicate_set',
        canonical_page_id: String(canonicalId),
        superseded_page_ids: [String(captureId)],
        duplicate_set_key: 'prepared-cross-source-fixture',
      },
      set_idempotency_key: 'prepared-set-cross-source-1',
      reversal_idempotency_key: 'prepared-reverse-cross-source-1',
      proof_query: 'prepared owner fixture',
      preconditions: ['fixture checked'],
      emit_mutation: true,
      executed: false,
    }];

    const created = await operationsByName.set_disposition_batch!.handler(dispositionContext(), {
      records,
      reason: 'prepared owner fixture apply',
    }) as { operation_uuid: string; idempotent_replay: boolean; events: unknown[] };
    expect(created.idempotent_replay).toBe(false);
    expect(created.events).toHaveLength(2);
    const replay = await operationsByName.set_disposition_batch!.handler(dispositionContext(), {
      records,
      reason: 'prepared owner fixture apply',
    }) as { operation_uuid: string; idempotent_replay: boolean };
    expect(replay.operation_uuid).toBe(created.operation_uuid);
    expect(replay.idempotent_replay).toBe(true);

    const duplicate = await getPageDisposition(engine, {
      sourceId: 'capture', slug: 'prepared/capture',
    });
    expect(duplicate.projection.canonical).toMatchObject({
      page_id: canonicalId, source_id: 'default', slug: 'prepared/canonical',
    });

    const reversed = await operationsByName.reverse_disposition_batch!.handler(dispositionContext(), {
      operation_uuid: created.operation_uuid,
      records,
      reason: 'prepared owner fixture reversal',
    }) as { events: Array<{ resulting_state: string }> };
    expect(reversed.events.every(event => event.resulting_state === 'undispositioned')).toBe(true);
  });

  test('derives actor and source from authenticated context and rejects payload spoofing', async () => {
    await seedPages('ops/canonical', 'ops/duplicate');
    const receipt = await operationsByName.set_duplicate_set!.handler(dispositionContext(), {
      source_id: 'default',
      canonical_slug: 'ops/canonical',
      superseded_slugs: ['ops/duplicate'],
      reason: 'authenticated operation fixture',
      idempotency_key: 'authenticated-operation-fixture',
    }) as { actor: string; events: unknown[] };
    expect(receipt.actor).toBe('kepler');
    expect(receipt.events).toHaveLength(2);

    await expect(operationsByName.set_page_disposition!.handler(dispositionContext(), {
      actor: 'vector',
      source_id: 'default',
      slug: 'ops/canonical',
      state: 'quarantined',
      reason: 'spoof attempt',
      idempotency_key: 'spoof-attempt',
    })).rejects.toMatchObject({ code: 'permission_denied' });
    await expect(operationsByName.get_page_disposition!.handler(dispositionContext({
      auth: {
        token: 'test-token', clientId: 'other-client', clientName: 'other',
        scopes: ['write'], sourceId: 'default',
      },
    }), {
      source_id: 'default', slug: 'ops/canonical',
    })).rejects.toMatchObject({ code: 'permission_denied' });
    await expect(operationsByName.get_page_disposition!.handler(dispositionContext(), {
      source_id: 'other', slug: 'ops/canonical',
    })).rejects.toMatchObject({ code: 'page_not_found' });
  });

  test('filters before keyword limits, stamps metadata, and gates curation scope', async () => {
    await seedPages('search/canonical', 'search/superseded', 'search/quarantined');
    for (const slug of ['search/canonical', 'search/superseded', 'search/quarantined']) {
      await engine.upsertChunks(slug, [{
        chunk_index: 0,
        chunk_text: `shared disposition fixture ${slug}`,
        chunk_source: 'compiled_truth',
        token_count: 4,
      }], { sourceId: 'default' });
    }
    await setDuplicateSet(engine, {
      actor,
      sourceId: 'default',
      canonicalSlug: 'search/canonical',
      supersededSlugs: ['search/superseded'],
      reason: 'search visibility fixture',
      idempotencyKey: 'search-visibility-set',
    });
    await setPageDisposition(engine, {
      actor,
      sourceId: 'default',
      slug: 'search/quarantined',
      state: 'quarantined',
      reason: 'search visibility fixture',
      idempotencyKey: 'search-visibility-quarantine',
    });
    await engine.setConfig('search.mcp_keyword_only', 'true');

    const competing = await operationsByName.search!.handler(dispositionContext(), {
      query: 'shared disposition fixture',
      limit: 20,
    }) as Array<{ slug: string; disposition?: { state: string } }>;
    expect(competing.map(result => result.slug)).toEqual(['search/canonical']);
    expect(competing[0]!.disposition?.state).toBe('canonical');

    const curation = await operationsByName.search!.handler(dispositionContext(), {
      query: 'shared disposition fixture',
      disposition_scope: 'curation',
      limit: 20,
    }) as Array<{ slug: string; disposition?: { state: string } }>;
    expect(new Set(curation.map(result => result.slug))).toEqual(new Set([
      'search/canonical', 'search/superseded', 'search/quarantined',
    ]));
    expect(new Set(curation.map(result => result.disposition?.state))).toEqual(new Set([
      'canonical', 'superseded', 'quarantined',
    ]));

    await expect(operationsByName.search!.handler(dispositionContext({
      auth: {
        token: 'test-token', clientId: 'other-client', clientName: 'other',
        scopes: ['read'], sourceId: 'default',
      },
    }), {
      query: 'shared disposition fixture', disposition_scope: 'curation',
    })).rejects.toMatchObject({ code: 'permission_denied' });
  });
});
