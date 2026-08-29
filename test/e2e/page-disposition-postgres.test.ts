/** Real-Postgres parity gate for reversible page dispositions. */

import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import {
  getPageDisposition,
  reverseDispositionBatch,
  setDispositionBatch,
} from '../../src/core/disposition/service.ts';
import { getEngine, hasDatabase, setupDB, teardownDB } from './helpers.ts';

const RUN = hasDatabase();
const d = RUN ? describe : describe.skip;

beforeAll(async () => {
  if (!RUN) return;
  const engine = await setupDB();
  await engine.initSchema();
  await engine.executeRaw(
    `TRUNCATE page_dispositions, page_disposition_events,
              page_disposition_operations, page_disposition_state CASCADE`,
  );
  await engine.executeRaw(
    `INSERT INTO page_disposition_state (id, generation) VALUES (1, 0)`,
  );
});

afterAll(async () => {
  if (RUN) await teardownDB();
});

d('page dispositions on real Postgres', () => {
  test('applies, replays, filters, reads back, and reverses one cross-source batch', async () => {
    const engine = getEngine();
    await engine.executeRaw(
      `INSERT INTO sources (id, name, config)
       VALUES ('capture', 'capture', '{}'::jsonb)
       ON CONFLICT (id) DO NOTHING`,
    );
    await engine.putPage('fixtures/current-policy', {
      type: 'concept',
      title: 'Current policy',
      compiled_truth: 'distinctive reversible disposition postgres fixture',
      timeline: '',
    }, { sourceId: 'default' });
    await engine.putPage('fixtures/captured-draft', {
      type: 'concept',
      title: 'Captured draft',
      compiled_truth: 'distinctive reversible disposition postgres fixture',
      timeline: '',
    }, { sourceId: 'capture' });
    for (const [sourceId, slug] of [
      ['default', 'fixtures/current-policy'],
      ['capture', 'fixtures/captured-draft'],
    ] as const) {
      await engine.upsertChunks(slug, [{
        chunk_index: 0,
        chunk_text: 'distinctive reversible disposition postgres fixture',
        chunk_source: 'compiled_truth',
        token_count: 5,
      }], { sourceId });
    }

    const request = {
      actor: 'kepler' as const,
      reason: 'real postgres cross-source parity fixture',
      idempotencyKey: 'postgres-cross-source-batch-1',
      items: [{
        kind: 'duplicate_set' as const,
        sourceId: 'default',
        canonicalSlug: 'fixtures/current-policy',
        superseded: [{ sourceId: 'capture', slug: 'fixtures/captured-draft' }],
      }],
    };
    const created = await setDispositionBatch(engine, request);
    const replay = await setDispositionBatch(engine, request);
    expect(created.kind).toBe('set_batch');
    expect(created.events).toHaveLength(2);
    expect(replay.operation_uuid).toBe(created.operation_uuid);
    expect(replay.idempotent_replay).toBe(true);

    const captured = await getPageDisposition(engine, {
      sourceId: 'capture', slug: 'fixtures/captured-draft',
    });
    expect(captured.projection.state).toBe('superseded');
    expect(captured.projection.canonical).toMatchObject({
      source_id: 'default', slug: 'fixtures/current-policy',
    });

    const competing = await engine.searchKeyword('distinctive reversible disposition postgres fixture', {
      limit: 10,
      dispositionScope: 'competing',
    });
    expect(competing.map(result => result.slug)).toEqual(['fixtures/current-policy']);
    const curation = await engine.searchKeyword('distinctive reversible disposition postgres fixture', {
      limit: 10,
      dispositionScope: 'curation',
    });
    expect(new Set(curation.map(result => result.slug))).toEqual(new Set([
      'fixtures/current-policy', 'fixtures/captured-draft',
    ]));

    await expect(engine.executeRaw(
      `UPDATE page_disposition_events SET event_kind = 'reverse'`,
    )).rejects.toThrow(/append-only/);

    const reversed = await reverseDispositionBatch(engine, {
      actor: 'kepler',
      operationUuid: created.operation_uuid,
      reason: 'real postgres parity fixture reversal',
      idempotencyKey: 'postgres-cross-source-batch-reverse-1',
    });
    expect(reversed.kind).toBe('reverse_batch');
    expect(reversed.events).toHaveLength(2);
    expect(reversed.events.every(event => event.resulting_state === 'undispositioned')).toBe(true);
    expect((await getPageDisposition(engine, {
      sourceId: 'capture', slug: 'fixtures/captured-draft',
    })).projection.state).toBe('undispositioned');
  }, 120_000);
});
