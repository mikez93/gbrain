import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PGLiteEngine } from '../src/core/pglite-engine.ts';
import { configureGateway, resetGateway, __setChatTransportForTests } from '../src/core/ai/gateway.ts';
import { runFactsBackstop } from '../src/core/facts/backstop.ts';
import { factPageBindingsFor, loadFactPageBindings } from '../src/core/facts/page-bindings.ts';
import { markShortLivedCliProcess, __resetShortLivedCliForTests } from '../src/core/facts/cli-process-mode.ts';
import { registerBuiltinHandlers } from '../src/commands/jobs.ts';
import type { BrainEngine } from '../src/core/engine.ts';

let engine: PGLiteEngine;
let tmpHome: string;
const savedEnv = {
  ANTHROPIC_API_KEY: process.env.ANTHROPIC_API_KEY,
  GBRAIN_HOME: process.env.GBRAIN_HOME,
};

const body = 'A substantive capture turn. ' +
  'Enough prose to clear the facts backstop eligibility threshold. '.repeat(4);

function extractorResult(fact: string, entity: string | null = null) {
  return {
    text: JSON.stringify({
      facts: [{ fact, kind: 'fact', entity, confidence: 0.9, notability: 'high' }],
    }),
    blocks: [{ type: 'text' as const, text: fact }],
    stopReason: 'end' as const,
    usage: { input_tokens: 1, output_tokens: 1, cache_read_tokens: 0, cache_creation_tokens: 0 },
    model: 'anthropic:claude-sonnet-4-6',
    providerId: 'anthropic',
  };
}

function enableExtractor(fact: string, entity: string | null = null): void {
  process.env.ANTHROPIC_API_KEY = 'sk-ant-lineage-test';
  configureGateway({
    chat_model: 'anthropic:claude-sonnet-4-6',
    env: { ...process.env, ANTHROPIC_API_KEY: 'sk-ant-lineage-test' },
  });
  __setChatTransportForTests(async () => extractorResult(fact, entity));
}

beforeAll(async () => {
  tmpHome = mkdtempSync(join(tmpdir(), 'gbrain-facts-lineage-'));
  process.env.GBRAIN_HOME = tmpHome;
  engine = new PGLiteEngine();
  await engine.connect({});
  await engine.initSchema();
  await engine.setConfig('facts.extraction_model', 'anthropic:claude-sonnet-4-6');
});

beforeEach(async () => {
  __resetShortLivedCliForTests();
  resetGateway();
  __setChatTransportForTests(null);
  await engine.executeRaw("DELETE FROM minion_jobs WHERE name = 'facts-absorb'");
  await engine.executeRaw("DELETE FROM facts WHERE fact LIKE 'lineage-test:%'");
});

afterAll(async () => {
  __setChatTransportForTests(null);
  resetGateway();
  await engine.disconnect();
  rmSync(tmpHome, { recursive: true, force: true });
  if (savedEnv.ANTHROPIC_API_KEY === undefined) delete process.env.ANTHROPIC_API_KEY;
  else process.env.ANTHROPIC_API_KEY = savedEnv.ANTHROPIC_API_KEY;
  if (savedEnv.GBRAIN_HOME === undefined) delete process.env.GBRAIN_HOME;
  else process.env.GBRAIN_HOME = savedEnv.GBRAIN_HOME;
});

describe('mcp:put_page fact capture lineage', () => {
  test('inline derives the exact capture page and Hermes session from the page', async () => {
    const fact = 'lineage-test:inline-derived';
    const captureSlug = 'daily/hermes/owner-a/0123456789abcdef0123/turn-a';
    const sessionRef = '0123456789abcdef0123';
    enableExtractor(fact);

    const result = await runFactsBackstop(
      {
        slug: captureSlug,
        type: 'note',
        compiled_truth: body,
        frontmatter: { hermes_session_ref: sessionRef },
      },
      {
        engine: engine as BrainEngine,
        sourceId: 'default',
        sessionId: null,
        source: 'mcp:put_page',
        mode: 'inline',
      },
    );
    expect(result.mode).toBe('inline');
    expect((result as { inserted: number }).inserted).toBe(1);
    const [row] = await engine.executeRaw<{
      context: string;
      source_session: string;
      source_markdown_slug: string | null;
    }>(
      'SELECT context, source_session, source_markdown_slug FROM facts WHERE fact = $1',
      [fact],
    );
    expect(row.context).toBe(captureSlug);
    expect(row.source_session).toBe(sessionRef);
    expect(row.source_markdown_slug).toBeNull();
    const bindings = await loadFactPageBindings(
      engine,
      [{ sourceId: 'default', slug: captureSlug }],
      { authorized: true },
    );
    expect(factPageBindingsFor(bindings, 'default', captureSlug)).toContainEqual({
      fact_id: expect.any(Number),
      capture_page_slug: captureSlug,
      hermes_session_ref: sessionRef,
      matched_via: 'capture_page',
    });
  });

  test('explicit non-put-page caller lineage wins over page frontmatter', async () => {
    const fact = 'lineage-test:explicit-wins';
    enableExtractor(fact);
    await runFactsBackstop(
      {
        slug: 'imports/owner-b/page-a',
        type: 'note',
        compiled_truth: body,
        frontmatter: { hermes_session_ref: 'aaaaaaaaaaaaaaaaaaaa' },
      },
      {
        engine: engine as BrainEngine,
        sourceId: 'default',
        sessionId: 'bbbbbbbbbbbbbbbbbbbb',
        sourceSlug: 'imports/owner-b/exact-origin',
        source: 'sync:import',
        mode: 'inline',
      },
    );
    const [row] = await engine.executeRaw<{ context: string; source_session: string }>(
      'SELECT context, source_session FROM facts WHERE fact = $1',
      [fact],
    );
    expect(row.context).toBe('imports/owner-b/exact-origin');
    expect(row.source_session).toBe('bbbbbbbbbbbbbbbbbbbb');
  });

  test('durable queued payload carries the exact capture page and session', async () => {
    const captureSlug = 'daily/hermes/owner-c/cccccccccccccccccccc/turn-c';
    const sessionRef = 'cccccccccccccccccccc';
    markShortLivedCliProcess();
    const result = await runFactsBackstop(
      {
        slug: captureSlug,
        type: 'note',
        compiled_truth: body,
        frontmatter: { hermes_session_ref: sessionRef },
      },
      {
        engine: engine as BrainEngine,
        sourceId: 'default',
        sessionId: null,
        source: 'mcp:put_page',
        mode: 'queue',
      },
    );
    expect(result).toMatchObject({ mode: 'queue', enqueued: true });
    const [row] = await engine.executeRaw<{ data: Record<string, unknown> | string }>(
      "SELECT data FROM minion_jobs WHERE name = 'facts-absorb'",
    );
    const data = typeof row.data === 'string' ? JSON.parse(row.data) : row.data;
    expect(data.sourceSlug).toBe(captureSlug);
    expect(data.sessionId).toBe(sessionRef);
  });

  test('durable retries deduplicate only identical normalized lineage', async () => {
    const captureSlug = 'daily/hermes/owner-idem/11111111111111111111/turn-a';
    const sessionRef = '11111111111111111111';
    markShortLivedCliProcess();
    const enqueue = (sourceSlug: string, sessionId: string) => runFactsBackstop(
      {
        slug: captureSlug,
        type: 'note',
        compiled_truth: body,
        frontmatter: { hermes_session_ref: sessionRef },
      },
      {
        engine: engine as BrainEngine,
        sourceId: 'default',
        sessionId,
        sourceSlug,
        source: 'mcp:put_page',
        mode: 'queue',
      },
    );

    await enqueue(`  ${captureSlug}  `, `  ${sessionRef}  `);
    await enqueue(captureSlug, sessionRef);

    const rows = await engine.executeRaw<{
      id: number;
      idempotency_key: string;
      data: Record<string, unknown> | string;
    }>(
      "SELECT id, idempotency_key, data FROM minion_jobs WHERE name = 'facts-absorb' ORDER BY id",
    );
    expect(rows).toHaveLength(1);
    const data = typeof rows[0].data === 'string' ? JSON.parse(rows[0].data) : rows[0].data;
    expect(data).toMatchObject({ sourceSlug: captureSlug, sessionId: sessionRef });
    expect(rows[0].idempotency_key).toMatch(/:[0-9a-f]{64}$/);
  });

  test('same body with changed source slug or session creates fresh durable jobs', async () => {
    const captureSlug = 'daily/hermes/owner-idem/22222222222222222222/turn-a';
    const sessionRef = '22222222222222222222';
    markShortLivedCliProcess();
    const enqueue = (sourceSlug: string, sessionId: string) => runFactsBackstop(
      {
        slug: captureSlug,
        type: 'note',
        compiled_truth: body,
        frontmatter: { hermes_session_ref: sessionRef },
      },
      {
        engine: engine as BrainEngine,
        sourceId: 'default',
        sessionId,
        sourceSlug,
        source: 'mcp:put_page',
        mode: 'queue',
      },
    );

    await enqueue(captureSlug, sessionRef);
    await enqueue(`${captureSlug}-moved`, sessionRef);
    await enqueue(captureSlug, '33333333333333333333');

    const rows = await engine.executeRaw<{ idempotency_key: string }>(
      "SELECT idempotency_key FROM minion_jobs WHERE name = 'facts-absorb' ORDER BY id",
    );
    expect(rows).toHaveLength(3);
    expect(new Set(rows.map((row) => row.idempotency_key)).size).toBe(3);
  });

  test('terminal jobs preserve exact-retry semantics without swallowing changed lineage', async () => {
    const captureSlug = 'daily/hermes/owner-idem/44444444444444444444/turn-a';
    const sessionRef = '44444444444444444444';
    markShortLivedCliProcess();
    const enqueue = (sourceSlug: string, sessionId: string) => runFactsBackstop(
      {
        slug: captureSlug,
        type: 'note',
        compiled_truth: body,
        frontmatter: { hermes_session_ref: sessionRef },
      },
      {
        engine: engine as BrainEngine,
        sourceId: 'default',
        sessionId,
        sourceSlug,
        source: 'mcp:put_page',
        mode: 'queue',
      },
    );

    await enqueue(captureSlug, sessionRef);
    const [first] = await engine.executeRaw<{ id: number }>(
      "SELECT id FROM minion_jobs WHERE name = 'facts-absorb'",
    );
    await engine.executeRaw(
      "UPDATE minion_jobs SET status = 'completed', finished_at = now() WHERE id = $1",
      [first.id],
    );
    await enqueue(captureSlug, sessionRef);
    expect(await engine.executeRaw(
      "SELECT id FROM minion_jobs WHERE name = 'facts-absorb'",
    )).toHaveLength(1);

    await enqueue(captureSlug, '55555555555555555555');
    const rows = await engine.executeRaw<{ id: number; status: string }>(
      "SELECT id, status FROM minion_jobs WHERE name = 'facts-absorb' ORDER BY id",
    );
    expect(rows).toHaveLength(2);
    expect(rows.map((row) => row.status)).toEqual(['completed', 'waiting']);

    await engine.executeRaw(
      "UPDATE minion_jobs SET status = 'failed', finished_at = now() WHERE id = $1",
      [rows[1].id],
    );
    await enqueue(captureSlug, '55555555555555555555');
    const afterFailedRetry = await engine.executeRaw<{ id: number; status: string }>(
      "SELECT id, status FROM minion_jobs WHERE name = 'facts-absorb' ORDER BY id",
    );
    expect(afterFailedRetry).toHaveLength(2);
    expect(afterFailedRetry[1]).toMatchObject({ id: rows[1].id, status: 'failed' });
  });

  test('legacy queued payload recovers lineage from the loaded page on replay', async () => {
    const fact = 'lineage-test:legacy-replay';
    const captureSlug = 'daily/hermes/owner-d/dddddddddddddddddddd/turn-d';
    const sessionRef = 'dddddddddddddddddddd';
    enableExtractor(fact);
    await engine.putPage(captureSlug, {
      title: 'Captured turn',
      type: 'note',
      compiled_truth: body,
      timeline: '',
      frontmatter: { hermes_session_ref: sessionRef },
    });
    const handlers = new Map<string, (job: unknown) => Promise<Record<string, unknown>>>();
    const worker = {
      register(name: string, handler: (job: unknown) => Promise<Record<string, unknown>>) {
        handlers.set(name, handler);
      },
    };
    await registerBuiltinHandlers(worker as never, engine, { quiet: true });
    const handler = handlers.get('facts-absorb');
    expect(handler).toBeTruthy();
    await handler!({
      id: 1,
      name: 'facts-absorb',
      data: { slug: captureSlug, sourceId: 'default', source: 'mcp:put_page' },
      attempts_made: 0,
      signal: new AbortController().signal,
      deadlineAtMs: null,
      updateProgress: async () => {},
    });
    const [row] = await engine.executeRaw<{
      context: string;
      source_session: string;
    }>('SELECT context, source_session FROM facts WHERE fact = $1', [fact]);
    expect(row.context).toBe(captureSlug);
    expect(row.source_session).toBe(sessionRef);
  });

  test('current durable job persists exact lineage and exposes the owner binding', async () => {
    const fact = 'lineage-test:current-durable-replay';
    const captureSlug = 'daily/hermes/owner-e/eeeeeeeeeeeeeeeeeeee/turn-e';
    const sessionRef = 'eeeeeeeeeeeeeeeeeeee';
    await engine.putPage(captureSlug, {
      title: 'Captured durable turn',
      type: 'note',
      compiled_truth: body,
      timeline: '',
      frontmatter: { hermes_session_ref: sessionRef },
    });
    markShortLivedCliProcess();
    await runFactsBackstop(
      {
        slug: captureSlug,
        type: 'note',
        compiled_truth: body,
        frontmatter: { hermes_session_ref: sessionRef },
      },
      {
        engine: engine as BrainEngine,
        sourceId: 'default',
        sessionId: null,
        source: 'mcp:put_page',
        mode: 'queue',
      },
    );
    const [queued] = await engine.executeRaw<{ id: number; data: Record<string, unknown> | string }>(
      "SELECT id, data FROM minion_jobs WHERE name = 'facts-absorb'",
    );
    const data = typeof queued.data === 'string' ? JSON.parse(queued.data) : queued.data;
    enableExtractor(fact);
    const handlers = new Map<string, (job: unknown) => Promise<Record<string, unknown>>>();
    await registerBuiltinHandlers({
      register(name: string, handler: (job: unknown) => Promise<Record<string, unknown>>) {
        handlers.set(name, handler);
      },
    } as never, engine, { quiet: true });
    await handlers.get('facts-absorb')!({
      id: queued.id,
      name: 'facts-absorb',
      data,
      attempts_made: 0,
      signal: new AbortController().signal,
      deadlineAtMs: null,
      updateProgress: async () => {},
    });
    const [row] = await engine.executeRaw<{
      id: number;
      context: string;
      source_session: string;
      source_markdown_slug: string | null;
    }>('SELECT id, context, source_session, source_markdown_slug FROM facts WHERE fact = $1', [fact]);
    expect(row).toMatchObject({
      context: captureSlug,
      source_session: sessionRef,
      source_markdown_slug: null,
    });
    const bindings = await loadFactPageBindings(
      engine,
      [{ sourceId: 'default', slug: captureSlug }],
      { authorized: true },
    );
    expect(factPageBindingsFor(bindings, 'default', captureSlug)).toContainEqual({
      fact_id: row.id,
      capture_page_slug: captureSlug,
      hermes_session_ref: sessionRef,
      matched_via: 'capture_page',
    });
  });

  test('entity fence stays internal while owner binding preserves capture lineage', async () => {
    const fact = 'lineage-test:hidden-entity-fence';
    const captureSlug = 'daily/hermes/owner-f/ffffffffffffffffffff/turn-f';
    const sessionRef = 'ffffffffffffffffffff';
    const entitySlug = 'people/example-subject';
    await engine.executeRaw("UPDATE sources SET local_path = $1 WHERE id = 'default'", [tmpHome]);
    enableExtractor(fact, entitySlug);
    try {
      const result = await runFactsBackstop(
        {
          slug: captureSlug,
          type: 'note',
          compiled_truth: body,
          frontmatter: { hermes_session_ref: sessionRef },
        },
        {
          engine: engine as BrainEngine,
          sourceId: 'default',
          sessionId: null,
          source: 'mcp:put_page',
          mode: 'inline',
        },
      );
      expect(result).toMatchObject({ mode: 'inline', inserted: 1 });

      const [row] = await engine.executeRaw<{
        id: number;
        context: string;
        source_session: string;
        source_markdown_slug: string | null;
      }>('SELECT id, context, source_session, source_markdown_slug FROM facts WHERE fact = $1', [fact]);
      expect(row).toMatchObject({
        context: captureSlug,
        source_session: sessionRef,
        source_markdown_slug: entitySlug,
      });

      const bindings = await loadFactPageBindings(
        engine,
        [
          { sourceId: 'default', slug: captureSlug },
          { sourceId: 'default', slug: entitySlug },
        ],
        { authorized: true },
      );
      const captureBinding = factPageBindingsFor(bindings, 'default', captureSlug)[0];
      const fenceBinding = factPageBindingsFor(bindings, 'default', entitySlug)[0];
      expect(captureBinding).toEqual({
        fact_id: row.id,
        capture_page_slug: captureSlug,
        hermes_session_ref: sessionRef,
        matched_via: 'capture_page',
      });
      expect(fenceBinding).toEqual({
        fact_id: row.id,
        capture_page_slug: captureSlug,
        hermes_session_ref: sessionRef,
        matched_via: 'entity_fence',
      });
      expect(captureBinding).not.toHaveProperty('entity_page_slug');
      expect(fenceBinding).not.toHaveProperty('entity_page_slug');
    } finally {
      await engine.executeRaw("UPDATE sources SET local_path = NULL WHERE id = 'default'");
    }
  });
});
