import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PGLiteEngine } from '../src/core/pglite-engine.ts';
import { configureGateway, resetGateway, __setChatTransportForTests } from '../src/core/ai/gateway.ts';
import {
  FACTS_ABSORB_PAYLOAD_LINEAGE_VERSION,
  FACTS_ABSORB_QUEUE,
  factsAbsorbCandidateMetadata,
  factsAbsorbExecutionIdentityHash,
  factsAbsorbIdempotencyKey,
  parseFactsAbsorbVersionedIdentity,
  factsAbsorbReplayLineage,
  runFactsBackstop,
  validateFactsAbsorbLivePage,
} from '../src/core/facts/backstop.ts';
import { factPageBindingsFor, loadFactPageBindings } from '../src/core/facts/page-bindings.ts';
import { markShortLivedCliProcess, __resetShortLivedCliForTests } from '../src/core/facts/cli-process-mode.ts';
import { registerBuiltinHandlers } from '../src/commands/jobs.ts';
import { MinionWorker } from '../src/core/minions/worker.ts';
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

async function waitFor<T>(read: () => Promise<T | undefined>, timeoutMs = 8_000): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = await read();
    if (value !== undefined) return value;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error(`timed out after ${timeoutMs}ms`);
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
    expect(data.payload_lineage_version).toBe(FACTS_ABSORB_PAYLOAD_LINEAGE_VERSION);
    expect(data.queue).toBe(FACTS_ABSORB_QUEUE);
    expect(data.pageType).toBe('note');
    expect(data.contentHash).toMatch(/^[0-9a-f]{64}$/);
    expect(data.model).toBe('anthropic:claude-sonnet-4-6');
    expect(data.validFrom).toBeNull();
    expect(data.entityHints).toEqual([]);
    expect(data.execution_identity_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(data).toMatchObject(factsAbsorbCandidateMetadata());
  });

  test('current identity parser accepts all six source values and rejects unknown provenance', () => {
    const base = {
      payloadLineageVersion: FACTS_ABSORB_PAYLOAD_LINEAGE_VERSION,
      queue: FACTS_ABSORB_QUEUE,
      sourceId: 'default',
      slug: 'daily/hermes/owner/hash/turn-a',
      pageType: 'note',
      contentHash: 'a'.repeat(64),
      source: 'mcp:put_page' as const,
      sourceSlug: 'daily/hermes/owner/hash/turn-a',
      sessionId: '0123456789abcdef0123',
      notabilityFilter: 'all' as const,
      visibility: 'private' as const,
      model: 'anthropic:claude-sonnet-4-6',
      validFrom: null,
      entityHints: [],
    };
    for (const source of ['sync:import', 'mcp:put_page', 'mcp:extract_facts', 'file_upload', 'code_import', 'hook:compact'] as const) {
      const identity = { ...base, source };
      const hash = factsAbsorbExecutionIdentityHash(identity);
      expect(parseFactsAbsorbVersionedIdentity({
        data: {
          payload_lineage_version: 1,
          queue: 'default',
          sourceId: identity.sourceId,
          slug: identity.slug,
          pageType: identity.pageType,
          contentHash: identity.contentHash,
          source,
          sourceSlug: identity.sourceSlug,
          sessionId: identity.sessionId,
          notabilityFilter: identity.notabilityFilter,
          visibility: identity.visibility,
          model: identity.model,
          validFrom: identity.validFrom,
          entityHints: identity.entityHints,
          execution_identity_hash: hash,
        },
        queue: 'default',
        idempotencyKey: factsAbsorbIdempotencyKey(identity),
      }).source).toBe(source);
    }
    const bad = { ...base, source: 'unknown' as never };
    expect(() => parseFactsAbsorbVersionedIdentity({
      data: {
        payload_lineage_version: 1, queue: 'default', sourceId: bad.sourceId, slug: bad.slug,
        pageType: bad.pageType, contentHash: bad.contentHash, source: bad.source,
        sourceSlug: bad.sourceSlug, sessionId: bad.sessionId, notabilityFilter: bad.notabilityFilter,
        visibility: bad.visibility, model: bad.model, validFrom: bad.validFrom, entityHints: bad.entityHints,
        execution_identity_hash: factsAbsorbExecutionIdentityHash(bad),
      },
      queue: 'default',
      idempotencyKey: factsAbsorbIdempotencyKey(bad),
    })).toThrow(/source is missing or not a recognized/);
  });

  test('current replay requires exact loaded put_page slug/session; only absent version gets legacy fallback', () => {
    const page = {
      slug: 'daily/hermes/owner/replay/turn-a',
      frontmatter: { hermes_session_ref: '0123456789abcdef0123' },
    };
    const current = {
      payload_lineage_version: FACTS_ABSORB_PAYLOAD_LINEAGE_VERSION,
      source: 'mcp:put_page',
      sourceSlug: page.slug,
      sessionId: page.frontmatter.hermes_session_ref,
    };
    expect(factsAbsorbReplayLineage(page, current)).toEqual({
      sourceSlug: page.slug,
      sessionId: page.frontmatter.hermes_session_ref,
    });
    for (const bad of [
      { ...current, sourceSlug: '' },
      { ...current, sourceSlug: `${page.slug}-adjacent` },
      { ...current, sourceSlug: 'daily/hermes/owner/replay/turn-b' },
      { ...current, sessionId: '' },
      { ...current, sessionId: 'fedcba9876543210fedc' },
    ]) {
      expect(() => factsAbsorbReplayLineage(page, bad)).toThrow(/lineage mismatch/);
    }
    expect(() => factsAbsorbReplayLineage(
      { ...page, frontmatter: {} },
      current,
    )).toThrow(/lineage mismatch/);
    expect(() => factsAbsorbReplayLineage(page, {
      ...current,
      payload_lineage_version: 999,
    })).toThrow(/unsupported payload_lineage_version/);
    expect(factsAbsorbReplayLineage(page, { source: 'mcp:put_page' })).toEqual({
      sourceSlug: page.slug,
      sessionId: page.frontmatter.hermes_session_ref,
    });
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

  test('every caller-settable semantic mutation creates one exact durable payload row', async () => {
    markShortLivedCliProcess();
    const base = {
      sourceId: 'default',
      slug: 'imports/gate2/page-a',
      pageType: 'note',
      compiledTruth: body,
      source: 'sync:import' as const,
      sourceSlug: 'imports/gate2/origin-a',
      sessionId: '12121212121212121212',
      notabilityFilter: 'all' as const,
      visibility: 'private' as const,
      model: 'anthropic:claude-sonnet-4-6',
      validFrom: new Date('2026-08-29T12:00:00.000Z'),
      entityHints: ['people/example-a'],
    };
    const rowsToSubmit = [
      base,
      { ...base, sourceId: 'owner-b' },
      { ...base, slug: 'imports/gate2/page-b' },
      { ...base, pageType: 'meeting' },
      { ...base, compiledTruth: `${body} B` },
      { ...base, source: 'file_upload' as const },
      { ...base, sourceSlug: 'imports/gate2/origin-b' },
      { ...base, sessionId: '34343434343434343434' },
      { ...base, notabilityFilter: 'high-only' as const },
      { ...base, visibility: 'world' as const },
      { ...base, model: 'openai:gpt-5.2' },
      { ...base, validFrom: new Date('2026-08-29T12:00:00.001Z') },
      { ...base, entityHints: ['people/example-b'] },
    ];
    for (const item of rowsToSubmit) {
      await runFactsBackstop(
        {
          slug: item.slug,
          type: item.pageType,
          compiled_truth: item.compiledTruth,
          frontmatter: {},
        },
        {
          engine: engine as BrainEngine,
          sourceId: item.sourceId,
          sessionId: item.sessionId,
          source: item.source,
          sourceSlug: item.sourceSlug,
          notabilityFilter: item.notabilityFilter,
          visibility: item.visibility,
          model: item.model,
          validFrom: item.validFrom,
          entityHints: item.entityHints,
          mode: 'queue',
        },
      );
    }
    const stored = await engine.executeRaw<{
      queue: string;
      idempotency_key: string;
      data: Record<string, unknown> | string;
    }>("SELECT queue, idempotency_key, data FROM minion_jobs WHERE name = 'facts-absorb' ORDER BY id");
    expect(stored).toHaveLength(rowsToSubmit.length);
    const hashes = new Set<string>();
    for (let i = 0; i < stored.length; i++) {
      const rawData = stored[i].data;
      const data = typeof rawData === 'string' ? JSON.parse(rawData) : rawData;
      const submitted = rowsToSubmit[i];
      expect(data).toMatchObject({
        payload_lineage_version: 1,
        queue: 'default',
        sourceId: submitted.sourceId,
        slug: submitted.slug,
        pageType: submitted.pageType,
        contentHash: createHash('sha256').update(submitted.compiledTruth).digest('hex'),
        source: submitted.source,
        sourceSlug: submitted.sourceSlug,
        sessionId: submitted.sessionId,
        notabilityFilter: submitted.notabilityFilter,
        visibility: submitted.visibility,
        model: submitted.model,
        validFrom: submitted.validFrom.toISOString(),
        entityHints: submitted.entityHints,
        candidate_release_id: expect.any(String),
        candidate_commit_sha: expect.any(String),
        candidate_package_version: expect.any(String),
      });
      const parsed = parseFactsAbsorbVersionedIdentity({
        data,
        queue: stored[i].queue,
        idempotencyKey: stored[i].idempotency_key,
      });
      expect(data.execution_identity_hash).toBe(factsAbsorbExecutionIdentityHash(parsed));
      expect(stored[i].idempotency_key).toBe(factsAbsorbIdempotencyKey(parsed));
      hashes.add(String(data.execution_identity_hash));
    }
    expect(hashes.size).toBe(rowsToSubmit.length);

    const priorRelease = process.env.GBRAIN_ENGINE_VERSION;
    process.env.GBRAIN_ENGINE_VERSION = 'metadata-only-change';
    try {
      await runFactsBackstop(
        { slug: base.slug, type: base.pageType, compiled_truth: base.compiledTruth, frontmatter: {} },
        {
          engine: engine as BrainEngine, sourceId: base.sourceId, sessionId: base.sessionId,
          source: base.source, sourceSlug: base.sourceSlug, notabilityFilter: base.notabilityFilter,
          visibility: base.visibility, model: base.model, validFrom: base.validFrom,
          entityHints: base.entityHints, mode: 'queue',
        },
      );
      const [count] = await engine.executeRaw<{ n: number }>(
        "SELECT COUNT(*)::int AS n FROM minion_jobs WHERE name = 'facts-absorb'",
      );
      expect(Number(count.n)).toBe(rowsToSubmit.length);
    } finally {
      if (priorRelease === undefined) delete process.env.GBRAIN_ENGINE_VERSION;
      else process.env.GBRAIN_ENGINE_VERSION = priorRelease;
    }
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
    const [queued] = await engine.executeRaw<{
      id: number;
      queue: string;
      idempotency_key: string;
      data: Record<string, unknown> | string;
    }>(
      "SELECT id, queue, idempotency_key, data FROM minion_jobs WHERE name = 'facts-absorb'",
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
      queue: queued.queue,
      idempotency_key: queued.idempotency_key,
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

  test('versioned worker rejects every malformed or stale identity before chat', async () => {
    const captureSlug = 'daily/hermes/owner-strict/99999999999999999999/turn-a';
    const sessionRef = '99999999999999999999';
    await engine.putPage(captureSlug, {
      title: 'Strict replay capture',
      type: 'note',
      compiled_truth: body,
      timeline: '',
      frontmatter: { hermes_session_ref: sessionRef },
    });
    markShortLivedCliProcess();
    await runFactsBackstop(
      { slug: captureSlug, type: 'note', compiled_truth: body, frontmatter: { hermes_session_ref: sessionRef } },
      {
        engine: engine as BrainEngine,
        sourceId: 'default',
        sessionId: null,
        source: 'mcp:put_page',
        sourceSlug: captureSlug,
        entityHints: [' people/example-a '],
        validFrom: new Date('2026-08-29T12:00:00.000Z'),
        mode: 'queue',
      },
    );
    const [queued] = await engine.executeRaw<{
      id: number;
      queue: string;
      idempotency_key: string;
      data: Record<string, unknown> | string;
    }>("SELECT id, queue, idempotency_key, data FROM minion_jobs WHERE name = 'facts-absorb'");
    const data = typeof queued.data === 'string' ? JSON.parse(queued.data) : queued.data;
    let chatCalls = 0;
    enableExtractor('lineage-test:strict-should-not-run');
    __setChatTransportForTests(async () => {
      chatCalls++;
      return extractorResult('lineage-test:strict-should-not-run');
    });
    const handlers = new Map<string, (job: any) => Promise<Record<string, unknown>>>();
    await registerBuiltinHandlers({
      register(name: string, handler: (job: any) => Promise<Record<string, unknown>>) {
        handlers.set(name, handler);
      },
    } as never, engine, { quiet: true });
    const handler = handlers.get('facts-absorb')!;
    const invoke = (candidate: Record<string, unknown>, overrides: Record<string, unknown> = {}) => handler({
      id: queued.id,
      name: 'facts-absorb',
      queue: queued.queue,
      idempotency_key: queued.idempotency_key,
      data: candidate,
      attempts_made: 0,
      signal: new AbortController().signal,
      deadlineAtMs: null,
      updateProgress: async () => {},
      ...overrides,
    });
    const rekey = (candidate: Record<string, unknown>) => {
      const identity = {
        payloadLineageVersion: candidate.payload_lineage_version as number,
        queue: candidate.queue as string,
        sourceId: candidate.sourceId as string,
        slug: candidate.slug as string,
        pageType: candidate.pageType as string,
        contentHash: candidate.contentHash as string,
        source: candidate.source as 'mcp:put_page',
        sourceSlug: candidate.sourceSlug as string,
        sessionId: candidate.sessionId as string | null,
        notabilityFilter: candidate.notabilityFilter as 'all' | 'high-only',
        visibility: candidate.visibility as 'private' | 'world',
        model: candidate.model as string,
        validFrom: candidate.validFrom as string | null,
        entityHints: candidate.entityHints as string[],
      };
      const next = {
        ...candidate,
        execution_identity_hash: factsAbsorbExecutionIdentityHash(identity),
      };
      return {
        data: next,
        key: factsAbsorbIdempotencyKey(identity),
      };
    };

    for (const field of [
      'payload_lineage_version', 'queue', 'sourceId', 'slug', 'pageType', 'contentHash', 'source',
      'sourceSlug', 'sessionId', 'notabilityFilter', 'visibility', 'model', 'validFrom', 'entityHints',
      'execution_identity_hash', 'candidate_release_id', 'candidate_commit_sha', 'candidate_package_version',
    ]) {
      const malformed = { ...data };
      delete malformed[field];
      await expect(invoke(malformed)).rejects.toThrow(/invalid versioned payload|requires data.slug/);
    }
    await expect(invoke({ ...data, payload_lineage_version: 999 })).rejects.toThrow(/unsupported payload_lineage_version/);
    await expect(invoke({ ...data, source: 'unknown' })).rejects.toThrow(/recognized production provenance/);
    await expect(invoke({ ...data }, { queue: 'other' })).rejects.toThrow(/queue must exactly equal/);
    await expect(invoke({ ...data }, { idempotency_key: `${queued.idempotency_key}-other` })).rejects.toThrow(/idempotency_key/);

    const wrongTypes: Array<[string, unknown]> = [
      ['payload_lineage_version', '1'],
      ['queue', 1],
      ['sourceId', 1],
      ['slug', 1],
      ['pageType', 1],
      ['contentHash', 1],
      ['source', 1],
      ['sourceSlug', 1],
      ['sessionId', 1],
      ['notabilityFilter', 1],
      ['visibility', 1],
      ['model', 1],
      ['validFrom', 1],
      ['entityHints', 'people/example-a'],
    ];
    for (const [field, value] of wrongTypes) {
      await expect(invoke({ ...data, [field]: value })).rejects.toThrow(/invalid versioned payload/);
    }
    const wrongEnums: Array<[string, unknown]> = [
      ['payload_lineage_version', 2],
      ['queue', 'priority'],
      ['source', 'manual'],
      ['notabilityFilter', 'medium'],
      ['visibility', 'public'],
    ];
    for (const [field, value] of wrongEnums) {
      await expect(invoke({ ...data, [field]: value })).rejects.toThrow(/invalid versioned payload/);
    }

    const nullIdentity = rekey({ ...data, sessionId: null, validFrom: null });
    expect(parseFactsAbsorbVersionedIdentity({
      data: nullIdentity.data,
      queue: queued.queue,
      idempotencyKey: nullIdentity.key,
    })).toMatchObject({ sessionId: null, validFrom: null });
    for (const field of ['sessionId', 'validFrom']) {
      await expect(invoke({ ...data, [field]: '' })).rejects.toThrow(/invalid versioned payload/);
    }

    // The physical-page guard is independent of sourceSlug lineage. Rekey a
    // payload whose canonical data.slug points somewhere else, then validate
    // it against the page actually loaded from storage. This catches a stale
    // or aliased getPage result before any model call.
    const physicalSlugMismatch = rekey({
      ...data,
      slug: `${captureSlug}-different-physical-page`,
    });
    const physicalIdentity = parseFactsAbsorbVersionedIdentity({
      data: physicalSlugMismatch.data,
      queue: queued.queue,
      idempotencyKey: physicalSlugMismatch.key,
    });
    const loadedPhysicalPage = await engine.getPage(captureSlug, { sourceId: 'default' });
    expect(loadedPhysicalPage).toBeTruthy();
    expect(() => validateFactsAbsorbLivePage(physicalIdentity, loadedPhysicalPage!))
      .toThrow(/loaded page slug does not match the stored identity/);

    await engine.putPage(captureSlug, {
      title: 'Strict replay capture', type: 'meeting', compiled_truth: body,
      timeline: '', frontmatter: { hermes_session_ref: sessionRef },
    });
    await expect(invoke(data)).rejects.toThrow(/page type/);
    await engine.putPage(captureSlug, {
      title: 'Strict replay capture', type: 'note', compiled_truth: `${body} edited`,
      timeline: '', frontmatter: { hermes_session_ref: sessionRef },
    });
    await expect(invoke(data)).rejects.toThrow(/content hash/);
    expect(chatCalls).toBe(0);
    const [facts] = await engine.executeRaw<{ n: number }>(
      "SELECT COUNT(*)::int AS n FROM facts WHERE fact = 'lineage-test:strict-should-not-run'",
    );
    expect(Number(facts.n)).toBe(0);
  });

  test('real worker retries a provider transport failure to one terminal result/fact with zero queue debt', async () => {
    const fact = 'lineage-test:worker-retry-success';
    const captureSlug = 'daily/hermes/owner-retry/abababababababababab/turn-a';
    const sessionRef = 'abababababababababab';
    const terminalValidFrom = new Date('2026-08-29T12:34:56.000Z');
    const priorRelease = process.env.GBRAIN_ENGINE_VERSION;
    const priorCommit = process.env.GBRAIN_ENGINE_SOURCE_COMMIT;
    process.env.GBRAIN_ENGINE_VERSION = 'facts-worker-test-release';
    process.env.GBRAIN_ENGINE_SOURCE_COMMIT = 'f'.repeat(40);
    let worker: MinionWorker | undefined;
    let workerPromise: Promise<void> | undefined;
    try {
      await engine.putPage(captureSlug, {
        title: 'Retry capture',
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
          validFrom: terminalValidFrom,
          mode: 'queue',
        },
      );
      const [queued] = await engine.executeRaw<{
        id: number;
        idempotency_key: string;
        max_attempts: number;
        data: Record<string, unknown> | string;
      }>("SELECT id, idempotency_key, max_attempts, data FROM minion_jobs WHERE name = 'facts-absorb'");
      const queuedData = typeof queued.data === 'string' ? JSON.parse(queued.data) : queued.data;
      expect(queued.max_attempts).toBe(5);
      expect(queuedData).toMatchObject({
        candidate_release_id: 'facts-worker-test-release',
        candidate_commit_sha: 'f'.repeat(40),
        payload_lineage_version: FACTS_ABSORB_PAYLOAD_LINEAGE_VERSION,
      });
      await engine.executeRaw(
        `UPDATE minion_jobs
            SET backoff_delay = 0, backoff_jitter = 0
          WHERE id = $1`,
        [queued.id],
      );

      process.env.ANTHROPIC_API_KEY = 'sk-ant-lineage-test';
      configureGateway({
        chat_model: 'anthropic:claude-sonnet-4-6',
        env: { ...process.env, ANTHROPIC_API_KEY: 'sk-ant-lineage-test' },
      });
      let transportCalls = 0;
      __setChatTransportForTests(async () => {
        transportCalls++;
        if (transportCalls === 1) throw new Error('gate2-transient-provider');
        return extractorResult(fact);
      });
      worker = new MinionWorker(engine, { concurrency: 1, pollInterval: 20, lockDuration: 30_000 });
      await registerBuiltinHandlers(worker, engine, { quiet: true });
      workerPromise = worker.start();
      const terminal = await waitFor(async () => {
        const [row] = await engine.executeRaw<{
          id: number;
          idempotency_key: string;
          data: Record<string, unknown> | string;
          status: string;
          max_attempts: number;
          attempts_made: number;
          attempts_started: number;
          stalled_counter: number;
          result: Record<string, unknown> | string;
          error_text: string | null;
          stacktrace: string[] | string;
          lock_token: string | null;
          lock_until: string | null;
          delay_until: string | null;
          started_at: string | null;
          finished_at: string | null;
        }>(`SELECT id, idempotency_key, data, status, max_attempts, attempts_made, attempts_started, stalled_counter, result,
                   error_text, stacktrace, lock_token, lock_until, delay_until,
                   started_at, finished_at
              FROM minion_jobs WHERE id = $1`, [queued.id]);
        return row?.status === 'completed' ? row : undefined;
      });
      worker.stop();
      await workerPromise;
      workerPromise = undefined;
      const result = typeof terminal.result === 'string' ? JSON.parse(terminal.result) : terminal.result;
      expect(terminal).toMatchObject({
        status: 'completed',
        max_attempts: 5,
        attempts_made: 1,
        attempts_started: 2,
        stalled_counter: 0,
        lock_token: null,
        lock_until: null,
        delay_until: null,
      });
      expect(terminal.started_at).not.toBeNull();
      expect(terminal.finished_at).not.toBeNull();
      expect(new Date(terminal.finished_at!).getTime()).toBeGreaterThanOrEqual(new Date(terminal.started_at!).getTime());
      expect(terminal.error_text).toContain('provider_error');
      expect(JSON.stringify(terminal.stacktrace)).toContain('provider_error');
      expect(transportCalls).toBe(2);
      expect(result).toMatchObject({
        candidate_release_id: 'facts-worker-test-release',
        candidate_commit_sha: 'f'.repeat(40),
        candidate_package_version: factsAbsorbCandidateMetadata().candidate_package_version,
        inserted: 1,
      });
      const [factRow] = await engine.executeRaw<{
        id: number;
        source_id: string;
        source: string;
        context: string;
        source_session: string;
        visibility: string;
        valid_from: string | Date;
      }>(
        'SELECT id, source_id, source, context, source_session, visibility, valid_from FROM facts WHERE fact = $1',
        [fact],
      );
      expect(factRow).toMatchObject({
        source_id: 'default',
        source: 'mcp:put_page',
        context: captureSlug,
        source_session: sessionRef,
        visibility: 'private',
      });
      expect(new Date(factRow.valid_from).toISOString()).toBe(terminalValidFrom.toISOString());
      expect(result.fact_ids).toEqual([factRow.id]);

      // Terminal exact replay is idempotent: same row, no second fact/result.
      const terminalResult = structuredClone(result);
      const terminalData = structuredClone(
        typeof terminal.data === 'string' ? JSON.parse(terminal.data) : terminal.data,
      );
      const terminalFactIds = structuredClone(result.fact_ids);
      await runFactsBackstop(
        { slug: captureSlug, type: 'note', compiled_truth: body, frontmatter: { hermes_session_ref: sessionRef } },
        {
          engine: engine as BrainEngine,
          sourceId: 'default',
          sessionId: null,
          source: 'mcp:put_page',
          validFrom: terminalValidFrom,
          mode: 'queue',
        },
      );
      const replayRows = await engine.executeRaw<{
        id: number;
        idempotency_key: string;
        data: Record<string, unknown> | string;
        result: Record<string, unknown> | string;
      }>(`SELECT id, idempotency_key, data, result
             FROM minion_jobs
            WHERE name = 'facts-absorb'
            ORDER BY id`);
      expect(replayRows).toHaveLength(1);
      const [afterReplay] = replayRows;
      expect(afterReplay.id).toBe(terminal.id);
      expect(afterReplay.idempotency_key).toBe(terminal.idempotency_key);
      const replayData = typeof afterReplay.data === 'string' ? JSON.parse(afterReplay.data) : afterReplay.data;
      expect(replayData).toEqual(terminalData);
      const replayResult = typeof afterReplay.result === 'string' ? JSON.parse(afterReplay.result) : afterReplay.result;
      expect(replayResult).toEqual(terminalResult);
      expect(replayResult.fact_ids).toEqual(terminalFactIds);
      expect(transportCalls).toBe(2);
      const [debt] = await engine.executeRaw<{
        total: number; completed: number; noncompleted: number; dead: number; failed: number;
        delayed: number; locked: number; stalled: number; parented: number; distinct_keys: number;
      }>(
        `SELECT COUNT(*)::int AS total,
                COUNT(*) FILTER (WHERE status = 'completed')::int AS completed,
                COUNT(*) FILTER (WHERE status <> 'completed')::int AS noncompleted,
                COUNT(*) FILTER (WHERE status = 'dead')::int AS dead,
                COUNT(*) FILTER (WHERE status = 'failed')::int AS failed,
                COUNT(*) FILTER (WHERE status = 'delayed' OR delay_until IS NOT NULL)::int AS delayed,
                COUNT(*) FILTER (WHERE lock_token IS NOT NULL OR lock_until IS NOT NULL)::int AS locked,
                COALESCE(SUM(stalled_counter), 0)::int AS stalled,
                COUNT(*) FILTER (WHERE parent_job_id IS NOT NULL OR private_queue_owner_job_id IS NOT NULL)::int AS parented,
                COUNT(DISTINCT idempotency_key)::int AS distinct_keys
           FROM minion_jobs
          WHERE name = 'facts-absorb'`,
      );
      expect(debt).toEqual({
        total: 1,
        completed: 1,
        noncompleted: 0,
        dead: 0,
        failed: 0,
        delayed: 0,
        locked: 0,
        stalled: 0,
        parented: 0,
        distinct_keys: 1,
      });
      const [factDebt] = await engine.executeRaw<{ n: number; ids: number }>(
        'SELECT COUNT(*)::int AS n, COUNT(DISTINCT id)::int AS ids FROM facts WHERE fact = $1',
        [fact],
      );
      expect(factDebt).toEqual({ n: 1, ids: 1 });
      const [liveLineage] = await engine.executeRaw<{
        fact_id: number;
        capture_page_slug: string;
        source_session: string;
      }>(
        `SELECT f.id AS fact_id, p.slug AS capture_page_slug, f.source_session
           FROM facts f
           JOIN pages p ON p.source_id = f.source_id AND p.slug = f.context
          WHERE f.id = $1 AND p.deleted_at IS NULL`,
        [factRow.id],
      );
      expect(liveLineage).toEqual({
        fact_id: factRow.id,
        capture_page_slug: captureSlug,
        source_session: sessionRef,
      });

      // Anti-manufacture receipt: this proof drives the real worker only. It
      // never writes terminal state itself, calls queue terminal methods, or
      // invokes the registered facts handler directly.
      const testSource = readFileSync(fileURLToPath(import.meta.url), 'utf8');
      const proofStart = testSource.indexOf("test('real worker retries a provider transport failure");
      const proofEnd = testSource.indexOf("test('entity fence stays internal", proofStart);
      const proofSource = testSource.slice(proofStart, proofEnd);
      const forbiddenColumns = [
        'status', 'attempts_made', 'attempts_started', 'result', 'error_text',
        'delay_until', 'lock_token', 'lock_until', 'started_at', 'finished_at',
        'updated_at',
      ];
      const directTerminalEdits = [...proofSource.matchAll(/UPDATE\s+minion_jobs\s+SET([\s\S]*?)(?:WHERE|`)/gi)]
        .flatMap((match) => forbiddenColumns.filter((column) =>
          new RegExp(`\\b${column}\\b\\s*=`).test(match[1]),
        )).length;
      const directQueueCalls = [
        ['queue', 'failJob'].join('.'),
        ['queue', 'completeJob'].join('.'),
      ].reduce((count, token) => count + proofSource.split(token).length - 1, 0);
      const directHandlerCalls = [
        ['handlers', "get('facts-absorb')"].join('.'),
        ['handler', '!('].join(''),
      ].reduce((count, token) => count + proofSource.split(token).length - 1, 0);
      expect({ directTerminalEdits, directQueueCalls, directHandlerCalls }).toEqual({
        directTerminalEdits: 0,
        directQueueCalls: 0,
        directHandlerCalls: 0,
      });
    } finally {
      worker?.stop();
      if (workerPromise) await workerPromise;
      if (priorRelease === undefined) delete process.env.GBRAIN_ENGINE_VERSION;
      else process.env.GBRAIN_ENGINE_VERSION = priorRelease;
      if (priorCommit === undefined) delete process.env.GBRAIN_ENGINE_SOURCE_COMMIT;
      else process.env.GBRAIN_ENGINE_SOURCE_COMMIT = priorCommit;
    }
  }, 20_000);

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
