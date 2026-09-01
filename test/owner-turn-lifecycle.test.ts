import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { __testing as captureTesting } from '../src/commands/capture.ts';
import { CLI_FLAG_REGISTRY } from '../src/core/cli-flag-registry.generated.ts';
import {
  OWNER_TURN_LIFECYCLE_PAYLOAD_VERSION,
  assertCanonicalOwnerTurnPage,
  ownerTurnLifecycleIdempotencyKey,
  ownerTurnPageContentHash,
  parseOwnerTurnLifecycleIdentity,
  submitOwnerTurnLifecycle,
} from '../src/core/cycle/owner-turn-lifecycle.ts';
import { isOwnerTurnPhaseComplete } from '../src/core/minions/handlers/owner-turn-lifecycle.ts';
import { isProtectedJobName } from '../src/core/minions/protected-names.ts';
import { PGLiteEngine } from '../src/core/pglite-engine.ts';

const JOBS_SOURCE = readFileSync(
  join(import.meta.dir, '..', 'src', 'commands', 'jobs.ts'),
  'utf8',
);
const HANDLER_SOURCE = readFileSync(
  join(import.meta.dir, '..', 'src', 'core', 'minions', 'handlers', 'owner-turn-lifecycle.ts'),
  'utf8',
);
let engine: PGLiteEngine;

beforeAll(async () => {
  engine = new PGLiteEngine();
  await engine.connect({});
  await engine.initSchema();
});

afterAll(async () => {
  await engine.disconnect();
});

describe('F4b owner-turn lifecycle identity', () => {
  const identity = {
    sourceId: 'marco-sessions',
    slug: 'daily/hermes/marco/session/turn',
    pageContentHash: 'a'.repeat(64),
  };

  test('exact source, slug, and page hash bind one stable idempotency key', () => {
    expect(ownerTurnLifecycleIdempotencyKey(identity)).toBe(
      ownerTurnLifecycleIdempotencyKey({ ...identity }),
    );
    expect(ownerTurnLifecycleIdempotencyKey({
      ...identity,
      pageContentHash: 'b'.repeat(64),
    })).not.toBe(ownerTurnLifecycleIdempotencyKey(identity));
    expect(parseOwnerTurnLifecycleIdentity({
      payload_lineage_version: OWNER_TURN_LIFECYCLE_PAYLOAD_VERSION,
      ...identity,
    })).toEqual(identity);
  });

  test('malformed scope fails before any phase can run', () => {
    expect(() => parseOwnerTurnLifecycleIdentity({
      payload_lineage_version: OWNER_TURN_LIFECYCLE_PAYLOAD_VERSION,
      ...identity,
      sourceId: '../private',
    })).toThrow();
    expect(() => parseOwnerTurnLifecycleIdentity({
      payload_lineage_version: OWNER_TURN_LIFECYCLE_PAYLOAD_VERSION,
      ...identity,
      sourceId: 'vector',
    })).toThrow(/not allowlisted/);
    expect(() => parseOwnerTurnLifecycleIdentity({
      payload_lineage_version: OWNER_TURN_LIFECYCLE_PAYLOAD_VERSION,
      ...identity,
      pageContentHash: 'short',
    })).toThrow();
  });

  test('page hash binds the current compiled page snapshot', () => {
    expect(ownerTurnPageContentHash({ compiled_truth: 'owner turn' } as never))
      .toMatch(/^[0-9a-f]{64}$/);
    expect(ownerTurnPageContentHash({ compiled_truth: 'owner turn' } as never))
      .not.toBe(ownerTurnPageContentHash({ compiled_truth: 'changed turn' } as never));
  });

  test('only canonical fixed-profile Hermes pages pass the inference gate', () => {
    const sessionRef = '1'.repeat(20);
    const turnRef = '2'.repeat(20);
    const contentHash = '3'.repeat(64);
    const page = {
      slug: `daily/hermes/marco/${sessionRef}/${turnRef}-${contentHash.slice(0, 12)}`,
      type: 'conversation',
      compiled_truth: 'owner turn',
      frontmatter: {
        captured_via: 'hermes-post-llm',
        hermes_agent: 'marco',
        hermes_session_ref: sessionRef,
        hermes_turn_ref: turnRef,
        hermes_content_sha256: contentHash,
      },
    };
    expect(() => assertCanonicalOwnerTurnPage('marco-sessions', page as never)).not.toThrow();
    expect(() => assertCanonicalOwnerTurnPage('vector', page as never)).toThrow(/not allowlisted/);
    expect(() => assertCanonicalOwnerTurnPage('marco-sessions', {
      ...page,
      frontmatter: { ...page.frontmatter, hermes_agent: 'ezra' },
    } as never)).toThrow(/lineage is invalid/);
  });

  test('protected submission coalesces the same page snapshot', async () => {
    const first = await submitOwnerTurnLifecycle(engine, identity);
    const second = await submitOwnerTurnLifecycle(engine, identity);
    expect(second.id).toBe(first.id);
    expect(second.coalesced).toBe(true);
    expect(first.name).toBe('owner-turn-lifecycle');
    expect(first.max_attempts).toBe(3);
    expect(first.timeout_ms).toBe(30 * 60_000);
    const changed = await submitOwnerTurnLifecycle(engine, {
      ...identity,
      pageContentHash: 'b'.repeat(64),
    });
    expect(changed.id).not.toBe(first.id);
    expect(changed.coalesced).not.toBe(true);
  }, 120000);
});

describe('F4b owner-turn lifecycle wiring', () => {
  test('capture requires an explicit local-only queue flag', () => {
    const parsed = captureTesting.parseArgs([
      '--stdin',
      '--source', 'ezra',
      '--owner-turn-lifecycle',
      '--json',
    ]);
    expect(parsed).toMatchObject({ ownerTurnLifecycle: true, source: 'ezra' });
  });

  test('generated registry admits the flag and executable help reaches capture', () => {
    expect(CLI_FLAG_REGISTRY.capture).toContain('--owner-turn-lifecycle');
    const result = Bun.spawnSync(
      ['bun', 'src/cli.ts', 'capture', '--owner-turn-lifecycle', '--help'],
      { cwd: join(import.meta.dir, '..'), stdout: 'pipe', stderr: 'pipe' },
    );
    expect(result.exitCode).toBe(0);
    expect(result.stdout.toString()).toContain('--owner-turn-lifecycle');
    expect(result.stderr.toString()).not.toContain('unknown flag');
  });

  test('job is protected and runs only the two exact-page phases', () => {
    expect(isProtectedJobName('owner-turn-lifecycle')).toBe(true);
    expect(JOBS_SOURCE).toContain("registerBuiltinJob(worker, engine, 'owner-turn-lifecycle'");
    expect(HANDLER_SOURCE).toContain("'extract_atoms',\n  'propose_takes'");
    expect(HANDLER_SOURCE).not.toContain('conversation_facts_backfill');
    expect(HANDLER_SOURCE).toContain('targetSlugs: [identity.slug]');
    expect(HANDLER_SOURCE).toContain('forcePhaseGates: [...PHASES]');
    expect(HANDLER_SOURCE).toContain("engine.getConfig('models.chat')");
    expect(HANDLER_SOURCE).toContain('extractAtomsModel: configuredChatModel');
    expect(HANDLER_SOURCE).toContain('proposeTakesModel: configuredChatModel');
    expect(HANDLER_SOURCE).not.toContain('drain');
    expect(HANDLER_SOURCE).not.toContain('listSources');
    expect(HANDLER_SOURCE).not.toContain('listPages');
  });

  test('retry accepts only an already-complete atom page as benign no-work', () => {
    const result = (phase: 'extract_atoms' | 'propose_takes', status: 'ok' | 'warn' | 'fail' | 'skipped', reason?: string) => ({
      phase,
      status,
      duration_ms: 0,
      summary: 'test',
      details: reason ? { reason } : {},
    });
    expect(isOwnerTurnPhaseComplete(result('extract_atoms', 'ok'))).toBe(true);
    expect(isOwnerTurnPhaseComplete(result('propose_takes', 'ok'))).toBe(true);
    expect(isOwnerTurnPhaseComplete(result('extract_atoms', 'skipped', 'no_work'))).toBe(true);
    expect(isOwnerTurnPhaseComplete(result('propose_takes', 'skipped', 'no_work'))).toBe(false);
    for (const reason of ['no_provider', 'disabled', 'insufficient_cycle_budget']) {
      expect(isOwnerTurnPhaseComplete(result('extract_atoms', 'skipped', reason))).toBe(false);
    }
    expect(isOwnerTurnPhaseComplete(result('extract_atoms', 'warn'))).toBe(false);
    expect(isOwnerTurnPhaseComplete(result('propose_takes', 'fail'))).toBe(false);
  });
});
