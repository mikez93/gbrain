import { describe, expect, test } from 'bun:test';
import {
  FACTS_ABSORB_PAYLOAD_LINEAGE_VERSION,
  FACTS_ABSORB_QUEUE,
  factsAbsorbExecutionIdentityCanonical,
  factsAbsorbExecutionIdentityHash,
  factsAbsorbIdempotencyKey,
  type FactsAbsorbExecutionIdentity,
} from '../src/core/facts/backstop.ts';

const baseline: FactsAbsorbExecutionIdentity = {
  payloadLineageVersion: FACTS_ABSORB_PAYLOAD_LINEAGE_VERSION,
  queue: FACTS_ABSORB_QUEUE,
  sourceId: 'default',
  slug: 'daily/hermes/owner-g2/77777777777777777777/turn-a',
  pageType: 'note',
  contentHash: 'a'.repeat(64),
  source: 'sync:import',
  sourceSlug: 'imports/owner-g2/origin-a',
  sessionId: '77777777777777777777',
  notabilityFilter: 'all',
  visibility: 'private',
  model: 'anthropic:claude-sonnet-4-6',
  validFrom: '2026-08-29T12:00:00.000Z',
  entityHints: ['people/example-a'],
};

describe('facts-absorb full execution identity', () => {
  test('uses the accepted fixed 15-field canonical order', () => {
    expect(JSON.parse(factsAbsorbExecutionIdentityCanonical(baseline))).toEqual([
      'facts-absorb',
      1,
      'default',
      'default',
      'daily/hermes/owner-g2/77777777777777777777/turn-a',
      'note',
      'a'.repeat(64),
      'sync:import',
      'imports/owner-g2/origin-a',
      '77777777777777777777',
      'all',
      'private',
      'anthropic:claude-sonnet-4-6',
      '2026-08-29T12:00:00.000Z',
      ['people/example-a'],
    ]);
    expect(factsAbsorbExecutionIdentityHash(baseline)).toMatch(/^[0-9a-f]{64}$/);
    expect(factsAbsorbIdempotencyKey(baseline)).toBe(
      `facts-absorb:v1:${factsAbsorbExecutionIdentityHash(baseline)}`,
    );
  });

  test('all 14 non-domain fields independently change canonical bytes, hash, and key', () => {
    const mutations: Array<[string, FactsAbsorbExecutionIdentity]> = [
      ['payloadLineageVersion', { ...baseline, payloadLineageVersion: 2 }],
      ['queue', { ...baseline, queue: 'facts-secondary' }],
      ['sourceId', { ...baseline, sourceId: 'owner-b' }],
      ['slug', { ...baseline, slug: `${baseline.slug}-b` }],
      ['pageType', { ...baseline, pageType: 'meeting' }],
      ['contentHash', { ...baseline, contentHash: 'b'.repeat(64) }],
      ['source', { ...baseline, source: 'file_upload' }],
      ['sourceSlug', { ...baseline, sourceSlug: 'imports/owner-g2/origin-b' }],
      ['sessionId', { ...baseline, sessionId: '88888888888888888888' }],
      ['notabilityFilter', { ...baseline, notabilityFilter: 'high-only' }],
      ['visibility', { ...baseline, visibility: 'world' }],
      ['model', { ...baseline, model: 'openai:gpt-5.2' }],
      ['validFrom', { ...baseline, validFrom: '2026-08-29T12:00:00.001Z' }],
      ['entityHints', { ...baseline, entityHints: ['people/example-b'] }],
    ];
    const canonical = factsAbsorbExecutionIdentityCanonical(baseline);
    const hash = factsAbsorbExecutionIdentityHash(baseline);
    const key = factsAbsorbIdempotencyKey(baseline);
    const hashes = new Set([hash]);
    const keys = new Set([key]);
    for (const [field, mutated] of mutations) {
      expect(factsAbsorbExecutionIdentityCanonical(mutated), field).not.toBe(canonical);
      expect(factsAbsorbExecutionIdentityHash(mutated), field).not.toBe(hash);
      expect(factsAbsorbIdempotencyKey(mutated), field).not.toBe(key);
      hashes.add(factsAbsorbExecutionIdentityHash(mutated));
      keys.add(factsAbsorbIdempotencyKey(mutated));
    }
    expect(hashes.size).toBe(15);
    expect(keys.size).toBe(15);
  });

  test('JSON array framing resists delimiter, NUL, null, hint-boundary, and property-order collisions', () => {
    const pairs: Array<[FactsAbsorbExecutionIdentity, FactsAbsorbExecutionIdentity]> = [
      [{ ...baseline, sourceId: 'a:b', slug: 'c' }, { ...baseline, sourceId: 'a', slug: 'b:c' }],
      [{ ...baseline, sourceId: 'a\0b', slug: 'c' }, { ...baseline, sourceId: 'a', slug: 'b\0c' }],
      [{ ...baseline, sessionId: null }, { ...baseline, sessionId: 'null' }],
      [{ ...baseline, entityHints: ['ab', 'c'] }, { ...baseline, entityHints: ['a', 'bc'] }],
    ];
    for (const [left, right] of pairs) {
      expect(factsAbsorbExecutionIdentityCanonical(left)).not.toBe(factsAbsorbExecutionIdentityCanonical(right));
      expect(factsAbsorbExecutionIdentityHash(left)).not.toBe(factsAbsorbExecutionIdentityHash(right));
      expect(factsAbsorbIdempotencyKey(left)).not.toBe(factsAbsorbIdempotencyKey(right));
    }

    const reverseInsertionOrder = Object.fromEntries(
      Object.entries(baseline).reverse(),
    ) as unknown as FactsAbsorbExecutionIdentity;
    expect(factsAbsorbExecutionIdentityCanonical(reverseInsertionOrder)).toBe(
      factsAbsorbExecutionIdentityCanonical(baseline),
    );
  });
});
