import { describe, expect, test } from 'bun:test';
import { buildJobContext } from '../src/core/minions/job-context.ts';
import type { BrainEngine } from '../src/core/engine.ts';
import type { MinionQueue } from '../src/core/minions/queue.ts';
import type { MinionJob } from '../src/core/minions/types.ts';

describe('MinionJobContext durable claim identity', () => {
  test.each([
    ['facts', 'facts-absorb:v1:abc'],
    ['default', null],
  ])('threads exact queue=%s and idempotency key=%p through the shared builder', (queueName, key) => {
    const job = {
      id: 17,
      name: 'facts-absorb',
      queue: queueName,
      idempotency_key: key,
      data: { payload_lineage_version: 'facts-absorb-v1' },
      attempts_made: 2,
      timeout_at: null,
    } as unknown as MinionJob;
    const context = buildJobContext(
      { executeRaw: async () => [] } as unknown as BrainEngine,
      {
        updateProgress: async () => {},
        updateTokens: async () => {},
        readInbox: async () => [],
      } as unknown as MinionQueue,
      job,
      'lock-token',
      new AbortController().signal,
      new AbortController().signal,
    );

    expect(context.queue).toBe(queueName);
    expect(context.idempotency_key).toBe(key);
    expect(context.data).toBe(job.data);
  });
});
