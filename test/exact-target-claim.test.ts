import { describe, expect, test } from 'bun:test';
import type { BrainEngine } from '../src/core/engine.ts';
import {
  ExactClaimAmbiguousError,
  ExactClaimLatch,
  MinionQueue,
} from '../src/core/minions/queue.ts';
import {
  assertExactTargetSchema,
  readExactClaimByToken,
} from '../src/core/minions/exact-target-claim.ts';
import {
  EXACT_TARGET_JOB_FIELDS,
  rowToExactTargetFrozenRow,
  rowToMinionJob,
  type ExactTargetFrozenRow,
} from '../src/core/minions/types.ts';

type DirectCall = {
  sql: string;
  params: unknown[] | undefined;
  opts: { signal?: AbortSignal } | undefined;
};

function frozenRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 17,
    name: 'facts-absorb',
    queue: 'default',
    status: 'waiting',
    priority: 0,
    data: { payload_lineage_version: 1 },
    max_attempts: 3,
    attempts_made: 0,
    attempts_started: 0,
    backoff_type: 'fixed',
    backoff_delay: 1000,
    backoff_jitter: 0,
    stalled_counter: 0,
    max_stalled: 5,
    lock_token: null,
    lock_until: null,
    delay_until: null,
    parent_job_id: null,
    on_child_fail: 'fail_parent',
    tokens_input: 0,
    tokens_output: 0,
    tokens_cache_read: 0,
    depth: 0,
    max_children: 1,
    timeout_ms: 60_000,
    lock_duration_ms: 30_000,
    timeout_at: null,
    remove_on_complete: false,
    remove_on_fail: false,
    idempotency_key: 'fixture-exact-target',
    private_queue_owner_job_id: null,
    private_queue_owner_token: null,
    private_queue_lease_until: null,
    budget_remaining_cents: null,
    budget_owner_job_id: null,
    budget_root_owner_id: null,
    quiet_hours: null,
    stagger_key: null,
    result: null,
    progress: null,
    error_text: null,
    stacktrace: [],
    created_at: '2026-08-30T00:00:00.000Z',
    started_at: null,
    finished_at: null,
    updated_at: '2026-08-30T00:00:00.000Z',
    ...overrides,
  };
}

function expectedRow(overrides: Record<string, unknown> = {}): ExactTargetFrozenRow {
  return rowToExactTargetFrozenRow(frozenRow(overrides));
}

function activeRow(lockToken = 'exact-token'): Record<string, unknown> {
  return frozenRow({
    status: 'active',
    attempts_started: 1,
    lock_token: lockToken,
    lock_until: '2026-08-30T00:01:00.000Z',
    timeout_at: '2026-08-30T00:01:00.000Z',
    started_at: '2026-08-30T00:00:00.100Z',
    updated_at: '2026-08-30T00:00:00.100Z',
  });
}

function schemaRows(fields: readonly string[] = EXACT_TARGET_JOB_FIELDS) {
  return fields.map((column_name) => ({ column_name }));
}

function connectionEnded(): Error & { code: string } {
  const error = new Error('write CONNECTION_ENDED') as Error & { code: string };
  error.code = 'CONNECTION_ENDED';
  return error;
}

function scriptedEngine(
  responses: Array<unknown[] | Error>,
): { engine: BrainEngine; calls: DirectCall[] } {
  const calls: DirectCall[] = [];
  const engine = {
    kind: 'postgres',
    executeRawDirect: async (
      sql: string,
      params?: unknown[],
      opts?: { signal?: AbortSignal },
    ) => {
      calls.push({ sql, params, opts });
      const response = responses.shift();
      if (response instanceof Error) throw response;
      if (!response) throw new Error('unexpected direct query');
      return response;
    },
    executeRaw: async () => {
      throw new Error('exact target lane must not use executeRaw');
    },
  } as unknown as BrainEngine;
  return { engine, calls };
}

describe('exact target 46-field row contract', () => {
  test('strict mapper accepts exactly 46 fields and preserves budget columns', () => {
    expect(EXACT_TARGET_JOB_FIELDS).toHaveLength(46);
    const row = rowToExactTargetFrozenRow(
      frozenRow({
        budget_remaining_cents: 125,
        budget_owner_job_id: 8,
        budget_root_owner_id: 3,
      }),
    );
    expect(Object.keys(row)).toEqual([...EXACT_TARGET_JOB_FIELDS]);
    expect(row.budget_remaining_cents).toBe(125);
    expect(row.budget_owner_job_id).toBe(8);
    expect(row.budget_root_owner_id).toBe(3);
  });

  test('strict mapper rejects missing, extra, and renamed fields', () => {
    const missing = frozenRow();
    delete missing.budget_root_owner_id;
    const extra = { ...frozenRow(), unexpected: true };
    const renamed = frozenRow();
    delete renamed.timeout_at;
    renamed.deadline_at = null;
    for (const row of [missing, extra, renamed]) {
      expect(() => rowToExactTargetFrozenRow(row)).toThrow('field set mismatch');
    }
  });

  test('general mapper repairs the three previously omitted budget fields', () => {
    const row = rowToMinionJob(
      frozenRow({
        budget_remaining_cents: 250,
        budget_owner_job_id: 9,
        budget_root_owner_id: 4,
      }),
    );
    expect(row.budget_remaining_cents).toBe(250);
    expect(row.budget_owner_job_id).toBe(9);
    expect(row.budget_root_owner_id).toBe(4);
  });
});

describe('exact target live schema gate', () => {
  test('uses only the direct lane and accepts order-independent exact equality', async () => {
    const { engine, calls } = scriptedEngine([schemaRows([...EXACT_TARGET_JOB_FIELDS].reverse())]);
    const signal = new AbortController().signal;
    await assertExactTargetSchema(engine, { signal });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.sql).toContain('information_schema.columns');
    expect(calls[0]!.opts?.signal).toBe(signal);
  });

  test('rejects missing, extra, and duplicate live columns', async () => {
    const cases = [
      EXACT_TARGET_JOB_FIELDS.slice(0, -1),
      [...EXACT_TARGET_JOB_FIELDS, 'unexpected'],
      [...EXACT_TARGET_JOB_FIELDS.slice(0, -1), EXACT_TARGET_JOB_FIELDS[0]],
    ];
    for (const fields of cases) {
      const { engine } = scriptedEngine([schemaRows(fields)]);
      await expect(assertExactTargetSchema(engine)).rejects.toThrow('field set mismatch');
    }
  });
});

describe('exact target one-shot direct claim', () => {
  test('runs one 46-predicate UPDATE with SKIP LOCKED and no fallback', async () => {
    const { engine, calls } = scriptedEngine([schemaRows(), [activeRow()]]);
    const queue = new MinionQueue(engine);
    const latch = new ExactClaimLatch();
    const result = await queue.claimExact(
      expectedRow(),
      'exact-token',
      45_000,
      latch,
    );

    expect(latch.consumed).toBe(true);
    expect(result.updates_attempted).toBe(1);
    expect(result.rows_returned).toBe(1);
    expect(result.same_token_readback).toBe('NOT_NEEDED');
    expect(result.job?.id).toBe(17);
    expect(calls).toHaveLength(2);
    const update = calls[1]!;
    expect(update.sql).toContain('FOR UPDATE SKIP LOCKED');
    expect(update.sql.match(/IS NOT DISTINCT FROM/g)).toHaveLength(46);
    expect(update.sql).toContain('::text::jsonb');
    expect(update.params).toHaveLength(48);
    expect(update.params?.at(-2)).toBe('exact-token');
    expect(update.params?.at(-1)).toBe(30_000);
  });

  test('consumes the latch before any await and forbids a second UPDATE', async () => {
    const { engine, calls } = scriptedEngine([schemaRows(), [activeRow()]]);
    const queue = new MinionQueue(engine);
    const latch = new ExactClaimLatch();
    await queue.claimExact(expectedRow(), 'exact-token', 30_000, latch);
    await expect(
      queue.claimExact(expectedRow(), 'exact-token', 30_000, latch),
    ).rejects.toThrow('latch already consumed');
    expect(calls.filter((call) => call.sql.includes('UPDATE minion_jobs'))).toHaveLength(1);
  });

  test('rejects a non-pristine or wrong-route target before schema or claim', async () => {
    for (const row of [
      expectedRow({ name: 'sync' }),
      expectedRow({ status: 'delayed' }),
      expectedRow({ attempts_started: 1 }),
      expectedRow({ budget_remaining_cents: 1 }),
    ]) {
      const { engine, calls } = scriptedEngine([]);
      await expect(
        new MinionQueue(engine).claimExact(
          row,
          'exact-token',
          30_000,
          new ExactClaimLatch(),
        ),
      ).rejects.toThrow('not the pristine facts-absorb target');
      expect(calls).toHaveLength(0);
    }
  });

  test('returns a zero-row refusal without retry or readback', async () => {
    const { engine, calls } = scriptedEngine([schemaRows(), []]);
    const result = await new MinionQueue(engine).claimExact(
      expectedRow(),
      'exact-token',
      30_000,
      new ExactClaimLatch(),
    );
    expect(result).toEqual({
      updates_attempted: 1,
      rows_returned: 0,
      same_token_readback: 'NOT_NEEDED',
      job: null,
    });
    expect(calls).toHaveLength(2);
  });
});

describe('exact target same-token lost-response readback', () => {
  test('recovers one active row by exact id and token without a second UPDATE', async () => {
    const { engine, calls } = scriptedEngine([
      schemaRows(),
      connectionEnded(),
      [activeRow('lost-response-token')],
    ]);
    const result = await new MinionQueue(engine).claimExact(
      expectedRow(),
      'lost-response-token',
      30_000,
      new ExactClaimLatch(),
    );
    expect(result.same_token_readback).toBe('RECOVERED');
    expect(result.job?.lock_token).toBe('lost-response-token');
    expect(calls.filter((call) => call.sql.includes('UPDATE minion_jobs'))).toHaveLength(1);
    expect(calls.filter((call) => call.sql.startsWith('SELECT id, name'))).toHaveLength(1);
    expect(calls[2]!.params).toEqual([17, 'lost-response-token']);
  });

  test('an absent or failed readback stays ambiguous and never retries UPDATE', async () => {
    for (const readback of [[], connectionEnded()]) {
      const { engine, calls } = scriptedEngine([
        schemaRows(),
        connectionEnded(),
        readback,
      ]);
      await expect(
        new MinionQueue(engine).claimExact(
          expectedRow(),
          'lost-response-token',
          30_000,
          new ExactClaimLatch(),
        ),
      ).rejects.toBeInstanceOf(ExactClaimAmbiguousError);
      expect(calls.filter((call) => call.sql.includes('UPDATE minion_jobs'))).toHaveLength(1);
      expect(calls).toHaveLength(3);
    }
  });

  test('direct readback rejects a malformed row instead of weakening the mapper', async () => {
    const malformed = activeRow();
    delete malformed.budget_owner_job_id;
    const { engine } = scriptedEngine([[malformed]]);
    await expect(
      readExactClaimByToken(engine, 17, 'exact-token'),
    ).rejects.toThrow('field set mismatch');
  });

  test('direct readback independently verifies id, active state, and same token', async () => {
    for (const row of [
      activeRow('wrong-token'),
      activeRow('exact-token') as Record<string, unknown>,
      { ...activeRow('exact-token'), id: 18 },
    ]) {
      if (row.lock_token === 'exact-token' && row.id === 17) row.status = 'waiting';
      const { engine } = scriptedEngine([[row]]);
      await expect(
        readExactClaimByToken(engine, 17, 'exact-token'),
      ).rejects.toThrow('readback identity mismatch');
    }
  });
});
