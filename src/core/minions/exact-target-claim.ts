import type { BrainEngine } from '../engine.ts';
import { isRetryableConnError } from '../retry.ts';
import {
  EXACT_TARGET_JOB_FIELDS,
  rowToExactTargetFrozenRow,
  type ExactTargetFrozenRow,
  type ExactTargetJobField,
} from './types.ts';

const JSON_FIELDS = new Set<ExactTargetJobField>([
  'data',
  'quiet_hours',
  'result',
  'progress',
  'stacktrace',
]);
const TIMESTAMP_FIELDS = new Set<ExactTargetJobField>([
  'lock_until',
  'delay_until',
  'timeout_at',
  'private_queue_lease_until',
  'created_at',
  'started_at',
  'finished_at',
  'updated_at',
]);

export type ExactClaimReadback = 'NOT_NEEDED' | 'RECOVERED';

export interface ExactTargetClaimResult {
  updates_attempted: 1;
  rows_returned: 0 | 1;
  same_token_readback: ExactClaimReadback;
  job: ExactTargetFrozenRow | null;
}

/** One-use in-memory fence. `consume` is synchronous and precedes every await. */
export class ExactClaimLatch {
  #consumed = false;

  get consumed(): boolean {
    return this.#consumed;
  }

  consume(): void {
    if (this.#consumed) {
      throw new Error('exact target claim latch already consumed');
    }
    this.#consumed = true;
  }
}

/** A lost UPDATE response that could not be proven by same-token readback. */
export class ExactClaimAmbiguousError extends Error {
  constructor() {
    super('exact target claim outcome is ambiguous');
    this.name = 'ExactClaimAmbiguousError';
  }
}

function exactColumnsSql(prefix = ''): string {
  return EXACT_TARGET_JOB_FIELDS.map((field) => `${prefix}${field}`).join(', ');
}

function exactPredicate(field: ExactTargetJobField, parameter: number): string {
  if (JSON_FIELDS.has(field)) {
    return `${field} IS NOT DISTINCT FROM $${parameter}::text::jsonb`;
  }
  if (TIMESTAMP_FIELDS.has(field)) {
    return `${field} IS NOT DISTINCT FROM $${parameter}::timestamptz`;
  }
  return `${field} IS NOT DISTINCT FROM $${parameter}`;
}

function exactBindValue(
  row: ExactTargetFrozenRow,
  field: ExactTargetJobField,
): unknown {
  const value = row[field];
  if (JSON_FIELDS.has(field)) {
    const encoded = JSON.stringify(value);
    if (encoded === undefined) {
      throw new Error(`exact target JSON field is not serializable: ${field}`);
    }
    return encoded;
  }
  if (TIMESTAMP_FIELDS.has(field) && value instanceof Date) {
    if (!Number.isFinite(value.getTime())) {
      throw new Error(`exact target timestamp is invalid: ${field}`);
    }
    return value.toISOString();
  }
  return value;
}

function assertClaimableTarget(row: ExactTargetFrozenRow): void {
  const pristine =
    Number.isInteger(row.id) &&
    row.id > 0 &&
    row.name === 'facts-absorb' &&
    row.queue === 'default' &&
    row.status === 'waiting' &&
    row.attempts_made === 0 &&
    row.attempts_started === 0 &&
    row.stalled_counter === 0 &&
    row.lock_token === null &&
    row.lock_until === null &&
    row.delay_until === null &&
    row.tokens_input === 0 &&
    row.tokens_output === 0 &&
    row.tokens_cache_read === 0 &&
    row.depth === 0 &&
    row.timeout_at === null &&
    row.private_queue_owner_job_id === null &&
    row.private_queue_owner_token === null &&
    row.private_queue_lease_until === null &&
    row.budget_remaining_cents === null &&
    row.budget_owner_job_id === null &&
    row.budget_root_owner_id === null &&
    row.quiet_hours === null &&
    row.stagger_key === null &&
    row.result === null &&
    row.progress === null &&
    row.error_text === null &&
    row.started_at === null &&
    row.finished_at === null &&
    Array.isArray(row.stacktrace) &&
    row.stacktrace.length === 0 &&
    typeof row.data === 'object' &&
    row.data !== null &&
    !Array.isArray(row.data) &&
    typeof row.idempotency_key === 'string' &&
    row.idempotency_key.length > 0;
  if (!pristine) {
    throw new Error('exact target row is not the pristine facts-absorb target');
  }
}

/** Require the live table to contain exactly the frozen 46-column contract. */
export async function assertExactTargetSchema(
  engine: BrainEngine,
  opts?: { signal?: AbortSignal },
): Promise<void> {
  const rows = await engine.executeRawDirect<{ column_name: string }>(
    `SELECT column_name
       FROM information_schema.columns
       WHERE table_schema = current_schema() AND table_name = 'minion_jobs'
       ORDER BY ordinal_position`,
    undefined,
    opts,
  );
  const actual = rows.map((row) => row.column_name);
  const expected = new Set<string>(EXACT_TARGET_JOB_FIELDS);
  if (
    actual.length !== expected.size ||
    new Set(actual).size !== actual.length ||
    actual.some((field) => !expected.has(field))
  ) {
    throw new Error(
      `live minion_jobs field set mismatch (expected ${expected.size}, received ${actual.length})`,
    );
  }
}

/** One bounded direct-lane read used only after an ambiguous claim response. */
export async function readExactClaimByToken(
  engine: BrainEngine,
  id: number,
  lockToken: string,
  opts?: { signal?: AbortSignal },
): Promise<ExactTargetFrozenRow | null> {
  const rows = await engine.executeRawDirect<Record<string, unknown>>(
    `SELECT ${exactColumnsSql()}
       FROM minion_jobs
       WHERE id = $1 AND status = 'active' AND lock_token = $2
       LIMIT 1`,
    [id, lockToken],
    opts,
  );
  if (rows.length > 1) {
    throw new Error('exact target same-token readback returned multiple rows');
  }
  if (rows.length === 0) return null;
  const recovered = rowToExactTargetFrozenRow(rows[0]);
  if (
    recovered.id !== id ||
    recovered.status !== 'active' ||
    recovered.lock_token !== lockToken
  ) {
    throw new Error('exact target same-token readback identity mismatch');
  }
  return recovered;
}

/**
 * Attempt exactly one direct UPDATE. A retryable lost response gets one
 * same-ID/same-token readback and never a second mutation.
 */
export async function claimExactTarget(
  engine: BrainEngine,
  expectedInput: ExactTargetFrozenRow,
  lockToken: string,
  lockDurationMs: number,
  latch: ExactClaimLatch,
  opts?: { signal?: AbortSignal },
): Promise<ExactTargetClaimResult> {
  latch.consume();
  const expected = rowToExactTargetFrozenRow(
    expectedInput as Record<string, unknown>,
  );
  assertClaimableTarget(expected);
  const effectiveLockDurationMs = expected.lock_duration_ms ?? lockDurationMs;
  if (
    !lockToken ||
    !Number.isInteger(lockDurationMs) ||
    lockDurationMs <= 0 ||
    !Number.isInteger(effectiveLockDurationMs) ||
    effectiveLockDurationMs <= 0
  ) {
    throw new Error('exact target claim lock contract is invalid');
  }
  await assertExactTargetSchema(engine, opts);

  const values = EXACT_TARGET_JOB_FIELDS.map((field) =>
    exactBindValue(expected, field),
  );
  const lockTokenParam = values.length + 1;
  const lockDurationParam = values.length + 2;
  const timeoutParam = EXACT_TARGET_JOB_FIELDS.indexOf('timeout_ms') + 1;
  const predicates = EXACT_TARGET_JOB_FIELDS.map((field, index) =>
    exactPredicate(field, index + 1),
  ).join('\n           AND ');
  const sql = `WITH exact_candidate AS (
      SELECT id FROM minion_jobs
       WHERE ${predicates}
       FOR UPDATE SKIP LOCKED
       LIMIT 1
    )
    UPDATE minion_jobs AS job SET
      status = 'active',
      lock_token = $${lockTokenParam},
      lock_until = now() + ($${lockDurationParam}::double precision * interval '1 millisecond'),
      timeout_at = CASE WHEN $${timeoutParam}::int IS NULL THEN NULL
                        ELSE now() + ($${timeoutParam}::double precision * interval '1 millisecond') END,
      attempts_started = attempts_started + 1,
      started_at = now(),
      updated_at = now()
    FROM exact_candidate
    WHERE job.id = exact_candidate.id
    RETURNING ${exactColumnsSql('job.')}`;

  try {
    const rows = await engine.executeRawDirect<Record<string, unknown>>(
      sql,
      [...values, lockToken, effectiveLockDurationMs],
      opts,
    );
    if (rows.length > 1) {
      throw new Error('exact target claim returned multiple rows');
    }
    const job = rows.length === 1 ? rowToExactTargetFrozenRow(rows[0]) : null;
    return {
      updates_attempted: 1,
      rows_returned: job === null ? 0 : 1,
      same_token_readback: 'NOT_NEEDED',
      job,
    };
  } catch (error) {
    if (!isRetryableConnError(error)) throw error;
    try {
      const recovered = await readExactClaimByToken(
        engine,
        expected.id,
        lockToken,
        opts,
      );
      if (recovered !== null) {
        return {
          updates_attempted: 1,
          rows_returned: 1,
          same_token_readback: 'RECOVERED',
          job: recovered,
        };
      }
    } catch {
      // The response remains ambiguous. Never retry the mutation.
    }
    throw new ExactClaimAmbiguousError();
  }
}
