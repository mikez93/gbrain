import type {
  ExactTargetInt4,
  ExactTargetInt8Text,
  ExactTargetJsonText,
  ExactTargetTimestampText,
} from './exact-target-pure-types.ts';

/** Frozen transport order from the accepted 46-column v11 oracle. */
export const EXACT_TARGET_FIELDS = [
  'id',
  'name',
  'queue',
  'status',
  'priority',
  'data',
  'max_attempts',
  'attempts_made',
  'attempts_started',
  'backoff_type',
  'backoff_delay',
  'backoff_jitter',
  'stalled_counter',
  'max_stalled',
  'lock_token',
  'lock_until',
  'delay_until',
  'parent_job_id',
  'on_child_fail',
  'tokens_input',
  'tokens_output',
  'tokens_cache_read',
  'depth',
  'max_children',
  'timeout_ms',
  'lock_duration_ms',
  'timeout_at',
  'remove_on_complete',
  'remove_on_fail',
  'idempotency_key',
  'private_queue_owner_job_id',
  'private_queue_owner_token',
  'private_queue_lease_until',
  'budget_remaining_cents',
  'budget_owner_job_id',
  'budget_root_owner_id',
  'quiet_hours',
  'stagger_key',
  'result',
  'progress',
  'error_text',
  'stacktrace',
  'created_at',
  'started_at',
  'finished_at',
  'updated_at',
] as const;

export type ExactTargetField = (typeof EXACT_TARGET_FIELDS)[number];

/**
 * Lossless row representation. JSONB and timestamps remain PostgreSQL text;
 * bigint values never pass through JavaScript Number.
 */
export interface ExactTargetTransportRow {
  readonly id: ExactTargetInt4;
  readonly name: string;
  readonly queue: string;
  readonly status: string;
  readonly priority: ExactTargetInt4;
  readonly data: ExactTargetJsonText;
  readonly max_attempts: ExactTargetInt4;
  readonly attempts_made: ExactTargetInt4;
  readonly attempts_started: ExactTargetInt4;
  readonly backoff_type: string;
  readonly backoff_delay: ExactTargetInt4;
  readonly backoff_jitter: number;
  readonly stalled_counter: ExactTargetInt4;
  readonly max_stalled: ExactTargetInt4;
  readonly lock_token: string | null;
  readonly lock_until: ExactTargetTimestampText | null;
  readonly delay_until: ExactTargetTimestampText | null;
  readonly parent_job_id: ExactTargetInt4 | null;
  readonly on_child_fail: string;
  readonly tokens_input: ExactTargetInt4;
  readonly tokens_output: ExactTargetInt4;
  readonly tokens_cache_read: ExactTargetInt4;
  readonly depth: ExactTargetInt4;
  readonly max_children: ExactTargetInt4 | null;
  readonly timeout_ms: ExactTargetInt4 | null;
  readonly lock_duration_ms: ExactTargetInt4 | null;
  readonly timeout_at: ExactTargetTimestampText | null;
  readonly remove_on_complete: boolean;
  readonly remove_on_fail: boolean;
  readonly idempotency_key: string | null;
  readonly private_queue_owner_job_id: ExactTargetInt4 | null;
  readonly private_queue_owner_token: string | null;
  readonly private_queue_lease_until: ExactTargetTimestampText | null;
  readonly budget_remaining_cents: ExactTargetInt4 | null;
  readonly budget_owner_job_id: ExactTargetInt8Text | null;
  readonly budget_root_owner_id: ExactTargetInt8Text | null;
  readonly quiet_hours: ExactTargetJsonText | null;
  readonly stagger_key: string | null;
  readonly result: ExactTargetJsonText | null;
  readonly progress: ExactTargetJsonText | null;
  readonly error_text: string | null;
  readonly stacktrace: ExactTargetJsonText;
  readonly created_at: ExactTargetTimestampText;
  readonly started_at: ExactTargetTimestampText | null;
  readonly finished_at: ExactTargetTimestampText | null;
  readonly updated_at: ExactTargetTimestampText;
}

export const EXACT_TARGET_SCHEMA_DIGEST =
  '3e4ce8713061b39feff9cb0ba4ba9f9e321322231c743d41ad51bd350b26c4e6';

export const EXACT_TARGET_APPROVED_LOCK_DURATION_MS = 45_000;
