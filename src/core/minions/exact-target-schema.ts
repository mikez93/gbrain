import { createHash } from 'node:crypto';
import { EXACT_TARGET_SCHEMA_DIGEST } from './exact-target-contract.ts';

export interface ExactTargetSchemaRow {
  readonly column_name: string;
  readonly data_type: string;
  readonly udt_name: string;
  readonly is_nullable: 'YES' | 'NO';
}

export interface ExactTargetSchemaAttestation {
  readonly brain_binding: string;
  readonly database_binding: string;
  readonly current_schema: string;
  readonly table_schema: string;
  readonly table_name: string;
  readonly column_count: number;
  readonly schema_sha256: string;
  readonly query_contract_sha256: string;
  readonly guardian_challenge_binding: string;
  readonly hold_gate_binding: string;
  readonly acquired_at: string;
  readonly expires_at: string;
}

export interface ExactTargetExpectedBindings {
  readonly brain_binding: 'private';
  readonly database_binding: 'mike_brain';
  readonly current_schema: 'public';
  readonly table_schema: 'public';
  readonly table_name: 'minion_jobs';
  readonly guardian_challenge_binding: string;
  readonly hold_gate_binding: string;
}

export interface ExactTargetAttestationConsumptionState {
  readonly key: string;
  readonly status: 'unused' | 'consumed';
}

export const EXACT_TARGET_SCHEMA_QUERY =
  "SELECT column_name || '|' || data_type || '|' || udt_name || '|' || is_nullable FROM information_schema.columns WHERE table_schema='public' AND table_name='minion_jobs' ORDER BY column_name";

export const EXACT_TARGET_SCHEMA_QUERY_BYTES = 189;
export const EXACT_TARGET_SCHEMA_QUERY_SHA256 =
  'd781ae8d2de684611ed7e098a3e7f4ded15a7c7f7b2cb37dee8ebf283fc1ed77';
export const EXACT_TARGET_SCHEMA_QUERY_WITH_LF_SHA256 =
  '81e0a914d5f9a89bbe8945b6c598aebcc7983b135fb4acb4a07ab9104ce3cd9f';
export const EXACT_TARGET_SCHEMA_SERIALIZED_BYTES = 1527;

export const EXACT_TARGET_ATTESTATION_SCOPE_LIMIT =
  'Order 1 proves only the pure unused-to-consumed transition when the returned state is threaded forward; replaying a stale unused state remains possible until a later durable atomic owner consumes it.';

const schemaRows: ExactTargetSchemaRow[] = [
  ['attempts_made', 'integer', 'int4', 'NO'],
  ['attempts_started', 'integer', 'int4', 'NO'],
  ['backoff_delay', 'integer', 'int4', 'NO'],
  ['backoff_jitter', 'real', 'float4', 'NO'],
  ['backoff_type', 'text', 'text', 'NO'],
  ['budget_owner_job_id', 'bigint', 'int8', 'YES'],
  ['budget_remaining_cents', 'integer', 'int4', 'YES'],
  ['budget_root_owner_id', 'bigint', 'int8', 'YES'],
  ['created_at', 'timestamp with time zone', 'timestamptz', 'NO'],
  ['data', 'jsonb', 'jsonb', 'NO'],
  ['delay_until', 'timestamp with time zone', 'timestamptz', 'YES'],
  ['depth', 'integer', 'int4', 'NO'],
  ['error_text', 'text', 'text', 'YES'],
  ['finished_at', 'timestamp with time zone', 'timestamptz', 'YES'],
  ['id', 'integer', 'int4', 'NO'],
  ['idempotency_key', 'text', 'text', 'YES'],
  ['lock_duration_ms', 'integer', 'int4', 'YES'],
  ['lock_token', 'text', 'text', 'YES'],
  ['lock_until', 'timestamp with time zone', 'timestamptz', 'YES'],
  ['max_attempts', 'integer', 'int4', 'NO'],
  ['max_children', 'integer', 'int4', 'YES'],
  ['max_stalled', 'integer', 'int4', 'NO'],
  ['name', 'text', 'text', 'NO'],
  ['on_child_fail', 'text', 'text', 'NO'],
  ['parent_job_id', 'integer', 'int4', 'YES'],
  ['priority', 'integer', 'int4', 'NO'],
  ['private_queue_lease_until', 'timestamp with time zone', 'timestamptz', 'YES'],
  ['private_queue_owner_job_id', 'integer', 'int4', 'YES'],
  ['private_queue_owner_token', 'text', 'text', 'YES'],
  ['progress', 'jsonb', 'jsonb', 'YES'],
  ['queue', 'text', 'text', 'NO'],
  ['quiet_hours', 'jsonb', 'jsonb', 'YES'],
  ['remove_on_complete', 'boolean', 'bool', 'NO'],
  ['remove_on_fail', 'boolean', 'bool', 'NO'],
  ['result', 'jsonb', 'jsonb', 'YES'],
  ['stacktrace', 'jsonb', 'jsonb', 'YES'],
  ['stagger_key', 'text', 'text', 'YES'],
  ['stalled_counter', 'integer', 'int4', 'NO'],
  ['started_at', 'timestamp with time zone', 'timestamptz', 'YES'],
  ['status', 'text', 'text', 'NO'],
  ['timeout_at', 'timestamp with time zone', 'timestamptz', 'YES'],
  ['timeout_ms', 'integer', 'int4', 'YES'],
  ['tokens_cache_read', 'integer', 'int4', 'NO'],
  ['tokens_input', 'integer', 'int4', 'NO'],
  ['tokens_output', 'integer', 'int4', 'NO'],
  ['updated_at', 'timestamp with time zone', 'timestamptz', 'NO'],
].map(([column_name, data_type, udt_name, is_nullable]) =>
  Object.freeze({
    column_name,
    data_type,
    udt_name,
    is_nullable: is_nullable as 'YES' | 'NO',
  }),
);

export const EXACT_TARGET_SCHEMA_ROWS: readonly ExactTargetSchemaRow[] =
  Object.freeze(schemaRows);

export const EXACT_TARGET_SCHEMA_REASON_FAMILIES = Object.freeze({
  LIVE_SCHEMA_COLUMN_MISSING_REJECTED: 'LIVE_SCHEMA_STRUCTURE_REJECTED',
  LIVE_SCHEMA_COLUMN_DUPLICATE_REJECTED: 'LIVE_SCHEMA_STRUCTURE_REJECTED',
  LIVE_SCHEMA_COLUMN_EXTRA_REJECTED: 'LIVE_SCHEMA_STRUCTURE_REJECTED',
  LIVE_SCHEMA_TYPE_REJECTED: 'LIVE_SCHEMA_TYPE_REJECTED',
  LIVE_SCHEMA_UDT_REJECTED: 'LIVE_SCHEMA_UDT_REJECTED',
  LIVE_SCHEMA_NULLABILITY_REJECTED: 'LIVE_SCHEMA_NULLABILITY_REJECTED',
  LIVE_SCHEMA_DIGEST_REJECTED: 'LIVE_SCHEMA_DIGEST_REJECTED',
  SCHEMA_ATTESTATION_MISSING_REJECTED:
    'SCHEMA_ATTESTATION_FRESHNESS_REJECTED',
  SCHEMA_ATTESTATION_EXPIRED_REJECTED:
    'SCHEMA_ATTESTATION_FRESHNESS_REJECTED',
  SCHEMA_ATTESTATION_REUSED_REJECTED:
    'SCHEMA_ATTESTATION_FRESHNESS_REJECTED',
  SCHEMA_ATTESTATION_BRAIN_REJECTED:
    'SCHEMA_ATTESTATION_PROVENANCE_REJECTED',
  SCHEMA_ATTESTATION_DATABASE_REJECTED:
    'SCHEMA_ATTESTATION_PROVENANCE_REJECTED',
  SCHEMA_ATTESTATION_CURRENT_SCHEMA_REJECTED:
    'SCHEMA_ATTESTATION_PROVENANCE_REJECTED',
  SCHEMA_ATTESTATION_TABLE_SCHEMA_REJECTED:
    'SCHEMA_ATTESTATION_PROVENANCE_REJECTED',
  SCHEMA_ATTESTATION_TABLE_NAME_REJECTED:
    'SCHEMA_ATTESTATION_PROVENANCE_REJECTED',
  SCHEMA_ATTESTATION_ROW_COUNT_REJECTED:
    'SCHEMA_ATTESTATION_PROVENANCE_REJECTED',
  SCHEMA_ATTESTATION_QUERY_CONTRACT_REJECTED:
    'SCHEMA_ATTESTATION_PROVENANCE_REJECTED',
  SCHEMA_ATTESTATION_GUARDIAN_CHALLENGE_REJECTED:
    'SCHEMA_ATTESTATION_PROVENANCE_REJECTED',
  SCHEMA_ATTESTATION_HOLD_BINDING_REJECTED:
    'SCHEMA_ATTESTATION_PROVENANCE_REJECTED',
  SCHEMA_ATTESTATION_TIMESTAMP_REJECTED:
    'SCHEMA_ATTESTATION_FRESHNESS_REJECTED',
  SCHEMA_ATTESTATION_STATE_REJECTED:
    'SCHEMA_ATTESTATION_FRESHNESS_REJECTED',
} as const);

export type ExactTargetSchemaReason =
  keyof typeof EXACT_TARGET_SCHEMA_REASON_FAMILIES;
export type ExactTargetSchemaReasonFamily =
  (typeof EXACT_TARGET_SCHEMA_REASON_FAMILIES)[ExactTargetSchemaReason];

export interface ExactTargetSchemaRejected {
  readonly ok: false;
  readonly reason_code: ExactTargetSchemaReason;
  readonly reason_family: ExactTargetSchemaReasonFamily;
  readonly consumption_state: ExactTargetAttestationConsumptionState | null;
}

export interface ExactTargetSchemaAccepted {
  readonly ok: true;
  readonly normalized_rows: readonly ExactTargetSchemaRow[];
  readonly serialization: string;
  readonly serialized_bytes: 1527;
  readonly schema_sha256: typeof EXACT_TARGET_SCHEMA_DIGEST;
  readonly consumption_state: ExactTargetAttestationConsumptionState & {
    readonly status: 'consumed';
  };
  readonly scope_limit: typeof EXACT_TARGET_ATTESTATION_SCOPE_LIMIT;
}

export type ExactTargetSchemaValidationResult =
  | ExactTargetSchemaAccepted
  | ExactTargetSchemaRejected;

export interface ValidateExactTargetSchemaInput {
  readonly rows: readonly ExactTargetSchemaRow[];
  readonly attestation: ExactTargetSchemaAttestation | null;
  readonly now: string;
  readonly consumption_state: ExactTargetAttestationConsumptionState;
  readonly expected_bindings: ExactTargetExpectedBindings;
}

const ROW_KEYS = [
  'column_name',
  'data_type',
  'is_nullable',
  'udt_name',
] as const;
const ATTESTATION_KEYS = [
  'acquired_at',
  'brain_binding',
  'column_count',
  'current_schema',
  'database_binding',
  'expires_at',
  'guardian_challenge_binding',
  'hold_gate_binding',
  'query_contract_sha256',
  'schema_sha256',
  'table_name',
  'table_schema',
] as const;
const EXPECTED_BINDING_KEYS = [
  'brain_binding',
  'current_schema',
  'database_binding',
  'guardian_challenge_binding',
  'hold_gate_binding',
  'table_name',
  'table_schema',
] as const;
const HEX_64 = /^[0-9a-f]{64}$/;
const UTC_SIX_MICROSECONDS = /^\d{4}-(0[1-9]|1[0-2])-([0-2]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\d\.\d{6}Z$/;

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function exactKeys(value: object, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  return (
    actual.length === expected.length &&
    actual.every((key, index) => key === expected[index])
  );
}

function reject(
  reason_code: ExactTargetSchemaReason,
  consumption_state: ExactTargetAttestationConsumptionState | null,
): ExactTargetSchemaRejected {
  const stateSnapshot =
    consumption_state === null
      ? null
      : Object.freeze({ ...consumption_state });
  return Object.freeze({
    ok: false,
    reason_code,
    reason_family: EXACT_TARGET_SCHEMA_REASON_FAMILIES[reason_code],
    consumption_state: stateSnapshot,
  });
}

function validCanonicalTimestamp(value: unknown): value is string {
  if (typeof value !== 'string') {
    return false;
  }
  const match = UTC_SIX_MICROSECONDS.exec(value);
  if (match === null) return false;
  const year = Number(value.slice(0, 4));
  const month = Number(value.slice(5, 7));
  const day = Number(value.slice(8, 10));
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const daysInMonth = [
    31,
    leapYear ? 29 : 28,
    31,
    30,
    31,
    30,
    31,
    31,
    30,
    31,
    30,
    31,
  ];
  return year >= 1 && day >= 1 && day <= daysInMonth[month - 1]!;
}

function compareColumnName(
  left: ExactTargetSchemaRow,
  right: ExactTargetSchemaRow,
): number {
  return left.column_name < right.column_name
    ? -1
    : left.column_name > right.column_name
      ? 1
      : 0;
}

export function serializeExactTargetSchema(
  rows: readonly ExactTargetSchemaRow[],
): string {
  return rows
    .map(
      (row) =>
        `${row.column_name}|${row.data_type}|${row.udt_name}|${row.is_nullable}\n`,
    )
    .join('');
}

export function digestExactTargetSchema(
  rows: readonly ExactTargetSchemaRow[],
): string {
  return sha256(serializeExactTargetSchema(rows));
}

export function validateExactTargetDigestEquality(
  computed: string,
  attested: string,
): ExactTargetSchemaReason | null {
  return computed === attested && attested === EXACT_TARGET_SCHEMA_DIGEST
    ? null
    : 'LIVE_SCHEMA_DIGEST_REJECTED';
}

export function validateExactTargetSchema(
  input: ValidateExactTargetSchemaInput | null | undefined,
): ExactTargetSchemaValidationResult {
  if (!input || typeof input !== 'object') {
    return reject('SCHEMA_ATTESTATION_STATE_REJECTED', null);
  }
  const state = input.consumption_state;
  if (
    !Array.isArray(input.rows) ||
    !state ||
    typeof state !== 'object' ||
    !exactKeys(state, ['key', 'status']) ||
    !HEX_64.test(state.key) ||
    (state.status !== 'unused' && state.status !== 'consumed') ||
    !input.expected_bindings ||
    !exactKeys(input.expected_bindings, EXPECTED_BINDING_KEYS) ||
    input.expected_bindings.brain_binding !== 'private' ||
    input.expected_bindings.database_binding !== 'mike_brain' ||
    input.expected_bindings.current_schema !== 'public' ||
    input.expected_bindings.table_schema !== 'public' ||
    input.expected_bindings.table_name !== 'minion_jobs' ||
    !HEX_64.test(input.expected_bindings.guardian_challenge_binding) ||
    !HEX_64.test(input.expected_bindings.hold_gate_binding) ||
    state.key !== input.expected_bindings.guardian_challenge_binding
  ) {
    return reject('SCHEMA_ATTESTATION_STATE_REJECTED', state);
  }

  for (const row of input.rows) {
    if (
      !row ||
      typeof row !== 'object' ||
      !exactKeys(row, ROW_KEYS) ||
      typeof row.column_name !== 'string'
    ) {
      return reject('LIVE_SCHEMA_COLUMN_EXTRA_REJECTED', state);
    }
  }

  const names = input.rows.map((row) => row.column_name);
  if (new Set(names).size !== names.length) {
    return reject('LIVE_SCHEMA_COLUMN_DUPLICATE_REJECTED', state);
  }

  const canonicalNames = new Set(
    EXACT_TARGET_SCHEMA_ROWS.map((row) => row.column_name),
  );
  if (names.some((name) => !canonicalNames.has(name))) {
    return reject('LIVE_SCHEMA_COLUMN_EXTRA_REJECTED', state);
  }
  if (
    EXACT_TARGET_SCHEMA_ROWS.some(
      (canonical) => !names.includes(canonical.column_name),
    )
  ) {
    return reject('LIVE_SCHEMA_COLUMN_MISSING_REJECTED', state);
  }

  const normalized = [...input.rows].sort(compareColumnName);
  for (const [index, canonical] of EXACT_TARGET_SCHEMA_ROWS.entries()) {
    const actual = normalized[index]!;
    if (actual.data_type !== canonical.data_type) {
      return reject('LIVE_SCHEMA_TYPE_REJECTED', state);
    }
    if (actual.udt_name !== canonical.udt_name) {
      return reject('LIVE_SCHEMA_UDT_REJECTED', state);
    }
    if (actual.is_nullable !== canonical.is_nullable) {
      return reject('LIVE_SCHEMA_NULLABILITY_REJECTED', state);
    }
  }

  const attestation = input.attestation;
  if (attestation === null || attestation === undefined) {
    return reject('SCHEMA_ATTESTATION_MISSING_REJECTED', state);
  }
  if (!exactKeys(attestation, ATTESTATION_KEYS)) {
    return reject('SCHEMA_ATTESTATION_STATE_REJECTED', state);
  }
  if (state.status === 'consumed') {
    return reject('SCHEMA_ATTESTATION_REUSED_REJECTED', state);
  }
  if (
    !validCanonicalTimestamp(input.now) ||
    !validCanonicalTimestamp(attestation.acquired_at) ||
    !validCanonicalTimestamp(attestation.expires_at) ||
    attestation.expires_at <= attestation.acquired_at ||
    input.now < attestation.acquired_at
  ) {
    return reject('SCHEMA_ATTESTATION_TIMESTAMP_REJECTED', state);
  }
  if (input.now >= attestation.expires_at) {
    return reject('SCHEMA_ATTESTATION_EXPIRED_REJECTED', state);
  }
  if (attestation.brain_binding !== input.expected_bindings.brain_binding) {
    return reject('SCHEMA_ATTESTATION_BRAIN_REJECTED', state);
  }
  if (attestation.database_binding !== input.expected_bindings.database_binding) {
    return reject('SCHEMA_ATTESTATION_DATABASE_REJECTED', state);
  }
  if (attestation.current_schema !== input.expected_bindings.current_schema) {
    return reject('SCHEMA_ATTESTATION_CURRENT_SCHEMA_REJECTED', state);
  }
  if (attestation.table_schema !== input.expected_bindings.table_schema) {
    return reject('SCHEMA_ATTESTATION_TABLE_SCHEMA_REJECTED', state);
  }
  if (attestation.table_name !== input.expected_bindings.table_name) {
    return reject('SCHEMA_ATTESTATION_TABLE_NAME_REJECTED', state);
  }
  if (attestation.column_count !== EXACT_TARGET_SCHEMA_ROWS.length) {
    return reject('SCHEMA_ATTESTATION_ROW_COUNT_REJECTED', state);
  }
  if (
    sha256(EXACT_TARGET_SCHEMA_QUERY) !== EXACT_TARGET_SCHEMA_QUERY_SHA256 ||
    attestation.query_contract_sha256 !== EXACT_TARGET_SCHEMA_QUERY_SHA256
  ) {
    return reject('SCHEMA_ATTESTATION_QUERY_CONTRACT_REJECTED', state);
  }
  if (
    attestation.guardian_challenge_binding !==
    input.expected_bindings.guardian_challenge_binding
  ) {
    return reject('SCHEMA_ATTESTATION_GUARDIAN_CHALLENGE_REJECTED', state);
  }
  if (
    attestation.hold_gate_binding !== input.expected_bindings.hold_gate_binding
  ) {
    return reject('SCHEMA_ATTESTATION_HOLD_BINDING_REJECTED', state);
  }

  const serialization = serializeExactTargetSchema(normalized);
  const computed = sha256(serialization);
  const digestReason = validateExactTargetDigestEquality(
    computed,
    attestation.schema_sha256,
  );
  if (digestReason !== null) return reject(digestReason, state);

  const acceptedRows = Object.freeze(
    normalized.map((row) => Object.freeze({ ...row })),
  );
  return Object.freeze({
    ok: true,
    normalized_rows: acceptedRows,
    serialization,
    serialized_bytes: EXACT_TARGET_SCHEMA_SERIALIZED_BYTES,
    schema_sha256: EXACT_TARGET_SCHEMA_DIGEST,
    consumption_state: Object.freeze({ key: state.key, status: 'consumed' }),
    scope_limit: EXACT_TARGET_ATTESTATION_SCOPE_LIMIT,
  });
}
