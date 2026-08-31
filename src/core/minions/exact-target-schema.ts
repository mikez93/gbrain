import { createHash } from 'node:crypto';
import { types as utilTypes } from 'node:util';
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
  LIVE_SCHEMA_INPUT_REJECTED: 'LIVE_SCHEMA_INPUT_REJECTED',
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
const INPUT_KEYS = [
  'attestation',
  'consumption_state',
  'expected_bindings',
  'now',
  'rows',
] as const;
const STATE_KEYS = ['key', 'status'] as const;
const HEX_64 = /^[0-9a-f]{64}$/;
const UTC_SIX_MICROSECONDS = /^\d{4}-(0[1-9]|1[0-2])-([0-2]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\d\.\d{6}Z$/;

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

type DataRecord = Readonly<Record<string, unknown>>;

function inspectOrdinaryDataRecord(
  value: unknown,
  expected: readonly string[],
): DataRecord | null {
  if (
    value === null ||
    typeof value !== 'object' ||
    utilTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    return null;
  }

  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== expected.length ||
    keys.some((key) => typeof key !== 'string')
  ) {
    return null;
  }
  const actual = [...(keys as string[])].sort();
  const wanted = [...expected].sort();
  if (!actual.every((key, index) => key === wanted[index])) return null;

  const snapshot: Record<string, unknown> = {};
  for (const key of expected) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !descriptor.enumerable ||
      !('value' in descriptor)
    ) {
      return null;
    }
    snapshot[key] = descriptor.value;
  }
  return snapshot;
}

function inspectDenseDataArray(value: unknown): readonly unknown[] | null {
  if (
    value === null ||
    typeof value !== 'object' ||
    utilTypes.isProxy(value) ||
    !Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Array.prototype
  ) {
    return null;
  }

  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
  if (
    lengthDescriptor === undefined ||
    !('value' in lengthDescriptor) ||
    lengthDescriptor.enumerable ||
    !Number.isSafeInteger(lengthDescriptor.value) ||
    lengthDescriptor.value < 0
  ) {
    return null;
  }
  const length = lengthDescriptor.value as number;
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== length + 1 ||
    keys.some((key) => typeof key !== 'string')
  ) {
    return null;
  }

  const snapshot: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (
      descriptor === undefined ||
      !descriptor.enumerable ||
      !('value' in descriptor)
    ) {
      return null;
    }
    snapshot.push(descriptor.value);
  }
  return snapshot;
}

function snapshotConsumptionState(
  value: unknown,
): ExactTargetAttestationConsumptionState | null {
  const record = inspectOrdinaryDataRecord(value, STATE_KEYS);
  if (record === null) return null;
  const { key, status } = record;
  if (
    typeof key !== 'string' ||
    !HEX_64.test(key) ||
    (status !== 'unused' && status !== 'consumed')
  ) {
    return null;
  }
  return Object.freeze({ key, status });
}

function stateSnapshotFromUnknownInput(
  value: unknown,
): ExactTargetAttestationConsumptionState | null {
  if (
    value === null ||
    typeof value !== 'object' ||
    utilTypes.isProxy(value)
  ) {
    return null;
  }
  const descriptor = Object.getOwnPropertyDescriptor(value, 'consumption_state');
  if (
    descriptor === undefined ||
    !descriptor.enumerable ||
    !('value' in descriptor)
  ) {
    return null;
  }
  return snapshotConsumptionState(descriptor.value);
}

function reject(
  reason_code: ExactTargetSchemaReason,
  consumption_state: ExactTargetAttestationConsumptionState | null,
): ExactTargetSchemaRejected {
  const stateSnapshot =
    consumption_state === null
      ? null
      : Object.freeze({
          key: consumption_state.key,
          status: consumption_state.status,
        });
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

interface ParsedValidateExactTargetSchemaInput {
  readonly rows: readonly ExactTargetSchemaRow[];
  readonly attestation: ExactTargetSchemaAttestation | null;
  readonly now: string;
  readonly consumption_state: ExactTargetAttestationConsumptionState;
  readonly expected_bindings: ExactTargetExpectedBindings;
}

function parseRows(value: unknown): readonly ExactTargetSchemaRow[] | null {
  const values = inspectDenseDataArray(value);
  if (values === null) return null;
  const rows: ExactTargetSchemaRow[] = [];
  for (const value of values) {
    const record = inspectOrdinaryDataRecord(value, ROW_KEYS);
    if (record === null) return null;
    const { column_name, data_type, udt_name, is_nullable } = record;
    if (
      typeof column_name !== 'string' ||
      typeof data_type !== 'string' ||
      typeof udt_name !== 'string' ||
      typeof is_nullable !== 'string'
    ) {
      return null;
    }
    rows.push({
      column_name,
      data_type,
      udt_name,
      is_nullable: is_nullable as 'YES' | 'NO',
    });
  }
  return rows;
}

function parseAttestation(value: unknown): ExactTargetSchemaAttestation | null | false {
  if (value === null) return null;
  const record = inspectOrdinaryDataRecord(value, ATTESTATION_KEYS);
  if (record === null) return false;
  const {
    acquired_at,
    brain_binding,
    column_count,
    current_schema,
    database_binding,
    expires_at,
    guardian_challenge_binding,
    hold_gate_binding,
    query_contract_sha256,
    schema_sha256,
    table_name,
    table_schema,
  } = record;
  if (
    typeof acquired_at !== 'string' ||
    typeof brain_binding !== 'string' ||
    typeof column_count !== 'number' ||
    !Number.isSafeInteger(column_count) ||
    typeof current_schema !== 'string' ||
    typeof database_binding !== 'string' ||
    typeof expires_at !== 'string' ||
    typeof guardian_challenge_binding !== 'string' ||
    typeof hold_gate_binding !== 'string' ||
    typeof query_contract_sha256 !== 'string' ||
    typeof schema_sha256 !== 'string' ||
    typeof table_name !== 'string' ||
    typeof table_schema !== 'string'
  ) {
    return false;
  }
  return {
    acquired_at,
    brain_binding,
    column_count,
    current_schema,
    database_binding,
    expires_at,
    guardian_challenge_binding,
    hold_gate_binding,
    query_contract_sha256,
    schema_sha256,
    table_name,
    table_schema,
  };
}

function parseExpectedBindings(value: unknown): ExactTargetExpectedBindings | null {
  const record = inspectOrdinaryDataRecord(value, EXPECTED_BINDING_KEYS);
  if (record === null) return null;
  const {
    brain_binding,
    current_schema,
    database_binding,
    guardian_challenge_binding,
    hold_gate_binding,
    table_name,
    table_schema,
  } = record;
  if (
    brain_binding !== 'private' ||
    database_binding !== 'mike_brain' ||
    current_schema !== 'public' ||
    table_schema !== 'public' ||
    table_name !== 'minion_jobs' ||
    typeof guardian_challenge_binding !== 'string' ||
    !HEX_64.test(guardian_challenge_binding) ||
    typeof hold_gate_binding !== 'string' ||
    !HEX_64.test(hold_gate_binding)
  ) {
    return null;
  }
  return {
    brain_binding,
    current_schema,
    database_binding,
    guardian_challenge_binding,
    hold_gate_binding,
    table_name,
    table_schema,
  };
}

function parseValidateExactTargetSchemaInput(
  value: unknown,
): ParsedValidateExactTargetSchemaInput | null {
  const record = inspectOrdinaryDataRecord(value, INPUT_KEYS);
  if (record === null || typeof record.now !== 'string') return null;
  const rows = parseRows(record.rows);
  const attestation = parseAttestation(record.attestation);
  const consumption_state = snapshotConsumptionState(record.consumption_state);
  const expected_bindings = parseExpectedBindings(record.expected_bindings);
  if (
    rows === null ||
    attestation === false ||
    consumption_state === null ||
    expected_bindings === null
  ) {
    return null;
  }
  return {
    rows,
    attestation,
    now: record.now,
    consumption_state,
    expected_bindings,
  };
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
  input: unknown,
): ExactTargetSchemaValidationResult {
  let safeState: ExactTargetAttestationConsumptionState | null = null;
  let parsed: ParsedValidateExactTargetSchemaInput | null = null;
  try {
    safeState = stateSnapshotFromUnknownInput(input);
    parsed = parseValidateExactTargetSchemaInput(input);
  } catch {
    return reject('LIVE_SCHEMA_INPUT_REJECTED', safeState);
  }
  if (parsed === null) {
    return reject('LIVE_SCHEMA_INPUT_REJECTED', safeState);
  }
  const { rows, attestation, now, consumption_state: state, expected_bindings } =
    parsed;
  if (state.key !== expected_bindings.guardian_challenge_binding) {
    return reject('SCHEMA_ATTESTATION_STATE_REJECTED', state);
  }

  const names = rows.map((row) => row.column_name);
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

  const normalized = [...rows].sort(compareColumnName);
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

  if (attestation === null) {
    return reject('SCHEMA_ATTESTATION_MISSING_REJECTED', state);
  }
  if (state.status === 'consumed') {
    return reject('SCHEMA_ATTESTATION_REUSED_REJECTED', state);
  }
  if (
    !validCanonicalTimestamp(now) ||
    !validCanonicalTimestamp(attestation.acquired_at) ||
    !validCanonicalTimestamp(attestation.expires_at) ||
    attestation.expires_at <= attestation.acquired_at ||
    now < attestation.acquired_at
  ) {
    return reject('SCHEMA_ATTESTATION_TIMESTAMP_REJECTED', state);
  }
  if (now >= attestation.expires_at) {
    return reject('SCHEMA_ATTESTATION_EXPIRED_REJECTED', state);
  }
  if (attestation.brain_binding !== expected_bindings.brain_binding) {
    return reject('SCHEMA_ATTESTATION_BRAIN_REJECTED', state);
  }
  if (attestation.database_binding !== expected_bindings.database_binding) {
    return reject('SCHEMA_ATTESTATION_DATABASE_REJECTED', state);
  }
  if (attestation.current_schema !== expected_bindings.current_schema) {
    return reject('SCHEMA_ATTESTATION_CURRENT_SCHEMA_REJECTED', state);
  }
  if (attestation.table_schema !== expected_bindings.table_schema) {
    return reject('SCHEMA_ATTESTATION_TABLE_SCHEMA_REJECTED', state);
  }
  if (attestation.table_name !== expected_bindings.table_name) {
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
    expected_bindings.guardian_challenge_binding
  ) {
    return reject('SCHEMA_ATTESTATION_GUARDIAN_CHALLENGE_REJECTED', state);
  }
  if (
    attestation.hold_gate_binding !== expected_bindings.hold_gate_binding
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
