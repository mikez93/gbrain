import { describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import type {
  ExactTargetAttestationConsumptionState,
  ExactTargetExpectedBindings,
  ExactTargetSchemaAttestation,
  ExactTargetSchemaReason,
  ExactTargetSchemaRow,
  ValidateExactTargetSchemaInput,
} from '../src/core/minions/exact-target-schema.ts';

const schema = await import('../src/core/minions/exact-target-schema.ts');
const {
  EXACT_TARGET_ATTESTATION_SCOPE_LIMIT,
  EXACT_TARGET_SCHEMA_QUERY,
  EXACT_TARGET_SCHEMA_QUERY_BYTES,
  EXACT_TARGET_SCHEMA_QUERY_SHA256,
  EXACT_TARGET_SCHEMA_QUERY_WITH_LF_SHA256,
  EXACT_TARGET_SCHEMA_REASON_FAMILIES,
  EXACT_TARGET_SCHEMA_ROWS,
  EXACT_TARGET_SCHEMA_SERIALIZED_BYTES,
  digestExactTargetSchema,
  serializeExactTargetSchema,
  validateExactTargetDigestEquality,
  validateExactTargetSchema,
} = schema;

const DIGEST =
  '3e4ce8713061b39feff9cb0ba4ba9f9e321322231c743d41ad51bd350b26c4e6';
const GUARDIAN = 'a'.repeat(64);
const HOLD = 'b'.repeat(64);
const NOW = '2026-08-30T00:01:00.000000Z';
const FOCUSED_COMMAND_ARGV = [
  'bun',
  '--config=/dev/null',
  'test',
  'test/exact-target-schema-pure.test.ts',
] as const;
const ORDER1_PARENT_DESIGN_SHA256 =
  '128a5f55ba0a20a30247d21466ae5e07ed7e038b73dca88a9c383276edd9a367';
const ORDER1_GAP_MAP_SHA256 =
  'e30f63659ed74cd32b61f6a0271a586ea54f214a979102b6ce6bb4cb3c22a62e';
const ORDER1_EXTERNAL_GATES_V7_HISTORICAL_SHA256 =
  '5550ff092982b895f4e08a1948a23f0357ac23cafae71eec6ba570a638bef9fc';
const ORDER1_EXTERNAL_GATES_V8_CONTROLLING_SHA256 =
  '3e5ef48a9ab7aa5e3a807552e6d2536bac73d9c1c560431202c0c34c83fe8081';
const ORDER1_CHECKLIST_V4_SHA256 =
  '9ff1a6af181e1964e8e798e8b8e390df4f7db34ad1ee99c41fe80db349ea6410';

const EXPECTED_ROW_LINES = [
  'attempts_made|integer|int4|NO',
  'attempts_started|integer|int4|NO',
  'backoff_delay|integer|int4|NO',
  'backoff_jitter|real|float4|NO',
  'backoff_type|text|text|NO',
  'budget_owner_job_id|bigint|int8|YES',
  'budget_remaining_cents|integer|int4|YES',
  'budget_root_owner_id|bigint|int8|YES',
  'created_at|timestamp with time zone|timestamptz|NO',
  'data|jsonb|jsonb|NO',
  'delay_until|timestamp with time zone|timestamptz|YES',
  'depth|integer|int4|NO',
  'error_text|text|text|YES',
  'finished_at|timestamp with time zone|timestamptz|YES',
  'id|integer|int4|NO',
  'idempotency_key|text|text|YES',
  'lock_duration_ms|integer|int4|YES',
  'lock_token|text|text|YES',
  'lock_until|timestamp with time zone|timestamptz|YES',
  'max_attempts|integer|int4|NO',
  'max_children|integer|int4|YES',
  'max_stalled|integer|int4|NO',
  'name|text|text|NO',
  'on_child_fail|text|text|NO',
  'parent_job_id|integer|int4|YES',
  'priority|integer|int4|NO',
  'private_queue_lease_until|timestamp with time zone|timestamptz|YES',
  'private_queue_owner_job_id|integer|int4|YES',
  'private_queue_owner_token|text|text|YES',
  'progress|jsonb|jsonb|YES',
  'queue|text|text|NO',
  'quiet_hours|jsonb|jsonb|YES',
  'remove_on_complete|boolean|bool|NO',
  'remove_on_fail|boolean|bool|NO',
  'result|jsonb|jsonb|YES',
  'stacktrace|jsonb|jsonb|YES',
  'stagger_key|text|text|YES',
  'stalled_counter|integer|int4|NO',
  'started_at|timestamp with time zone|timestamptz|YES',
  'status|text|text|NO',
  'timeout_at|timestamp with time zone|timestamptz|YES',
  'timeout_ms|integer|int4|YES',
  'tokens_cache_read|integer|int4|NO',
  'tokens_input|integer|int4|NO',
  'tokens_output|integer|int4|NO',
  'updated_at|timestamp with time zone|timestamptz|NO',
] as const;

const EXPECTED_BINDINGS: ExactTargetExpectedBindings = Object.freeze({
  brain_binding: 'private',
  database_binding: 'mike_brain',
  current_schema: 'public',
  table_schema: 'public',
  table_name: 'minion_jobs',
  guardian_challenge_binding: GUARDIAN,
  hold_gate_binding: HOLD,
});

const ATTESTATION: ExactTargetSchemaAttestation = Object.freeze({
  brain_binding: 'private',
  database_binding: 'mike_brain',
  current_schema: 'public',
  table_schema: 'public',
  table_name: 'minion_jobs',
  column_count: 46,
  schema_sha256: DIGEST,
  query_contract_sha256: EXACT_TARGET_SCHEMA_QUERY_SHA256,
  guardian_challenge_binding: GUARDIAN,
  hold_gate_binding: HOLD,
  acquired_at: '2026-08-30T00:00:00.000000Z',
  expires_at: '2026-08-30T00:05:00.000000Z',
});

const UNUSED: ExactTargetAttestationConsumptionState = Object.freeze({
  key: GUARDIAN,
  status: 'unused',
});

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function cloneRows(): ExactTargetSchemaRow[] {
  return EXACT_TARGET_SCHEMA_ROWS.map((row) => ({ ...row }));
}

function input(
  overrides: Partial<ValidateExactTargetSchemaInput> = {},
): ValidateExactTargetSchemaInput {
  return {
    rows: cloneRows(),
    attestation: { ...ATTESTATION },
    now: NOW,
    consumption_state: { ...UNUSED },
    expected_bindings: { ...EXPECTED_BINDINGS },
    ...overrides,
  };
}

function validate(
  value: unknown,
): ReturnType<typeof validateExactTargetSchema> {
  return validateExactTargetSchema(value);
}

type RejectedDecision = Extract<
  ReturnType<typeof validateExactTargetSchema>,
  { readonly ok: false }
>;

function expectReason(
  value: ValidateExactTargetSchemaInput,
  reason: ExactTargetSchemaReason,
): RejectedDecision {
  const previousState = value.consumption_state;
  let result: ReturnType<typeof validateExactTargetSchema> | undefined;
  expect(() => {
    result = validate(value);
  }).not.toThrow();
  if (result === undefined) throw new Error(`missing rejection ${reason}`);
  expect(result.ok).toBe(false);
  if (result.ok) throw new Error(`expected rejection ${reason}`);
  expect(result.reason_code).toBe(reason);
  expect(result.reason_family).toBe(EXACT_TARGET_SCHEMA_REASON_FAMILIES[reason]);
  expect(result.consumption_state).toEqual(previousState);
  expect(result.consumption_state).not.toBe(previousState);
  expect(recursivelyFrozen(result)).toBe(true);
  return result;
}

function replaceRow(
  rows: readonly ExactTargetSchemaRow[],
  name: string,
  patch: Partial<ExactTargetSchemaRow>,
): ExactTargetSchemaRow[] {
  return rows.map((row) =>
    row.column_name === name ? { ...row, ...patch } : { ...row },
  );
}

function seededPermutation(rows: readonly ExactTargetSchemaRow[]) {
  const seed = 'gbrain-order1-schema-permutation-v1';
  return [...rows].sort((left, right) =>
    createHash('sha256')
      .update(`${seed}\0${left.column_name}`)
      .digest()
      .compare(
        createHash('sha256')
          .update(`${seed}\0${right.column_name}`)
          .digest(),
      ),
  );
}

const mutationIds = new Set<string>();
const mutationHistogram: Record<string, number> = {
  per_column_missing: 0,
  per_column_data_type_change: 0,
  per_column_udt_name_change: 0,
  per_column_is_nullable_change: 0,
  singletons: 0,
};
const mutationReasons = new Set<ExactTargetSchemaReason>();
const parentMutationResults: Record<string, unknown>[] = [];
const parentPositiveResults: Record<string, unknown>[] = [];

function recordMutation(
  id: string,
  group: keyof typeof mutationHistogram,
  value: ValidateExactTargetSchemaInput,
  reason: ExactTargetSchemaReason,
): void {
  expect(mutationIds.has(id), `duplicate mutation id: ${id}`).toBe(false);
  mutationIds.add(id);
  mutationHistogram[group] += 1;
  const result = expectReason(value, reason);
  mutationReasons.add(result.reason_code);
  parentMutationResults.push({
    id,
    group,
    reason: result.reason_code,
    family: result.reason_family,
    pass: true,
    no_throw: true,
    decision_recursive_frozen: recursivelyFrozen(result),
    state_nonaliased: result.consumption_state !== value.consumption_state,
    decision_graph_sha256: graphSha256(result),
  });
}

type StateKind = 'frozen_copy' | 'null';
type X1Case = {
  readonly id: string;
  readonly make: () => unknown;
  readonly stateKind: StateKind;
  readonly exotic?: boolean;
  readonly nonEnumerable?: boolean;
};

function mutableInput(): Record<string, unknown> {
  return input() as unknown as Record<string, unknown>;
}

function withTopLevelMutation(
  mutate: (value: Record<string, unknown>) => void,
): () => unknown {
  return () => {
    const value = mutableInput();
    mutate(value);
    return value;
  };
}

function withRowsMutation(mutate: (rows: unknown[]) => void): () => unknown {
  return withTopLevelMutation((value) => {
    const rows = value.rows as unknown[];
    mutate(rows);
  });
}

function withRowMutation(
  mutate: (row: Record<PropertyKey, unknown>) => void,
): () => unknown {
  return withRowsMutation((rows) => mutate(rows[0] as Record<PropertyKey, unknown>));
}

function withAttestationMutation(
  mutate: (attestation: Record<PropertyKey, unknown>) => void,
): () => unknown {
  return withTopLevelMutation((value) =>
    mutate(value.attestation as Record<PropertyKey, unknown>),
  );
}

function withExpectedMutation(
  mutate: (bindings: Record<PropertyKey, unknown>) => void,
): () => unknown {
  return withTopLevelMutation((value) =>
    mutate(value.expected_bindings as Record<PropertyKey, unknown>),
  );
}

function withStateMutation(
  mutate: (state: Record<PropertyKey, unknown>) => void,
): () => unknown {
  return withTopLevelMutation((value) =>
    mutate(value.consumption_state as Record<PropertyKey, unknown>),
  );
}

function throwingGetter(target: object, key: PropertyKey): void {
  Object.defineProperty(target, key, {
    enumerable: true,
    configurable: true,
    get() {
      throw new Error('attacker getter invoked');
    },
  });
}

function nonEnumerable(target: object, key: PropertyKey): void {
  const descriptor = Object.getOwnPropertyDescriptor(target, key);
  if (descriptor === undefined || !('value' in descriptor)) {
    throw new Error(`missing data property ${String(key)}`);
  }
  Object.defineProperty(target, key, { ...descriptor, enumerable: false });
}

const runtimeValues: readonly [string, () => unknown][] = [
  ['null', () => null],
  ['object', () => ({})],
  ['array', () => []],
  ['function', () => function attacker() {}],
  ['number', () => 0],
  ['boolean', () => false],
  ['bigint', () => 0n],
  ['symbol', () => Symbol('attacker')],
];

class Attacker {}
const exoticValues: readonly [string, () => object][] = [
  ['date', () => new Date(0)],
  ['map', () => new Map()],
  ['set', () => new Set()],
  ['boxed', () => new Number(0)],
  ['custom-class', () => new Attacker()],
];

function buildX1Cases(): X1Case[] {
  const cases: X1Case[] = [
    { id: 'X1-TL-null', make: () => null, stateKind: 'null' },
    { id: 'X1-TL-undefined', make: () => undefined, stateKind: 'null' },
    { id: 'X1-TL-boolean', make: () => false, stateKind: 'null' },
    { id: 'X1-TL-number', make: () => 0, stateKind: 'null' },
    { id: 'X1-TL-string', make: () => 'invalid', stateKind: 'null' },
    { id: 'X1-TL-bigint', make: () => 0n, stateKind: 'null' },
    { id: 'X1-TL-symbol', make: () => Symbol('attacker'), stateKind: 'null' },
    { id: 'X1-TL-function', make: () => function attacker() {}, stateKind: 'null' },
    { id: 'X1-TL-array', make: () => [], stateKind: 'null' },
    { id: 'X1-TL-empty_object', make: () => ({}), stateKind: 'null' },
    {
      id: 'X1-TL-proxy',
      make: () =>
        new Proxy(mutableInput(), {
          ownKeys() {
            throw new Error('attacker ownKeys trap invoked');
          },
          getOwnPropertyDescriptor() {
            throw new Error('attacker descriptor trap invoked');
          },
        }),
      stateKind: 'null',
    },
    {
      id: 'X1-TL-extra-key',
      make: withTopLevelMutation((value) => {
        value.attacker_marker = true;
      }),
      stateKind: 'frozen_copy',
    },
    {
      id: 'X1-TL-symbol-key',
      make: withTopLevelMutation((value) => {
        value[Symbol('attacker')] = true;
      }),
      stateKind: 'frozen_copy',
    },
  ];

  for (const key of ['rows', 'attestation', 'now', 'consumption_state', 'expected_bindings']) {
    cases.push({
      id: `X1-TL-missing-${key.replace('_', '_')}`,
      make: withTopLevelMutation((value) => {
        delete value[key];
      }),
      stateKind: key === 'consumption_state' ? 'null' : 'frozen_copy',
    });
  }
  for (const key of ['rows', 'attestation', 'now', 'consumption_state', 'expected_bindings']) {
    cases.push({
      id: `X1-TL-accessor-${key}`,
      make: withTopLevelMutation((value) => throwingGetter(value, key)),
      stateKind: key === 'consumption_state' ? 'null' : 'frozen_copy',
    });
  }
  for (const key of ['rows', 'attestation', 'now', 'consumption_state', 'expected_bindings']) {
    cases.push({
      id: `X1-TL-inherited-${key}`,
      make: withTopLevelMutation((value) => {
        const inherited = value[key];
        delete value[key];
        Object.setPrototypeOf(value, { [key]: inherited });
      }),
      stateKind: key === 'consumption_state' ? 'null' : 'frozen_copy',
    });
  }

  cases.push(
    { id: 'X1-ROWS-null', make: withTopLevelMutation((v) => { v.rows = null; }), stateKind: 'frozen_copy' },
    { id: 'X1-ROWS-object', make: withTopLevelMutation((v) => { v.rows = {}; }), stateKind: 'frozen_copy' },
    { id: 'X1-ROWS-sparse', make: withRowsMutation((rows) => { delete rows[0]; }), stateKind: 'frozen_copy' },
    { id: 'X1-ROWS-proxy', make: withTopLevelMutation((v) => { v.rows = new Proxy(v.rows as object, {}); }), stateKind: 'frozen_copy' },
    { id: 'X1-ROWS-accessor_element', make: withRowsMutation((rows) => throwingGetter(rows, 0)), stateKind: 'frozen_copy' },
    { id: 'X1-ROWS-row_null', make: withRowsMutation((rows) => { rows[0] = null; }), stateKind: 'frozen_copy' },
    { id: 'X1-ROWS-row_array', make: withRowsMutation((rows) => { rows[0] = []; }), stateKind: 'frozen_copy' },
    { id: 'X1-ROWS-row_proxy', make: withRowsMutation((rows) => { rows[0] = new Proxy(rows[0] as object, {}); }), stateKind: 'frozen_copy' },
    { id: 'X1-ROWS-row_missing_key', make: withRowMutation((row) => { delete row.udt_name; }), stateKind: 'frozen_copy' },
    { id: 'X1-ROWS-row_extra_key', make: withRowMutation((row) => { row.attacker = true; }), stateKind: 'frozen_copy' },
    { id: 'X1-ROWS-row_symbol_key', make: withRowMutation((row) => { row[Symbol('attacker')] = true; }), stateKind: 'frozen_copy' },
    {
      id: 'X1-ROWS-row_inherited_coordinate',
      make: withRowMutation((row) => {
        const columnName = row.column_name;
        delete row.column_name;
        Object.setPrototypeOf(row, { column_name: columnName });
      }),
      stateKind: 'frozen_copy',
    },
  );

  for (const coordinate of ['column_name', 'data_type', 'udt_name', 'is_nullable']) {
    for (const [kind, makeValue] of runtimeValues) {
      cases.push({
        id: `X1-ROW-${coordinate}-${kind}`,
        make: withRowMutation((row) => { row[coordinate] = makeValue(); }),
        stateKind: 'frozen_copy',
      });
    }
    cases.push({
      id: `X1-ROW-${coordinate}-accessor`,
      make: withRowMutation((row) => throwingGetter(row, coordinate)),
      stateKind: 'frozen_copy',
    });
    cases.push({
      id: `X1-ROW-${coordinate}-proxy`,
      make: withRowMutation((row) => { row[coordinate] = new Proxy({}, {}); }),
      stateKind: 'frozen_copy',
    });
  }

  cases.push(
    { id: 'X1-ATT-array', make: withTopLevelMutation((v) => { v.attestation = []; }), stateKind: 'frozen_copy' },
    { id: 'X1-ATT-empty', make: withTopLevelMutation((v) => { v.attestation = {}; }), stateKind: 'frozen_copy' },
    { id: 'X1-ATT-proxy', make: withTopLevelMutation((v) => { v.attestation = new Proxy(v.attestation as object, {}); }), stateKind: 'frozen_copy' },
    { id: 'X1-ATT-extra', make: withAttestationMutation((v) => { v.attacker_marker = true; }), stateKind: 'frozen_copy' },
    { id: 'X1-ATT-symbol', make: withAttestationMutation((v) => { v[Symbol('attacker')] = true; }), stateKind: 'frozen_copy' },
    { id: 'X1-ATT-accessor', make: withAttestationMutation((v) => throwingGetter(v, 'brain_binding')), stateKind: 'frozen_copy' },
  );
  for (const coordinate of [
    'brain_binding', 'database_binding', 'current_schema', 'table_schema',
    'table_name', 'column_count', 'schema_sha256', 'query_contract_sha256',
    'guardian_challenge_binding', 'hold_gate_binding', 'acquired_at', 'expires_at',
  ]) {
    cases.push({
      id: `X1-ATT-${coordinate}-wrong-type`,
      make: withAttestationMutation((value) => {
        value[coordinate] = coordinate === 'column_count' ? '46' : 0;
      }),
      stateKind: 'frozen_copy',
    });
  }
  for (const [kind, invalid] of [
    ['nan', Number.NaN],
    ['positive-infinity', Number.POSITIVE_INFINITY],
    ['negative-infinity', Number.NEGATIVE_INFINITY],
    ['fraction', 46.5],
    ['unsafe-integer', Number.MAX_SAFE_INTEGER + 1],
  ] as const) {
    cases.push({
      id: `X1-ATT-column_count-${kind}`,
      make: withAttestationMutation((value) => { value.column_count = invalid; }),
      stateKind: 'frozen_copy',
    });
  }

  cases.push(
    { id: 'X1-EXP-null', make: withTopLevelMutation((v) => { v.expected_bindings = null; }), stateKind: 'frozen_copy' },
    { id: 'X1-EXP-array', make: withTopLevelMutation((v) => { v.expected_bindings = []; }), stateKind: 'frozen_copy' },
    { id: 'X1-EXP-empty', make: withTopLevelMutation((v) => { v.expected_bindings = {}; }), stateKind: 'frozen_copy' },
    { id: 'X1-EXP-proxy', make: withTopLevelMutation((v) => { v.expected_bindings = new Proxy(v.expected_bindings as object, {}); }), stateKind: 'frozen_copy' },
    { id: 'X1-EXP-extra', make: withExpectedMutation((v) => { v.attacker_marker = true; }), stateKind: 'frozen_copy' },
    { id: 'X1-EXP-symbol', make: withExpectedMutation((v) => { v[Symbol('attacker')] = true; }), stateKind: 'frozen_copy' },
    { id: 'X1-EXP-accessor', make: withExpectedMutation((v) => throwingGetter(v, 'brain_binding')), stateKind: 'frozen_copy' },
  );
  for (const coordinate of [
    'brain_binding', 'database_binding', 'current_schema', 'table_schema',
    'table_name', 'guardian_challenge_binding', 'hold_gate_binding',
  ]) {
    cases.push({
      id: `X1-EXP-${coordinate}-wrong-type`,
      make: withExpectedMutation((value) => { value[coordinate] = 0; }),
      stateKind: 'frozen_copy',
    });
  }

  const nowRuntimeValues: readonly [string, () => unknown][] = [
    ['null', () => null],
    ['number', () => 0],
    ['object', () => ({})],
    ['array', () => []],
    ['function', () => function attacker() {}],
    ['boolean', () => false],
    ['bigint', () => 0n],
    ['symbol', () => Symbol('attacker')],
  ];
  for (const [kind, makeValue] of nowRuntimeValues) {
    cases.push({
      id: `X1-NOW-${kind}`,
      make: withTopLevelMutation((value) => { value.now = makeValue(); }),
      stateKind: 'frozen_copy',
    });
  }

  cases.push(
    { id: 'X1-STATE-null', make: withTopLevelMutation((v) => { v.consumption_state = null; }), stateKind: 'null' },
    { id: 'X1-STATE-array', make: withTopLevelMutation((v) => { v.consumption_state = []; }), stateKind: 'null' },
    { id: 'X1-STATE-empty', make: withTopLevelMutation((v) => { v.consumption_state = {}; }), stateKind: 'null' },
    { id: 'X1-STATE-proxy', make: withTopLevelMutation((v) => { v.consumption_state = new Proxy(v.consumption_state as object, {}); }), stateKind: 'null' },
    { id: 'X1-STATE-extra', make: withStateMutation((v) => { v.attacker_marker = true; }), stateKind: 'null' },
    { id: 'X1-STATE-symbol', make: withStateMutation((v) => { v[Symbol('attacker')] = true; }), stateKind: 'null' },
    { id: 'X1-STATE-key-accessor', make: withStateMutation((v) => throwingGetter(v, 'key')), stateKind: 'null' },
    { id: 'X1-STATE-status-accessor', make: withStateMutation((v) => throwingGetter(v, 'status')), stateKind: 'null' },
  );
  for (const coordinate of ['key', 'status']) {
    for (const [kind, makeValue] of runtimeValues) {
      cases.push({
        id: `X1-STATE-${coordinate}-${kind}`,
        make: withStateMutation((value) => { value[coordinate] = makeValue(); }),
        stateKind: 'null',
      });
    }
    cases.push({
      id: `X1-STATE-${coordinate}-proxy`,
      make: withStateMutation((value) => { value[coordinate] = new Proxy({}, {}); }),
      stateKind: 'null',
    });
  }
  cases.push(
    { id: 'X1-STATE-key-short', make: withStateMutation((v) => { v.key = 'a'.repeat(63); }), stateKind: 'null' },
    { id: 'X1-STATE-key-uppercase', make: withStateMutation((v) => { v.key = 'A'.repeat(64); }), stateKind: 'null' },
    { id: 'X1-STATE-status-bogus', make: withStateMutation((v) => { v.status = 'bogus'; }), stateKind: 'null' },
  );

  cases.push(
    {
      id: 'X1-DEF-proxy-ownKeys-throws',
      make: () => new Proxy(mutableInput(), { ownKeys() { throw new Error('ownKeys'); } }),
      stateKind: 'null',
    },
    {
      id: 'X1-DEF-proxy-getOwnPropertyDescriptor-throws',
      make: () => new Proxy(mutableInput(), { getOwnPropertyDescriptor() { throw new Error('descriptor'); } }),
      stateKind: 'null',
    },
    {
      id: 'X1-DEF-nested-getter-throws',
      make: withRowMutation((row) => throwingGetter(row, 'column_name')),
      stateKind: 'frozen_copy',
    },
  );

  for (const [kind, makeValue] of exoticValues) {
    cases.push({ id: `X1-EXOTIC-top_level-${kind}`, make: makeValue, stateKind: 'null', exotic: true });
  }
  for (const [coordinate, mutate] of [
    ['row', (value: Record<string, unknown>, exotic: object) => { (value.rows as unknown[])[0] = exotic; }],
    ['attestation', (value: Record<string, unknown>, exotic: object) => { value.attestation = exotic; }],
    ['expected_bindings', (value: Record<string, unknown>, exotic: object) => { value.expected_bindings = exotic; }],
    ['consumption_state', (value: Record<string, unknown>, exotic: object) => { value.consumption_state = exotic; }],
  ] as const) {
    for (const [kind, makeValue] of exoticValues) {
      cases.push({
        id: `X1-EXOTIC-${coordinate}-${kind}`,
        make: withTopLevelMutation((value) => mutate(value, makeValue())),
        stateKind: coordinate === 'consumption_state' ? 'null' : 'frozen_copy',
        exotic: true,
      });
    }
  }

  cases.push(
    { id: 'X1-NONENUM-top_level', make: withTopLevelMutation((v) => nonEnumerable(v, 'rows')), stateKind: 'frozen_copy', nonEnumerable: true },
    { id: 'X1-NONENUM-row', make: withRowMutation((v) => nonEnumerable(v, 'column_name')), stateKind: 'frozen_copy', nonEnumerable: true },
    { id: 'X1-NONENUM-attestation', make: withAttestationMutation((v) => nonEnumerable(v, 'brain_binding')), stateKind: 'frozen_copy', nonEnumerable: true },
    { id: 'X1-NONENUM-expected_bindings', make: withExpectedMutation((v) => nonEnumerable(v, 'brain_binding')), stateKind: 'frozen_copy', nonEnumerable: true },
    { id: 'X1-NONENUM-consumption_state', make: withStateMutation((v) => nonEnumerable(v, 'key')), stateKind: 'null', nonEnumerable: true },
  );
  return cases;
}

function primitiveEncoding(value: unknown): string {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'undefined': return 'undefined';
    case 'string': return `string:${JSON.stringify(value)}`;
    case 'boolean': return `boolean:${value}`;
    case 'number': return `number:${Object.is(value, -0) ? '-0' : String(value)}`;
    case 'bigint': return `bigint:${value}`;
    case 'symbol': return `symbol:${String(value.description)}`;
    case 'function': return `function:${value.name}`;
    default: return `unknown:${String(value)}`;
  }
}

function descriptorGraph(value: unknown): string {
  const references = new Map<object, number>();
  const encode = (current: unknown): unknown => {
    if ((typeof current !== 'object' || current === null) && typeof current !== 'function') {
      return primitiveEncoding(current);
    }
    const object = current as object;
    const seen = references.get(object);
    if (seen !== undefined) return { ref: seen };
    const id = references.size;
    references.set(object, id);
    const prototype = Object.getPrototypeOf(object);
    const prototypeName = prototype === Object.prototype
      ? 'Object.prototype'
      : prototype === Array.prototype
        ? 'Array.prototype'
        : prototype === null
          ? 'null'
          : `other:${prototype?.constructor?.name ?? 'unknown'}`;
    const keys = Reflect.ownKeys(object).sort((left, right) => {
      const a = typeof left === 'string' ? `0:${left}` : `1:${left.description ?? ''}`;
      const b = typeof right === 'string' ? `0:${right}` : `1:${right.description ?? ''}`;
      return a.localeCompare(b);
    });
    return {
      id,
      kind: Array.isArray(object) ? 'array' : 'object',
      prototype: prototypeName,
      properties: keys.map((key) => {
        const descriptor = Object.getOwnPropertyDescriptor(object, key)!;
        const name = typeof key === 'string' ? `string:${key}` : `symbol:${key.description ?? ''}`;
        if ('value' in descriptor) {
          return {
            name,
            enumerable: descriptor.enumerable,
            configurable: descriptor.configurable,
            writable: descriptor.writable,
            value: encode(descriptor.value),
          };
        }
        return {
          name,
          enumerable: descriptor.enumerable,
          configurable: descriptor.configurable,
          getter: descriptor.get ? `function:${descriptor.get.name}` : 'absent',
          setter: descriptor.set ? `function:${descriptor.set.name}` : 'absent',
        };
      }),
    };
  };
  return JSON.stringify(encode(value));
}

function graphSha256(value: unknown): string {
  return sha256(descriptorGraph(value));
}

function recursivelyFrozen(value: unknown, seen = new Set<object>()): boolean {
  if ((typeof value !== 'object' || value === null) && typeof value !== 'function') return true;
  const object = value as object;
  if (seen.has(object)) return true;
  seen.add(object);
  if (!Object.isFrozen(object)) return false;
  for (const key of Reflect.ownKeys(object)) {
    const descriptor = Object.getOwnPropertyDescriptor(object, key)!;
    if ('value' in descriptor && !recursivelyFrozen(descriptor.value, seen)) return false;
  }
  return true;
}

function objectReferences(value: unknown): Set<object> {
  const references = new Set<object>();
  const visit = (current: unknown): void => {
    if ((typeof current !== 'object' || current === null) && typeof current !== 'function') {
      return;
    }
    const object = current as object;
    if (references.has(object)) return;
    references.add(object);
    for (const key of Reflect.ownKeys(object)) {
      const descriptor = Object.getOwnPropertyDescriptor(object, key)!;
      if ('value' in descriptor) visit(descriptor.value);
    }
  };
  visit(value);
  return references;
}

function recordParentPositive(
  id: string,
  result: AcceptedDecision,
): void {
  parentPositiveResults.push({
    id,
    pass: true,
    normalized_rows: result.normalized_rows.length,
    serialized_bytes: result.serialized_bytes,
    schema_sha256: result.schema_sha256,
    state_status: result.consumption_state.status,
    decision_recursive_frozen: recursivelyFrozen(result),
    decision_graph_sha256: graphSha256(result),
  });
}

function impossibleMutation(mutate: () => unknown): { threw: boolean; result: unknown } {
  try {
    return { threw: false, result: mutate() };
  } catch {
    return { threw: true, result: null };
  }
}

type AcceptedDecision = Extract<
  ReturnType<typeof validateExactTargetSchema>,
  { readonly ok: true }
>;

type X3OutputOperation = {
  readonly id: string;
  readonly target: string;
  readonly operation: string;
  readonly aliasDerivation: string | null;
  readonly mutate: () => unknown;
  readonly reflectFalse?: boolean;
};

function buildX3OutputOperations(decision: AcceptedDecision): X3OutputOperation[] {
  const mutableDecision = decision as unknown as Record<string, unknown>;
  const rows = decision.normalized_rows as unknown as unknown[];
  const operations: X3OutputOperation[] = [
    { id: 'X3-O001-decision-ok-set', target: 'decision.ok', operation: 'strict assignment', aliasDerivation: null, mutate: () => { mutableDecision.ok = false; } },
    { id: 'X3-O002-decision-serialized_bytes-delete', target: 'decision.serialized_bytes', operation: 'strict delete', aliasDerivation: null, mutate: () => delete mutableDecision.serialized_bytes },
    { id: 'X3-O003-decision-scope_limit-redefine', target: 'decision.scope_limit', operation: 'Object.defineProperty', aliasDerivation: null, mutate: () => Object.defineProperty(decision, 'scope_limit', { value: 'attacker', configurable: true }) },
    { id: 'X3-O004', target: 'decision', operation: 'setPrototypeOf', aliasDerivation: null, mutate: () => Object.setPrototypeOf(decision, { attacker: true }) },
    { id: 'X3-O005', target: 'normalized_rows', operation: 'reorder', aliasDerivation: null, mutate: () => rows.reverse() },
    { id: 'X3-O006', target: 'normalized_rows', operation: 'splice', aliasDerivation: null, mutate: () => rows.splice(0, 1) },
    { id: 'X3-O007', target: 'normalized_rows', operation: 'append', aliasDerivation: null, mutate: () => rows.push({ attacker: true }) },
    { id: 'X3-O008', target: 'normalized_rows', operation: 'delete', aliasDerivation: null, mutate: () => delete rows[0] },
    { id: 'X3-O009', target: 'normalized_rows', operation: 'redefine', aliasDerivation: null, mutate: () => Object.defineProperty(rows, '0', { value: { attacker: true } }) },
    { id: 'X3-O010', target: 'normalized_rows', operation: 'setPrototypeOf', aliasDerivation: null, mutate: () => Object.setPrototypeOf(rows, { attacker: true }) },
  ];
  let sequence = 11;
  for (const [index, row] of decision.normalized_rows.entries()) {
    const mutableRow = row as unknown as Record<string, unknown>;
    const prefix = `normalized_rows[${index}]`;
    operations.push(
      { id: `X3-O${String(sequence++).padStart(3, '0')}`, target: prefix, operation: 'set', aliasDerivation: null, mutate: () => { mutableRow.column_name = 'attacker'; } },
      { id: `X3-O${String(sequence++).padStart(3, '0')}`, target: prefix, operation: 'delete', aliasDerivation: null, mutate: () => delete mutableRow.column_name },
      { id: `X3-O${String(sequence++).padStart(3, '0')}`, target: prefix, operation: 'redefine', aliasDerivation: null, mutate: () => Object.defineProperty(row, 'column_name', { value: 'attacker' }) },
      { id: `X3-O${String(sequence++).padStart(3, '0')}`, target: prefix, operation: 'setPrototypeOf', aliasDerivation: null, mutate: () => Object.setPrototypeOf(row, { attacker: true }) },
    );
  }
  const state = decision.consumption_state;
  const mutableState = state as unknown as Record<string, unknown>;
  operations.push(
    { id: 'X3-O195', target: 'decision.serialization', operation: 'replace', aliasDerivation: null, mutate: () => { mutableDecision.serialization = 'attacker'; } },
    { id: 'X3-O196-decision-schema_sha256-replace', target: 'decision.schema_sha256', operation: 'strict assignment replace exact property value', aliasDerivation: null, mutate: () => { mutableDecision.schema_sha256 = '0'.repeat(64); } },
    { id: 'X3-O197-consumption_state-key-set', target: 'state.key where state = decision.consumption_state', operation: 'strict assignment', aliasDerivation: 'const state = decision.consumption_state', mutate: () => { mutableState.key = 'c'.repeat(64); } },
    { id: 'X3-O198-consumption_state-key-delete', target: 'state.key where state = decision.consumption_state', operation: 'strict delete', aliasDerivation: 'const state = decision.consumption_state', mutate: () => delete mutableState.key },
    { id: 'X3-O199-consumption_state-key-redefine', target: 'state.key where state = decision.consumption_state', operation: 'Object.defineProperty', aliasDerivation: 'const state = decision.consumption_state', mutate: () => Object.defineProperty(state, 'key', { value: 'c'.repeat(64), configurable: true }) },
    { id: 'X3-O200-consumption_state-key-reflect-set', target: 'state.key where state = decision.consumption_state', operation: 'Reflect.set', aliasDerivation: 'const state = decision.consumption_state', mutate: () => Reflect.set(state, 'key', 'c'.repeat(64)), reflectFalse: true },
    { id: 'X3-O201-consumption_state-status-set', target: 'state.status where state = decision.consumption_state', operation: 'strict assignment', aliasDerivation: 'const state = decision.consumption_state', mutate: () => { mutableState.status = 'unused'; } },
    { id: 'X3-O202-consumption_state-status-delete', target: 'state.status where state = decision.consumption_state', operation: 'strict delete', aliasDerivation: 'const state = decision.consumption_state', mutate: () => delete mutableState.status },
    { id: 'X3-O203-consumption_state-status-redefine', target: 'state.status where state = decision.consumption_state', operation: 'Object.defineProperty', aliasDerivation: 'const state = decision.consumption_state', mutate: () => Object.defineProperty(state, 'status', { value: 'unused', configurable: true }) },
    { id: 'X3-O204-consumption_state-status-reflect-delete', target: 'state.status where state = decision.consumption_state', operation: 'Reflect.deleteProperty', aliasDerivation: 'const state = decision.consumption_state', mutate: () => Reflect.deleteProperty(state, 'status'), reflectFalse: true },
    { id: 'X3-O205-decision-consumption_state-set', target: 'decision.consumption_state', operation: 'replace exact property value', aliasDerivation: null, mutate: () => { mutableDecision.consumption_state = { key: 'c'.repeat(64), status: 'unused' }; } },
    { id: 'X3-O206-decision-consumption_state-delete', target: 'decision.consumption_state', operation: 'delete exact property', aliasDerivation: null, mutate: () => delete mutableDecision.consumption_state },
    { id: 'X3-O207-decision-consumption_state-redefine', target: 'decision.consumption_state', operation: 'Object.defineProperty exact property', aliasDerivation: null, mutate: () => Object.defineProperty(decision, 'consumption_state', { value: null, configurable: true }) },
    { id: 'X3-O208-consumption_state-alias-setPrototypeOf', target: 'state alias derived from decision.consumption_state', operation: 'Object.setPrototypeOf(state, attackerPrototype)', aliasDerivation: 'const state = decision.consumption_state', mutate: () => Object.setPrototypeOf(state, { attacker: true }) },
    { id: 'X3-O209-consumption_state-alias-extend', target: 'state alias derived from decision.consumption_state', operation: 'add own enumerable attacker_marker property', aliasDerivation: 'const state = decision.consumption_state', mutate: () => { mutableState.attacker_marker = true; } },
  );
  return operations;
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(',')}]`;
  }
  if (value !== null && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

const X1_MUTATION_EXPECTED =
  'strict-mode throw or observably impossible; recursively canonicalized decision graph bytes unchanged';

function x1CatalogEntry(
  id: string,
  caseId: string,
  stateKind: StateKind,
  target: string,
  operation: string,
): Record<string, unknown> {
  return {
    id,
    case_id: caseId,
    state_kind: stateKind,
    target,
    operation,
    expected: X1_MUTATION_EXPECTED,
  };
}

function x1MutationRecipe(target: string, operation: string): string {
  if (target === 'decision_root') {
    if (operation === 'set') return "strict assignment decision.reason_code='attacker'";
    if (operation === 'delete') return 'strict delete decision.reason_code';
    if (operation === 'redefine') {
      return "Object.defineProperty(decision,'reason_code',{value:'attacker'})";
    }
    return 'Object.setPrototypeOf(decision,attackerPrototype)';
  }
  if (target === 'consumption_state') {
    return 'Object.setPrototypeOf(decision.consumption_state,attackerPrototype)';
  }
  const property = target.endsWith('.key') ? 'key' : 'status';
  if (operation === 'set') return `strict assignment decision.consumption_state.${property}`;
  if (operation === 'delete') return `strict delete decision.consumption_state.${property}`;
  return `Object.defineProperty(decision.consumption_state,'${property}',attackerDescriptor)`;
}

function x3CatalogEntry(operation: X3OutputOperation): Record<string, unknown> {
  const genericExpected =
    'strict-mode throw or observably impossible; recursively inspected graph remains byte/value-identical';
  const detailed: Readonly<Record<string, Record<string, unknown>>> = {
    'X3-O001-decision-ok-set': {
      id: operation.id,
      target: operation.target,
      operation: operation.operation,
      recipe:
        'On an accepted decision, in strict mode assign false to exact own property decision.ok.',
      alias_derivation: null,
      cause_bound_observation:
        'strict assignment throws or is observably impossible because the real own data property is frozen/nonwritable; no abstract-local binding path',
      expected: 'full descriptor-graph before/after SHA-256 equal and decision.ok remains true',
    },
    'X3-O002-decision-serialized_bytes-delete': {
      id: operation.id,
      target: operation.target,
      operation: operation.operation,
      recipe:
        'On an accepted decision, in strict mode delete exact own property decision.serialized_bytes.',
      alias_derivation: null,
      cause_bound_observation:
        'strict delete throws or is observably impossible because the real own property is nonconfigurable; no abstract-local binding path',
      expected:
        'full descriptor-graph before/after SHA-256 equal and decision.serialized_bytes remains 1527',
    },
    'X3-O003-decision-scope_limit-redefine': {
      id: operation.id,
      target: operation.target,
      operation: operation.operation,
      recipe:
        'On an accepted decision, call Object.defineProperty(decision, "scope_limit", {value:"attacker", configurable:true}).',
      alias_derivation: null,
      cause_bound_observation:
        'defineProperty throws because the real frozen own property is nonconfigurable; no abstract-local or missing-property path',
      expected:
        'full descriptor-graph before/after SHA-256 equal and decision.scope_limit remains exact accepted constant',
    },
    'X3-O196-decision-schema_sha256-replace': {
      id: operation.id,
      target: operation.target,
      operation: operation.operation,
      recipe:
        'In strict mode assign an attacker digest string to exact own property decision.schema_sha256.',
      alias_derivation: null,
      cause_bound_observation:
        'throw or observably impossible because decision property is frozen; no missing-property or primitive-TypeError path',
      expected: 'full descriptor-graph before/after SHA-256 equal',
    },
    'X3-O197-consumption_state-key-set': {
      id: operation.id,
      target: operation.target,
      operation: operation.operation,
      recipe:
        'Derive `const state = decision.consumption_state`; assert exact frozen returned state/nonalias; in strict mode assign a different 64-lowercase-hex value to state.key.',
      alias_derivation: operation.aliasDerivation,
      cause_bound_observation:
        'strict assignment throws or is impossible on the real frozen key property',
      expected: 'full descriptor-graph before/after SHA-256 equal',
    },
    'X3-O198-consumption_state-key-delete': {
      id: operation.id,
      target: operation.target,
      operation: operation.operation,
      recipe: 'Derive exact state alias; in strict mode delete state.key.',
      alias_derivation: operation.aliasDerivation,
      cause_bound_observation:
        'strict delete throws or is impossible on the real nonconfigurable key property',
      expected: 'full descriptor-graph before/after SHA-256 equal',
    },
    'X3-O199-consumption_state-key-redefine': {
      id: operation.id,
      target: operation.target,
      operation: operation.operation,
      recipe:
        'Derive exact state alias; redefine own property state.key with a different value/descriptor.',
      alias_derivation: operation.aliasDerivation,
      cause_bound_observation:
        'defineProperty throws on the real nonconfigurable frozen key property',
      expected: 'full descriptor-graph before/after SHA-256 equal',
    },
    'X3-O200-consumption_state-key-reflect-set': {
      id: operation.id,
      target: operation.target,
      operation: operation.operation,
      recipe:
        'Derive exact state alias; call Reflect.set(state, "key", attackerKey).',
      alias_derivation: operation.aliasDerivation,
      cause_bound_observation:
        'Reflect.set returns exact false (not primitive TypeError); real key remains unchanged',
      expected: 'return false and full descriptor-graph before/after SHA-256 equal',
    },
    'X3-O201-consumption_state-status-set': {
      id: operation.id,
      target: operation.target,
      operation: operation.operation,
      recipe:
        'Derive exact state alias; in strict mode assign a different valid status string to state.status.',
      alias_derivation: operation.aliasDerivation,
      cause_bound_observation:
        'strict assignment throws or is impossible on the real frozen status property',
      expected: 'full descriptor-graph before/after SHA-256 equal',
    },
    'X3-O202-consumption_state-status-delete': {
      id: operation.id,
      target: operation.target,
      operation: operation.operation,
      recipe: 'Derive exact state alias; in strict mode delete state.status.',
      alias_derivation: operation.aliasDerivation,
      cause_bound_observation:
        'strict delete throws or is impossible on the real nonconfigurable status property',
      expected: 'full descriptor-graph before/after SHA-256 equal',
    },
    'X3-O203-consumption_state-status-redefine': {
      id: operation.id,
      target: operation.target,
      operation: operation.operation,
      recipe:
        'Derive exact state alias; redefine own property state.status with a different value/descriptor.',
      alias_derivation: operation.aliasDerivation,
      cause_bound_observation:
        'defineProperty throws on the real nonconfigurable frozen status property',
      expected: 'full descriptor-graph before/after SHA-256 equal',
    },
    'X3-O204-consumption_state-status-reflect-delete': {
      id: operation.id,
      target: operation.target,
      operation: operation.operation,
      recipe:
        'Derive exact state alias; call Reflect.deleteProperty(state, "status").',
      alias_derivation: operation.aliasDerivation,
      cause_bound_observation:
        'Reflect.deleteProperty returns exact false (not primitive TypeError); real status remains present/unchanged',
      expected: 'return false and full descriptor-graph before/after SHA-256 equal',
    },
    'X3-O205-decision-consumption_state-set': {
      id: operation.id,
      target: operation.target,
      operation: operation.operation,
      recipe:
        'In strict mode assign a different object to exact own property decision.consumption_state.',
      alias_derivation: null,
      expected:
        'throw or observably impossible; full descriptor-graph before/after SHA-256 equal',
    },
    'X3-O206-decision-consumption_state-delete': {
      id: operation.id,
      target: operation.target,
      operation: operation.operation,
      recipe:
        'In strict mode delete exact own property decision.consumption_state.',
      alias_derivation: null,
      expected:
        'throw or observably impossible; full descriptor-graph before/after SHA-256 equal',
    },
    'X3-O207-decision-consumption_state-redefine': {
      id: operation.id,
      target: operation.target,
      operation: operation.operation,
      recipe:
        'In strict mode redefine exact own property descriptor decision.consumption_state with a different value/descriptor.',
      alias_derivation: null,
      expected:
        'throw or observably impossible; full descriptor-graph before/after SHA-256 equal',
    },
    'X3-O208-consumption_state-alias-setPrototypeOf': {
      id: operation.id,
      target: operation.target,
      operation: operation.operation,
      recipe:
        'Derive `const state = decision.consumption_state`; assert it is the exact returned frozen state and nonaliased from caller state; then set its prototype.',
      alias_derivation: operation.aliasDerivation,
      expected:
        'throw or observably impossible; full descriptor-graph before/after SHA-256 equal',
    },
    'X3-O209-consumption_state-alias-extend': {
      id: operation.id,
      target: operation.target,
      operation: operation.operation,
      recipe:
        'Derive `const state = decision.consumption_state`; assert exact returned frozen state/nonalias; then assign state.attacker_marker=true in strict mode.',
      alias_derivation: operation.aliasDerivation,
      expected:
        'throw or observably impossible; full descriptor-graph before/after SHA-256 equal',
    },
  };
  return (
    detailed[operation.id] ?? {
      id: operation.id,
      target: operation.target,
      operation: operation.operation,
      expected: genericExpected,
    }
  );
}

describe('exact-target pure schema and attestation validator', () => {
  const x1Receipt = {
    caseResultsSha256: '',
    catalogSha256: '',
    mutationResultsSha256: '',
    frozenStates: 0,
    nullStates: 0,
    decisionsRecursiveFrozen: 0,
    decisionsNonaliased: 0,
    decisionMutationPasses: 0,
    stateMutationPasses: 0,
    mutationPasses: 0,
    graphEqual: 0,
    reasons: new Set<ExactTargetSchemaReason>(),
  };
  const x2Receipt = {
    invalidPasses: 0,
    positivePasses: 0,
    reasonObservations: 0,
    resultSha256: '',
    positiveResultSha256: '',
    reasons: new Set<ExactTargetSchemaReason>(),
  };
  const x3Receipt = {
    callerPasses: 0,
    callerResultsSha256: '',
    outputPasses: 0,
    catalogSha256: '',
    mutationResultsSha256: '',
    graphEqual: 0,
    reflectFalse: 0,
    reflectFalsePasses: 0,
    recursiveFrozen: false,
    inputAliasCount: 0,
    callerObjectFrozenCount: 0,
    stateAliasPasses: 0,
    returnedStateContainerPasses: 0,
    exactDecisionPropertyPasses: 0,
  };
  const stateReceipt = {
    id: '',
    resultSha256: '',
    decisionGraphSha256: '',
    returnedStateGraphSha256: '',
    reason: '' as ExactTargetSchemaReason | '',
    family: '',
    recursiveFrozen: false,
    stateNonaliased: false,
    noThrow: false,
  };

  test('X1 rejects the exact 187 hostile runtime inputs and proves 1,665 immutable mutations', () => {
    const cases = buildX1Cases();
    expect(cases).toHaveLength(187);
    expect(new Set(cases.map(({ id }) => id)).size).toBe(187);
    expect(sha256(cases.map(({ id }) => id).join('\n'))).toBe(
      '4a23eccebb8f56d5f25e50d9da7ac196007b7fda5516e8459724a780de23cb22',
    );
    expect(cases.filter(({ exotic }) => exotic)).toHaveLength(25);
    expect(cases.filter(({ nonEnumerable }) => nonEnumerable)).toHaveLength(5);

    const caseResults: unknown[] = [];
    const mutationIds: string[] = [];
    const mutationCatalog: Record<string, unknown>[] = [];
    const mutationResults: unknown[] = [];
    for (const fixture of cases) {
      const candidate = fixture.make();
      let decision: ReturnType<typeof validateExactTargetSchema> | undefined;
      expect(() => {
        decision = validate(candidate);
      }, fixture.id).not.toThrow();
      if (decision === undefined) throw new Error(`missing decision for ${fixture.id}`);
      expect(decision.ok, fixture.id).toBe(false);
      if (decision.ok) throw new Error(`expected INPUT rejection for ${fixture.id}`);
      expect(decision.reason_code, fixture.id).toBe('LIVE_SCHEMA_INPUT_REJECTED');
      expect(decision.reason_family, fixture.id).toBe('LIVE_SCHEMA_INPUT_REJECTED');
      x1Receipt.reasons.add(decision.reason_code);
      expect(Reflect.ownKeys(decision).sort(), fixture.id).toEqual([
        'consumption_state',
        'ok',
        'reason_code',
        'reason_family',
      ]);
      expect(recursivelyFrozen(decision), fixture.id).toBe(true);
      x1Receipt.decisionsRecursiveFrozen += Number(recursivelyFrozen(decision));
      expect(decision, fixture.id).not.toBe(candidate);
      x1Receipt.decisionsNonaliased += Number(decision !== candidate);

      if (fixture.stateKind === 'null') {
        x1Receipt.nullStates += 1;
        expect(decision.consumption_state, fixture.id).toBeNull();
      } else {
        x1Receipt.frozenStates += 1;
        const topDescriptor = Object.getOwnPropertyDescriptor(
          candidate as object,
          'consumption_state',
        );
        if (topDescriptor === undefined || !('value' in topDescriptor)) {
          throw new Error(`missing caller state for ${fixture.id}`);
        }
        expect(decision.consumption_state, fixture.id).toEqual(topDescriptor.value);
        expect(decision.consumption_state, fixture.id).not.toBe(topDescriptor.value);
        expect(Object.isFrozen(decision.consumption_state), fixture.id).toBe(true);
      }

      caseResults.push({
        id: fixture.id,
        reason: decision.reason_code,
        family: decision.reason_family,
        state_kind: fixture.stateKind,
        decision_frozen: recursivelyFrozen(decision),
        no_throw: true,
        content_free: Reflect.ownKeys(decision).length === 4,
        decision_nonaliased: decision !== candidate,
        decision_graph_sha256: graphSha256(decision),
      });

      const baseline = graphSha256(decision);
      const rootOperations: readonly [string, () => unknown][] = [
        ['set', () => { (decision as unknown as Record<string, unknown>).reason_code = 'attacker'; }],
        ['delete', () => delete (decision as unknown as Record<string, unknown>).reason_code],
        ['redefine', () => Object.defineProperty(decision, 'reason_code', { value: 'attacker' })],
        ['setPrototypeOf', () => Object.setPrototypeOf(decision, { attacker: true })],
      ];
      for (const [operation, mutate] of rootOperations) {
        const id = `X1-MUT:${fixture.id}:decision:${operation}`;
        const before = graphSha256(decision);
        const observation = impossibleMutation(mutate);
        const after = graphSha256(decision);
        const pass = before === baseline && after === baseline && observation.threw;
        expect(pass, id).toBe(true);
        const target = 'decision_root';
        const catalogEntry = x1CatalogEntry(
          id,
          fixture.id,
          fixture.stateKind,
          target,
          operation,
        );
        mutationIds.push(id);
        mutationCatalog.push(catalogEntry);
        mutationResults.push({
          ...catalogEntry,
          recipe: x1MutationRecipe(target, operation),
          pass,
          throw_or_impossible: observation.threw,
          graph_before_sha256: before,
          graph_after_sha256: after,
        });
        x1Receipt.decisionMutationPasses += Number(pass);
        x1Receipt.mutationPasses += Number(pass);
        x1Receipt.graphEqual += Number(before === after && after === baseline);
      }

      const state = decision.consumption_state;
      if (state !== null) {
        const stateOperations: readonly [string, string, () => unknown][] = [
          ['state.key', 'set', () => { (state as { key: string }).key = 'c'.repeat(64); }],
          ['state.key', 'delete', () => delete (state as unknown as Record<string, unknown>).key],
          ['state.key', 'redefine', () => Object.defineProperty(state, 'key', { value: 'c'.repeat(64) })],
          ['state.status', 'set', () => { (state as { status: string }).status = 'consumed'; }],
          ['state.status', 'delete', () => delete (state as unknown as Record<string, unknown>).status],
          ['state.status', 'redefine', () => Object.defineProperty(state, 'status', { value: 'consumed' })],
          ['state', 'setPrototypeOf', () => Object.setPrototypeOf(state, { attacker: true })],
        ];
        for (const [target, operation, mutate] of stateOperations) {
          const id = `X1-MUT:${fixture.id}:${target}:${operation}`;
          const before = graphSha256(decision);
          const observation = impossibleMutation(mutate);
          const after = graphSha256(decision);
          const pass = before === baseline && after === baseline && observation.threw;
          expect(pass, id).toBe(true);
          const exactTarget = target === 'state'
            ? 'consumption_state'
            : target.replace('state.', 'consumption_state.');
          const catalogEntry = x1CatalogEntry(
            id,
            fixture.id,
            fixture.stateKind,
            exactTarget,
            operation,
          );
          mutationIds.push(id);
          mutationCatalog.push(catalogEntry);
          mutationResults.push({
            ...catalogEntry,
            recipe: x1MutationRecipe(exactTarget, operation),
            pass,
            throw_or_impossible: observation.threw,
            graph_before_sha256: before,
            graph_after_sha256: after,
          });
          x1Receipt.stateMutationPasses += Number(pass);
          x1Receipt.mutationPasses += Number(pass);
          x1Receipt.graphEqual += Number(before === after && after === baseline);
        }
      }
    }

    expect(x1Receipt.frozenStates).toBe(131);
    expect(x1Receipt.nullStates).toBe(56);
    expect(mutationIds).toHaveLength(1665);
    expect(new Set(mutationIds).size).toBe(1665);
    expect(sha256(mutationIds.join('\n'))).toBe(
      'f869fa936c0f2a2d2ab457a6b6f187acc6abf8fff84f6dd9a538bce1e9693709',
    );
    expect(mutationCatalog).toHaveLength(1665);
    x1Receipt.catalogSha256 = sha256(canonicalJson(mutationCatalog));
    expect(x1Receipt.catalogSha256).toBe(
      '2edfb31eb6507ae574534be54afbef652edc4a2c795246a5f3e4eb22df916655',
    );
    expect(x1Receipt.decisionsRecursiveFrozen).toBe(187);
    expect(x1Receipt.decisionsNonaliased).toBe(187);
    expect(x1Receipt.decisionMutationPasses).toBe(748);
    expect(x1Receipt.stateMutationPasses).toBe(917);
    expect(x1Receipt.mutationPasses).toBe(1665);
    expect(x1Receipt.graphEqual).toBe(1665);
    x1Receipt.caseResultsSha256 = sha256(canonicalJson(caseResults));
    x1Receipt.mutationResultsSha256 = sha256(canonicalJson(mutationResults));
  });

  test('matches the authoritative 46-row table coordinate for coordinate', () => {
    expect(EXACT_TARGET_SCHEMA_ROWS).toHaveLength(46);
    expect(
      EXACT_TARGET_SCHEMA_ROWS.map(
        (row) =>
          `${row.column_name}|${row.data_type}|${row.udt_name}|${row.is_nullable}`,
      ),
    ).toEqual(EXPECTED_ROW_LINES);
    expect(new Set(EXACT_TARGET_SCHEMA_ROWS.map((row) => row.column_name)).size).toBe(
      46,
    );
  });

  test('serializes exactly 1527 UTF-8 bytes with final LF and accepted digest', () => {
    const serialization = serializeExactTargetSchema(EXACT_TARGET_SCHEMA_ROWS);
    expect(Buffer.byteLength(serialization, 'utf8')).toBe(
      EXACT_TARGET_SCHEMA_SERIALIZED_BYTES,
    );
    expect(EXACT_TARGET_SCHEMA_SERIALIZED_BYTES).toBe(1527);
    expect(serialization.endsWith('\n')).toBe(true);
    expect(serialization.split('\n')).toHaveLength(47);
    expect(sha256(serialization)).toBe(DIGEST);
    expect(digestExactTargetSchema(EXACT_TARGET_SCHEMA_ROWS)).toBe(DIGEST);
  });

  test('pins the exact 189-byte query with no LF and rejects the with-LF digest', () => {
    expect(Buffer.byteLength(EXACT_TARGET_SCHEMA_QUERY, 'utf8')).toBe(189);
    expect(EXACT_TARGET_SCHEMA_QUERY_BYTES).toBe(189);
    expect(EXACT_TARGET_SCHEMA_QUERY.startsWith('SELECT')).toBe(true);
    expect(EXACT_TARGET_SCHEMA_QUERY.endsWith('column_name')).toBe(true);
    expect(EXACT_TARGET_SCHEMA_QUERY.includes('\n')).toBe(false);
    expect(sha256(EXACT_TARGET_SCHEMA_QUERY)).toBe(
      EXACT_TARGET_SCHEMA_QUERY_SHA256,
    );
    expect(sha256(`${EXACT_TARGET_SCHEMA_QUERY}\n`)).toBe(
      EXACT_TARGET_SCHEMA_QUERY_WITH_LF_SHA256,
    );
    expect(EXACT_TARGET_SCHEMA_QUERY_SHA256).not.toBe(
      EXACT_TARGET_SCHEMA_QUERY_WITH_LF_SHA256,
    );
  });

  test('accepts canonical order and consumes the threaded pure state', () => {
    const result = validate(input());
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.reason_code);
    expect(result.normalized_rows).toEqual(EXACT_TARGET_SCHEMA_ROWS);
    expect(result.schema_sha256).toBe(DIGEST);
    expect(result.serialized_bytes).toBe(1527);
    expect(result.consumption_state).toEqual({ key: GUARDIAN, status: 'consumed' });
    expect(result.scope_limit).toBe(EXACT_TARGET_ATTESTATION_SCOPE_LIMIT);
    recordParentPositive('PARENT-P01-canonical', result);
  });

  test('accepts reverse order with the same normalization and digest', () => {
    const result = validate(input({ rows: cloneRows().reverse() }));
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.reason_code);
    expect(result.normalized_rows).toEqual(EXACT_TARGET_SCHEMA_ROWS);
    expect(result.schema_sha256).toBe(DIGEST);
    recordParentPositive('PARENT-P02-reverse', result);
  });

  test('accepts rotate-17 order with the same normalization and digest', () => {
    const rows = cloneRows();
    const rotated = [...rows.slice(17), ...rows.slice(0, 17)];
    expect(sha256(`${rotated.map((row) => row.column_name).join('\n')}\n`)).toBe(
      'fb14b3e71bee1bf0525d6eeab4503c4413bf1dd6847b942c3bb238909bf959fc',
    );
    const result = validate(input({ rows: rotated }));
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.reason_code);
    expect(result.normalized_rows).toEqual(EXACT_TARGET_SCHEMA_ROWS);
    expect(result.schema_sha256).toBe(DIGEST);
    recordParentPositive('PARENT-P03-rotate-17', result);
  });

  test('accepts the frozen seeded order with the same normalization and digest', () => {
    const seeded = seededPermutation(cloneRows());
    expect(sha256(`${seeded.map((row) => row.column_name).join('\n')}\n`)).toBe(
      'ee26ef573923c7d4c731d34a5947b30eddbaab1afe6f1ee69312e4274c389371',
    );
    const result = validate(input({ rows: seeded }));
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.reason_code);
    expect(result.normalized_rows).toEqual(EXACT_TARGET_SCHEMA_ROWS);
    expect(result.schema_sha256).toBe(DIGEST);
    recordParentPositive('PARENT-P04-seeded', result);
  });

  test('detects a raw duplicate before an accompanying extra or sort', () => {
    const rows = cloneRows().reverse();
    rows.push({ ...rows.find((row) => row.column_name === 'id')! });
    rows.push({
      column_name: '__unexpected_order1_column__',
      data_type: 'text',
      udt_name: 'text',
      is_nullable: 'YES',
    });
    expectReason(
      input({ rows }),
      'LIVE_SCHEMA_COLUMN_DUPLICATE_REJECTED',
    );
  });

  test('detects a raw extra before an accompanying missing column or sort', () => {
    const rows = cloneRows()
      .filter((row) => row.column_name !== 'id')
      .reverse();
    rows.push({
      column_name: '__unexpected_order1_column__',
      data_type: 'text',
      udt_name: 'text',
      is_nullable: 'YES',
    });
    expectReason(input({ rows }), 'LIVE_SCHEMA_COLUMN_EXTRA_REJECTED');
  });

  test('detects a raw missing canonical column before sorting', () => {
    const rows = cloneRows()
      .filter((row) => row.column_name !== 'id')
      .reverse();
    expectReason(input({ rows }), 'LIVE_SCHEMA_COLUMN_MISSING_REJECTED');
  });

  test('executes 184 independent per-column non-noop mutations', () => {
    for (const canonical of EXACT_TARGET_SCHEMA_ROWS) {
      const name = canonical.column_name;
      recordMutation(
        `missing:${name}`,
        'per_column_missing',
        input({ rows: cloneRows().filter((row) => row.column_name !== name) }),
        'LIVE_SCHEMA_COLUMN_MISSING_REJECTED',
      );

      const dataType = canonical.data_type === 'text' ? 'integer' : 'text';
      expect(dataType).not.toBe(canonical.data_type);
      recordMutation(
        `data_type:${name}`,
        'per_column_data_type_change',
        input({ rows: replaceRow(cloneRows(), name, { data_type: dataType }) }),
        'LIVE_SCHEMA_TYPE_REJECTED',
      );

      const udtName = canonical.udt_name === 'text' ? 'int4' : 'text';
      expect(udtName).not.toBe(canonical.udt_name);
      recordMutation(
        `udt_name:${name}`,
        'per_column_udt_name_change',
        input({ rows: replaceRow(cloneRows(), name, { udt_name: udtName }) }),
        'LIVE_SCHEMA_UDT_REJECTED',
      );

      const isNullable = canonical.is_nullable === 'YES' ? 'NO' : 'YES';
      expect(isNullable).not.toBe(canonical.is_nullable);
      recordMutation(
        `is_nullable:${name}`,
        'per_column_is_nullable_change',
        input({ rows: replaceRow(cloneRows(), name, { is_nullable: isNullable }) }),
        'LIVE_SCHEMA_NULLABILITY_REJECTED',
      );
    }

    expect(mutationIds.size).toBe(184);
    expect(mutationHistogram).toEqual({
      per_column_missing: 46,
      per_column_data_type_change: 46,
      per_column_udt_name_change: 46,
      per_column_is_nullable_change: 46,
      singletons: 0,
    });
  });

  test('executes the exact 15 singleton mutations', () => {
    const duplicateRows = cloneRows();
    duplicateRows.push({ ...duplicateRows.find((row) => row.column_name === 'id')! });
    recordMutation(
      'duplicate_column',
      'singletons',
      input({ rows: duplicateRows }),
      'LIVE_SCHEMA_COLUMN_DUPLICATE_REJECTED',
    );

    recordMutation(
      'expired_attestation',
      'singletons',
      input({ attestation: { ...ATTESTATION, expires_at: NOW } }),
      'SCHEMA_ATTESTATION_EXPIRED_REJECTED',
    );

    recordMutation(
      'extra_column',
      'singletons',
      input({
        rows: [
          ...cloneRows(),
          {
            column_name: '__unexpected_order1_column__',
            data_type: 'text',
            udt_name: 'text',
            is_nullable: 'YES',
          },
        ],
      }),
      'LIVE_SCHEMA_COLUMN_EXTRA_REJECTED',
    );

    recordMutation(
      'missing_attestation',
      'singletons',
      input({ attestation: null }),
      'SCHEMA_ATTESTATION_MISSING_REJECTED',
    );

    recordMutation(
      'reused_attestation',
      'singletons',
      input({ consumption_state: { key: GUARDIAN, status: 'consumed' } }),
      'SCHEMA_ATTESTATION_REUSED_REJECTED',
    );

    const singletonAttestationCases: readonly [
      string,
      Partial<ExactTargetSchemaAttestation>,
      ExactTargetSchemaReason,
    ][] = [
      [
        'wrong_brain',
        { brain_binding: 'wrong-private' },
        'SCHEMA_ATTESTATION_BRAIN_REJECTED',
      ],
      [
        'wrong_current_schema',
        { current_schema: 'not_public' },
        'SCHEMA_ATTESTATION_CURRENT_SCHEMA_REJECTED',
      ],
      [
        'wrong_database',
        { database_binding: 'wrong_database' },
        'SCHEMA_ATTESTATION_DATABASE_REJECTED',
      ],
      ['wrong_digest', { schema_sha256: '0'.repeat(64) }, 'LIVE_SCHEMA_DIGEST_REJECTED'],
      [
        'wrong_guardian_challenge',
        { guardian_challenge_binding: 'c'.repeat(64) },
        'SCHEMA_ATTESTATION_GUARDIAN_CHALLENGE_REJECTED',
      ],
      [
        'wrong_hold_binding',
        { hold_gate_binding: 'c'.repeat(64) },
        'SCHEMA_ATTESTATION_HOLD_BINDING_REJECTED',
      ],
      [
        'wrong_query_contract',
        { query_contract_sha256: EXACT_TARGET_SCHEMA_QUERY_WITH_LF_SHA256 },
        'SCHEMA_ATTESTATION_QUERY_CONTRACT_REJECTED',
      ],
      [
        'wrong_row_count',
        { column_count: 45 },
        'SCHEMA_ATTESTATION_ROW_COUNT_REJECTED',
      ],
      [
        'wrong_table_name',
        { table_name: 'other_table' },
        'SCHEMA_ATTESTATION_TABLE_NAME_REJECTED',
      ],
      [
        'wrong_table_schema',
        { table_schema: 'other_schema' },
        'SCHEMA_ATTESTATION_TABLE_SCHEMA_REJECTED',
      ],
    ];

    for (const [id, patch, reason] of singletonAttestationCases) {
      recordMutation(
        id,
        'singletons',
        input({ attestation: { ...ATTESTATION, ...patch } }),
        reason,
      );
    }

    expect(mutationIds.size).toBe(199);
    expect(sha256(`${[...mutationIds].sort().join('\n')}\n`)).toBe(
      'ac867d7b81211494d1551eb9ebcfa784f95531485886f177d1d1bec3c5620883',
    );
    expect(mutationHistogram).toEqual({
      per_column_missing: 46,
      per_column_data_type_change: 46,
      per_column_udt_name_change: 46,
      per_column_is_nullable_change: 46,
      singletons: 15,
    });
  });

  test('enforces computed, attested, and authoritative digest equality', () => {
    expect(validateExactTargetDigestEquality(DIGEST, DIGEST)).toBeNull();
    expect(validateExactTargetDigestEquality('0'.repeat(64), DIGEST)).toBe(
      'LIVE_SCHEMA_DIGEST_REJECTED',
    );
    expect(validateExactTargetDigestEquality(DIGEST, '0'.repeat(64))).toBe(
      'LIVE_SCHEMA_DIGEST_REJECTED',
    );
    expect(validateExactTargetDigestEquality('1'.repeat(64), '1'.repeat(64))).toBe(
      'LIVE_SCHEMA_DIGEST_REJECTED',
    );
  });

  test('accepts now exactly equal to acquired_at', () => {
    const result = validate(
      input({ now: '2026-08-30T00:00:00.000000Z' }),
    );
    expect(result.ok).toBe(true);
  });

  test('rejects now exactly equal to expires_at as expired', () => {
    expectReason(
      input({ now: '2026-08-30T00:05:00.000000Z' }),
      'SCHEMA_ATTESTATION_EXPIRED_REJECTED',
    );
  });

  test('rejects expires_at equal to acquired_at as malformed time', () => {
    expectReason(
      input({
        attestation: {
          ...ATTESTATION,
          expires_at: ATTESTATION.acquired_at,
        },
      }),
      'SCHEMA_ATTESTATION_TIMESTAMP_REJECTED',
    );
  });

  test('rejects noncanonical timestamps and Date objects', () => {
    expectReason(
      input({ now: '2026-08-30T00:01:00Z' }),
      'SCHEMA_ATTESTATION_TIMESTAMP_REJECTED',
    );
    expectReason(
      input({ now: new Date('2026-08-30T00:01:00Z') as unknown as string }),
      'LIVE_SCHEMA_INPUT_REJECTED',
    );
  });

  test('X2 rejects the exact 12 impossible Gregorian fixtures and accepts leap day', () => {
    const invalidValues = [
      ['feb31', '2026-02-31T00:00:00.000000Z'],
      ['nonleap', '2025-02-29T00:00:00.000000Z'],
      ['month13', '2026-13-01T00:00:00.000000Z'],
      ['day00', '2026-01-00T00:00:00.000000Z'],
    ] as const;
    const ids: string[] = [];
    const results: Record<string, unknown>[] = [];
    for (const [prefix, field] of [
      ['N', 'now'],
      ['A', 'acquired_at'],
      ['E', 'expires_at'],
    ] as const) {
      for (const [index, [invalidKind, invalid]] of invalidValues.entries()) {
        const id = `X2-${prefix}${index + 1}`;
        ids.push(id);
        const candidate = input({
          now: field === 'now' ? invalid : '2026-03-01T00:00:00.000000Z',
          attestation: {
            ...ATTESTATION,
            acquired_at:
              field === 'acquired_at'
                ? invalid
                : '2026-02-28T00:00:00.000000Z',
            expires_at:
              field === 'expires_at'
                ? invalid
                : '2026-03-02T00:00:00.000000Z',
          },
        });
        const callerState = candidate.consumption_state;
        let result: ReturnType<typeof validateExactTargetSchema> | undefined;
        expect(() => {
          result = validate(candidate);
        }, id).not.toThrow();
        if (result === undefined) throw new Error(`missing timestamp result for ${id}`);
        expect(result.ok, id).toBe(false);
        if (result.ok) throw new Error(`expected timestamp rejection for ${id}`);
        expect(result.reason_code, id).toBe(
          'SCHEMA_ATTESTATION_TIMESTAMP_REJECTED',
        );
        expect(result.consumption_state, id).toEqual(callerState);
        expect(result.consumption_state, id).not.toBe(callerState);
        expect(recursivelyFrozen(result), id).toBe(true);
        x2Receipt.reasons.add(result.reason_code);
        x2Receipt.reasonObservations += Number(
          result.reason_code === 'SCHEMA_ATTESTATION_TIMESTAMP_REJECTED',
        );
        results.push({
          id,
          field,
          invalid_kind: invalidKind,
          supplied_value_sha256: sha256(invalid),
          reason: result.reason_code,
          family: result.reason_family,
          pass: true,
          no_throw: true,
          state_nonaliased: result.consumption_state !== callerState,
          decision_recursive_frozen: recursivelyFrozen(result),
          caller_state_graph_sha256: graphSha256(callerState),
          returned_state_graph_sha256: graphSha256(result.consumption_state),
          decision_graph_sha256: graphSha256(result),
        });
        x2Receipt.invalidPasses += 1;
      }
    }
    expect(ids).toHaveLength(12);
    expect(sha256(ids.join('\n'))).toBe(
      '702a189b342a744640ccf014610ec22c337dd504030f241ed9cf9f9bce95351f',
    );
    expect(x2Receipt.invalidPasses).toBe(12);
    expect(x2Receipt.reasonObservations).toBe(12);
    x2Receipt.resultSha256 = sha256(canonicalJson(results));

    const leapCandidate = input({
        attestation: {
          ...ATTESTATION,
          acquired_at: '2028-02-29T00:00:00.000000Z',
          expires_at: '2028-02-29T00:05:00.000000Z',
        },
        now: '2028-02-29T00:01:00.000000Z',
      });
    let leap: ReturnType<typeof validateExactTargetSchema> | undefined;
    expect(() => {
      leap = validate(leapCandidate);
    }, 'X2-P01-leap-day').not.toThrow();
    if (leap === undefined) throw new Error('missing X2 leap-day result');
    expect(leap.ok).toBe(true);
    x2Receipt.positivePasses = Number(leap.ok);
    if (!leap.ok) throw new Error(`unexpected leap-day rejection: ${leap.reason_code}`);
    x2Receipt.positiveResultSha256 = sha256(canonicalJson({
      id: 'X2-P01-leap-day',
      pass: true,
      no_throw: true,
      schema_sha256: leap.schema_sha256,
      serialized_bytes: leap.serialized_bytes,
      state_status: leap.consumption_state.status,
      decision_recursive_frozen: recursivelyFrozen(leap),
      decision_graph_sha256: graphSha256(leap),
    }));
  });

  test('returns a stable content-free INPUT rejection for null and undefined input', () => {
    for (const invalidInput of [null, undefined]) {
      const result = validateExactTargetSchema(invalidInput);
      expect(result).toEqual({
        ok: false,
        reason_code: 'LIVE_SCHEMA_INPUT_REJECTED',
        reason_family: 'LIVE_SCHEMA_INPUT_REJECTED',
        consumption_state: null,
      });
      expect(Object.isFrozen(result)).toBe(true);
    }
  });

  test('deep-freezes copy-safe accepted decisions and normalized rows', () => {
    const candidate = input();
    const result = validate(candidate);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.reason_code);
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.normalized_rows)).toBe(true);
    expect(result.normalized_rows.every((row) => Object.isFrozen(row))).toBe(true);
    expect(Object.isFrozen(result.consumption_state)).toBe(true);

    const firstName = result.normalized_rows[0]!.column_name;
    const callerRow = candidate.rows.find((row) => row.column_name === firstName)!;
    (callerRow as { data_type: string }).data_type = 'text';
    expect(result.normalized_rows[0]!.data_type).toBe('integer');
    expect(() => {
      (result.normalized_rows[0] as { data_type: string }).data_type = 'text';
    }).toThrow();
    expect(() => {
      (result as { schema_sha256: string }).schema_sha256 = '0'.repeat(64);
    }).toThrow();
    expect(result.schema_sha256).toBe(DIGEST);
  });

  test('X3 isolates accepted output from the exact 19 caller aliases', () => {
    const callerCases: readonly [string, (candidate: ValidateExactTargetSchemaInput) => void][] = [
      ['X3-C01-row-field', (candidate) => { (candidate.rows[0] as { column_name: string }).column_name = 'attacker'; }],
      ['X3-C02-rows-reorder', (candidate) => { (candidate.rows as ExactTargetSchemaRow[]).sort(() => -1); }],
      ['X3-C03-rows-reverse', (candidate) => { (candidate.rows as ExactTargetSchemaRow[]).reverse(); }],
      ['X3-C04-rows-splice', (candidate) => { (candidate.rows as ExactTargetSchemaRow[]).splice(0, 2); }],
      ['X3-C05-rows-remove', (candidate) => { (candidate.rows as ExactTargetSchemaRow[]).pop(); }],
      ['X3-C06-rows-append', (candidate) => { (candidate.rows as ExactTargetSchemaRow[]).push({ column_name: 'attacker', data_type: 'text', udt_name: 'text', is_nullable: 'YES' }); }],
      ['X3-C07-att-schema_sha256', (candidate) => { (candidate.attestation as unknown as Record<string, unknown>).schema_sha256 = '0'.repeat(64); }],
      ['X3-C08-att-guardian_challenge_binding', (candidate) => { (candidate.attestation as unknown as Record<string, unknown>).guardian_challenge_binding = 'c'.repeat(64); }],
      ['X3-C09-att-acquired_at', (candidate) => { (candidate.attestation as unknown as Record<string, unknown>).acquired_at = 'attacker'; }],
      ['X3-C10-att-expires_at', (candidate) => { (candidate.attestation as unknown as Record<string, unknown>).expires_at = 'attacker'; }],
      ['X3-C11-exp-brain_binding', (candidate) => { (candidate.expected_bindings as unknown as Record<string, unknown>).brain_binding = 'attacker'; }],
      ['X3-C12-exp-database_binding', (candidate) => { (candidate.expected_bindings as unknown as Record<string, unknown>).database_binding = 'attacker'; }],
      ['X3-C13-exp-current_schema', (candidate) => { (candidate.expected_bindings as unknown as Record<string, unknown>).current_schema = 'attacker'; }],
      ['X3-C14-exp-table_schema', (candidate) => { (candidate.expected_bindings as unknown as Record<string, unknown>).table_schema = 'attacker'; }],
      ['X3-C15-exp-table_name', (candidate) => { (candidate.expected_bindings as unknown as Record<string, unknown>).table_name = 'attacker'; }],
      ['X3-C16-exp-guardian_challenge_binding', (candidate) => { (candidate.expected_bindings as unknown as Record<string, unknown>).guardian_challenge_binding = 'c'.repeat(64); }],
      ['X3-C17-exp-hold_gate_binding', (candidate) => { (candidate.expected_bindings as unknown as Record<string, unknown>).hold_gate_binding = 'c'.repeat(64); }],
      ['X3-C18-state-key', (candidate) => { (candidate.consumption_state as unknown as Record<string, unknown>).key = 'c'.repeat(64); }],
      ['X3-C19-state-status', (candidate) => { (candidate.consumption_state as unknown as Record<string, unknown>).status = 'consumed'; }],
    ];
    expect(callerCases).toHaveLength(19);
    const callerResults: Record<string, unknown>[] = [];

    for (const [id, mutate] of callerCases) {
      const candidate = input();
      const callerState = candidate.consumption_state;
      const result = validate(candidate);
      expect(result.ok, id).toBe(true);
      if (!result.ok) throw new Error(`${id}: ${result.reason_code}`);
      expect(result.consumption_state, id).not.toBe(callerState);
      expect(result.normalized_rows, id).not.toBe(candidate.rows);
      const baseline = graphSha256(result);
      const callerReferences = objectReferences(candidate);
      const returnedReferences = objectReferences(result);
      const inputAliasCount = [...returnedReferences].filter((reference) =>
        callerReferences.has(reference),
      ).length;
      const callerObjectFrozenCount = [...callerReferences].filter((reference) =>
        Object.isFrozen(reference),
      ).length;
      expect(inputAliasCount, id).toBe(0);
      expect(callerObjectFrozenCount, id).toBe(0);
      expect(recursivelyFrozen(result), id).toBe(true);
      mutate(candidate);
      const after = graphSha256(result);
      expect(after, id).toBe(baseline);
      expect(result.normalized_rows.map((row) => row.column_name), id).toEqual(
        EXACT_TARGET_SCHEMA_ROWS.map((row) => row.column_name),
      );
      expect(Buffer.byteLength(result.serialization, 'utf8'), id).toBe(1527);
      expect(sha256(result.serialization), id).toBe(DIGEST);
      expect(result.schema_sha256, id).toBe(DIGEST);
      expect(result.consumption_state, id).toEqual({ key: GUARDIAN, status: 'consumed' });
      callerResults.push({
        id,
        pass: true,
        input_alias_count: inputAliasCount,
        caller_object_frozen_count: callerObjectFrozenCount,
        returned_recursive_frozen: recursivelyFrozen(result),
        graph_before_sha256: baseline,
        graph_after_sha256: after,
        graph_equal: baseline === after,
      });
      x3Receipt.inputAliasCount += inputAliasCount;
      x3Receipt.callerObjectFrozenCount += callerObjectFrozenCount;
      x3Receipt.callerPasses += 1;
    }
    expect(x3Receipt.callerPasses).toBe(19);
    expect(x3Receipt.inputAliasCount).toBe(0);
    expect(x3Receipt.callerObjectFrozenCount).toBe(0);
    x3Receipt.callerResultsSha256 = sha256(canonicalJson(callerResults));
  });

  test('X3 proves the exact 209 accepted-output mutations against full graph hashes', () => {
    const candidate = input();
    const result = validate(candidate);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.reason_code);
    expect(recursivelyFrozen(result)).toBe(true);
    x3Receipt.recursiveFrozen = recursivelyFrozen(result);
    expect(result.consumption_state).not.toBe(candidate.consumption_state);
    expect(result.normalized_rows).not.toBe(candidate.rows);

    const operations = buildX3OutputOperations(result);
    expect(operations).toHaveLength(209);
    const ids = operations.map(({ id }) => id);
    expect(new Set(ids).size).toBe(209);
    expect(sha256(ids.join('\n'))).toBe(
      '6700fabc5ad8a8e66a98c86bf8672f98dd9952e9a10d203e9922d4c99106f0ab',
    );
    const catalog = operations.map(x3CatalogEntry);
    x3Receipt.catalogSha256 = sha256(canonicalJson(catalog));
    expect(x3Receipt.catalogSha256).toBe(
      'd0a66a360d1c38375ceb5362f6c36ccee1957bab3869ad4a49415be443455442',
    );
    expect(operations.slice(3).map(({ id, target, operation }) => ({ id, target, operation }))).toHaveLength(206);
    expect(operations.filter(({ aliasDerivation }) => aliasDerivation !== null)).toHaveLength(10);
    expect(operations.filter(({ reflectFalse }) => reflectFalse)).toHaveLength(2);
    expect(operations.filter(({ id }) => /^X3-O20[5-9]-/.test(id))).toHaveLength(5);

    const baseline = graphSha256(result);
    const mutationResults: unknown[] = [];
    for (const fixture of operations) {
      const before = graphSha256(result);
      const observation = impossibleMutation(fixture.mutate);
      const after = graphSha256(result);
      let blocked = observation.threw;
      let reflectReturn: boolean | null = null;
      if (fixture.reflectFalse) {
        reflectReturn = observation.result as boolean;
        expect(observation.threw, fixture.id).toBe(false);
        expect(reflectReturn, fixture.id).toBe(false);
        blocked = reflectReturn === false;
        x3Receipt.reflectFalse += Number(blocked);
      }
      const pass = blocked && before === baseline && after === baseline;
      expect(pass, fixture.id).toBe(true);
      x3Receipt.outputPasses += Number(pass);
      x3Receipt.graphEqual += Number(before === after && after === baseline);
      mutationResults.push({
        id: fixture.id,
        target: fixture.target,
        operation: fixture.operation,
        alias_derivation: fixture.aliasDerivation,
        pass,
        throw_observed_or_impossible: observation.threw || blocked,
        reflect_return_or_null: reflectReturn,
        graph_before_sha256: before,
        graph_after_sha256: after,
        baseline_graph_sha256: baseline,
      });
      if (fixture.aliasDerivation !== null) {
        x3Receipt.stateAliasPasses += Number(pass);
      }
      if (/^X3-O20[5-9]-/.test(fixture.id)) {
        x3Receipt.returnedStateContainerPasses += Number(pass);
      }
      if (/^X3-O00[1-3]-/.test(fixture.id)) {
        x3Receipt.exactDecisionPropertyPasses += Number(pass);
      }
      if (fixture.reflectFalse) {
        x3Receipt.reflectFalsePasses += Number(pass);
      }
    }
    expect(x3Receipt.outputPasses).toBe(209);
    expect(x3Receipt.graphEqual).toBe(209);
    expect(x3Receipt.reflectFalse).toBe(2);
    expect(x3Receipt.reflectFalsePasses).toBe(2);
    expect(x3Receipt.stateAliasPasses).toBe(10);
    expect(x3Receipt.returnedStateContainerPasses).toBe(5);
    expect(x3Receipt.exactDecisionPropertyPasses).toBe(3);
    expect(result.ok).toBe(true);
    expect(result.serialized_bytes).toBe(1527);
    expect(result.scope_limit).toBe(EXACT_TARGET_ATTESTATION_SCOPE_LIMIT);
    expect(result.schema_sha256).toBe(DIGEST);
    expect(result.consumption_state).toEqual({ key: GUARDIAN, status: 'consumed' });
    x3Receipt.mutationResultsSha256 = sha256(canonicalJson(mutationResults));
  });

  test('rejects a threaded consumed state without mutating it', () => {
    const consumed = Object.freeze({ key: GUARDIAN, status: 'consumed' as const });
    expectReason(
      input({ consumption_state: consumed }),
      'SCHEMA_ATTESTATION_REUSED_REJECTED',
    );
    expect(consumed).toEqual({ key: GUARDIAN, status: 'consumed' });
  });

  test('states and demonstrates the stale-unused replay limitation honestly', () => {
    const stale = Object.freeze({ key: GUARDIAN, status: 'unused' as const });
    const first = validate(input({ consumption_state: stale }));
    const replayFromStale = validate(input({ consumption_state: stale }));
    expect(first.ok).toBe(true);
    expect(replayFromStale.ok).toBe(true);
    expect(EXACT_TARGET_ATTESTATION_SCOPE_LIMIT).toContain('stale unused state');
    expect(EXACT_TARGET_ATTESTATION_SCOPE_LIMIT).toContain('later durable atomic owner');
  });

  test('rejects malformed state and attestation shapes as INPUT', () => {
    const malformedState = validate(
      input({
        consumption_state: {
          key: GUARDIAN,
          status: 'unused',
          extra: true,
        } as unknown as ExactTargetAttestationConsumptionState,
      }),
    );
    expect(malformedState.ok).toBe(false);
    if (malformedState.ok) throw new Error('expected malformed-state rejection');
    expect(malformedState.reason_code).toBe('LIVE_SCHEMA_INPUT_REJECTED');
    expect(malformedState.consumption_state).toBeNull();
    expect(recursivelyFrozen(malformedState)).toBe(true);
    expectReason(
      input({
        attestation: {
          ...ATTESTATION,
          extra: true,
        } as unknown as ExactTargetSchemaAttestation,
      }),
      'LIVE_SCHEMA_INPUT_REJECTED',
    );
  });

  test('uses STATE only for a structurally valid expected-key mismatch', () => {
    const mismatched = { key: 'c'.repeat(64), status: 'unused' as const };
    let result: ReturnType<typeof validateExactTargetSchema> | undefined;
    expect(() => {
      result = validate(input({ consumption_state: mismatched }));
    }, 'STATE-X1').not.toThrow();
    if (result === undefined) throw new Error('missing STATE-X1 result');
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error('expected state rejection');
    expect(result.reason_code).toBe('SCHEMA_ATTESTATION_STATE_REJECTED');
    expect(result.reason_family).toBe('SCHEMA_ATTESTATION_FRESHNESS_REJECTED');
    expect(result.consumption_state).toEqual(mismatched);
    expect(result.consumption_state).not.toBe(mismatched);
    expect(recursivelyFrozen(result)).toBe(true);
    stateReceipt.id = 'STATE-X1';
    stateReceipt.reason = result.reason_code;
    stateReceipt.family = result.reason_family;
    stateReceipt.recursiveFrozen = recursivelyFrozen(result);
    stateReceipt.stateNonaliased = result.consumption_state !== mismatched;
    stateReceipt.noThrow = true;
    stateReceipt.decisionGraphSha256 = graphSha256(result);
    stateReceipt.returnedStateGraphSha256 = graphSha256(result.consumption_state);
    stateReceipt.resultSha256 = sha256(canonicalJson({
      id: stateReceipt.id,
      reason: stateReceipt.reason,
      family: stateReceipt.family,
      recursive_frozen: stateReceipt.recursiveFrozen,
      state_nonaliased: stateReceipt.stateNonaliased,
      no_throw: stateReceipt.noThrow,
      decision_graph_sha256: stateReceipt.decisionGraphSha256,
      returned_state_graph_sha256: stateReceipt.returnedStateGraphSha256,
    }));
  });

  test('covers all 22 reasons and emits the exact Order-1 evidence summary', () => {
    const parentReasons = [...mutationReasons].sort();
    const x2Reasons = [...x2Receipt.reasons].sort();
    const x1Reasons = [...x1Receipt.reasons].sort();
    expect(parentReasons).toHaveLength(19);
    expect(x2Reasons).toEqual(['SCHEMA_ATTESTATION_TIMESTAMP_REJECTED']);
    expect(stateReceipt.reason).toBe('SCHEMA_ATTESTATION_STATE_REJECTED');
    expect(x1Reasons).toEqual(['LIVE_SCHEMA_INPUT_REJECTED']);
    const fixtureFlowReasons = new Set<ExactTargetSchemaReason>([
      ...parentReasons,
      ...x2Reasons,
      stateReceipt.reason as ExactTargetSchemaReason,
      ...x1Reasons,
    ]);
    const allReasons = Object.keys(
      EXACT_TARGET_SCHEMA_REASON_FAMILIES,
    ).sort() as ExactTargetSchemaReason[];
    expect(allReasons).toHaveLength(22);
    expect([...fixtureFlowReasons].sort()).toEqual(allReasons);
    expect(mutationIds.size).toBe(199);
    expect(
      Object.values(mutationHistogram).reduce((sum, count) => sum + count, 0),
    ).toBe(199);
    expect(parentMutationResults).toHaveLength(199);
    expect(parentPositiveResults).toHaveLength(4);

    const parentIds = [...mutationIds].sort();
    const parentIdSha256 = sha256(`${parentIds.join('\n')}\n`);
    expect(parentIdSha256).toBe(
      'ac867d7b81211494d1551eb9ebcfa784f95531485886f177d1d1bec3c5620883',
    );
    const parentResultSha256 = sha256(canonicalJson(parentMutationResults));
    const parentGraphSha256 = sha256(canonicalJson(
      parentMutationResults.map(({ id, decision_graph_sha256 }) => ({
        id,
        decision_graph_sha256,
      })),
    ));
    const parentReasonSetSha256 = sha256(canonicalJson(parentReasons));
    const parentPositiveResultSha256 = sha256(canonicalJson(parentPositiveResults));
    const fixtureFlowReasonEvidenceSha256 = sha256(canonicalJson({
      parent_ledger: parentReasons,
      timestamp: x2Reasons,
      state: [stateReceipt.reason],
      input: x1Reasons,
    }));

    console.log(
      JSON.stringify({
        schema: 'gbrain.exact-target-order1-pure-test-receipt.v2',
        focused_command_argv: FOCUSED_COMMAND_ARGV,
        source_test_authority_only: true,
        committed_focused_receipt_authority: 'runtime_proof_only',
        order1_parent_design_sha256: ORDER1_PARENT_DESIGN_SHA256,
        order1_gap_map_sha256: ORDER1_GAP_MAP_SHA256,
        order1_external_gates_v7_historical_sha256:
          ORDER1_EXTERNAL_GATES_V7_HISTORICAL_SHA256,
        order1_external_gates_v8_controlling_sha256:
          ORDER1_EXTERNAL_GATES_V8_CONTROLLING_SHA256,
        order1_controlling_checklist_v4_sha256: ORDER1_CHECKLIST_V4_SHA256,
        schema_rows: EXACT_TARGET_SCHEMA_ROWS.length,
        serialized_bytes: EXACT_TARGET_SCHEMA_SERIALIZED_BYTES,
        schema_sha256: DIGEST,
        query_bytes: EXACT_TARGET_SCHEMA_QUERY_BYTES,
        query_sha256: EXACT_TARGET_SCHEMA_QUERY_SHA256,
        positive_permutations: 4,
        parent_positive_permutation_result_sha256: parentPositiveResultSha256,
        parent_ledger_instance_count: mutationIds.size,
        parent_ledger_unique_id_count: mutationIds.size,
        parent_ledger_id_sha256: parentIdSha256,
        parent_ledger_result_sha256: parentResultSha256,
        parent_ledger_graph_sha256: parentGraphSha256,
        parent_ledger_histogram: mutationHistogram,
        parent_ledger_reason_set: parentReasons,
        parent_ledger_reason_set_sha256: parentReasonSetSha256,
        reason_codes_covered: fixtureFlowReasons.size,
        parent_ledger_used_reasons: 19,
        pre_x1_outside_parent_reason_count: 2,
        x1_external_reason_count: 1,
        total_validator_reason_count: 22,
        fixture_flow_reason_evidence_sha256: fixtureFlowReasonEvidenceSha256,
        timestamp_reason_fixture_owner: 'X2',
        state_reason_fixture_owner: stateReceipt.id,
        input_reason_fixture_owner: 'X1',
        threaded_unused_to_consumed: true,
        stale_unused_replay_limitation_proved: true,
        state_fixture_id: stateReceipt.id,
        state_reason: stateReceipt.reason,
        state_reason_family: stateReceipt.family,
        state_decision_recursive_frozen: stateReceipt.recursiveFrozen,
        state_returned_state_nonaliased: stateReceipt.stateNonaliased,
        state_no_throw: stateReceipt.noThrow,
        state_result_sha256: stateReceipt.resultSha256,
        state_decision_graph_sha256: stateReceipt.decisionGraphSha256,
        state_returned_state_graph_sha256: stateReceipt.returnedStateGraphSha256,
        x1_case_count: 187,
        x1_pass_count: 187,
        x1_fail_count: 0,
        x1_error_count: 0,
        x1_throw_count: 0,
        x1_reason: 'LIVE_SCHEMA_INPUT_REJECTED',
        x1_reason_family: 'LIVE_SCHEMA_INPUT_REJECTED',
        x1_reason_count: x1Reasons.length,
        x1_case_ids_sha256:
          '4a23eccebb8f56d5f25e50d9da7ac196007b7fda5516e8459724a780de23cb22',
        x1_case_results_sha256: x1Receipt.caseResultsSha256,
        x1_decisions_recursive_frozen: x1Receipt.decisionsRecursiveFrozen,
        x1_decisions_nonaliased: x1Receipt.decisionsNonaliased,
        x1_frozen_state_case_count: x1Receipt.frozenStates,
        x1_null_state_case_count: x1Receipt.nullStates,
        x1_exotic_object_case_count: 25,
        x1_non_enumerable_case_count: 5,
        x1_decision_mutation_count: 748,
        x1_decision_mutation_pass_count: x1Receipt.decisionMutationPasses,
        x1_state_mutation_count: 917,
        x1_state_mutation_pass_count: x1Receipt.stateMutationPasses,
        x1_total_mutation_count: 1665,
        x1_unique_mutation_id_count: 1665,
        x1_total_mutation_pass_count: x1Receipt.mutationPasses,
        x1_total_mutation_fail_count: 0,
        x1_total_mutation_error_count: 0,
        x1_recursive_graph_unchanged_count: x1Receipt.mutationPasses,
        x1_graph_before_after_equal_count: x1Receipt.graphEqual,
        x1_graph_before_after_mismatch_count: 0,
        x1_mutation_ids_sha256:
          'f869fa936c0f2a2d2ab457a6b6f187acc6abf8fff84f6dd9a538bce1e9693709',
        x1_operation_catalog_sha256: x1Receipt.catalogSha256,
        x1_mutation_results_sha256: x1Receipt.mutationResultsSha256,
        x2_invalid_count: 12,
        x2_invalid_pass_count: x2Receipt.invalidPasses,
        x2_timestamp_reason_count: x2Receipt.reasonObservations,
        x2_positive_count: 1,
        x2_positive_pass_count: x2Receipt.positivePasses,
        x2_case_ids_sha256:
          '702a189b342a744640ccf014610ec22c337dd504030f241ed9cf9f9bce95351f',
        x2_result_sha256: x2Receipt.resultSha256,
        x2_positive_result_sha256: x2Receipt.positiveResultSha256,
        x3_caller_alias_case_count: 19,
        x3_caller_alias_pass_count: x3Receipt.callerPasses,
        x3_caller_result_sha256: x3Receipt.callerResultsSha256,
        x3_output_mutation_case_count: 209,
        x3_output_mutation_pass_count: x3Receipt.outputPasses,
        x3_output_mutation_ids_sha256:
          '6700fabc5ad8a8e66a98c86bf8672f98dd9952e9a10d203e9922d4c99106f0ab',
        x3_output_mutation_catalog_sha256: x3Receipt.catalogSha256,
        x3_mutation_results_sha256: x3Receipt.mutationResultsSha256,
        x3_full_graph_before_after_equal_count: x3Receipt.graphEqual,
        x3_full_graph_before_after_mismatch_count: 0,
        x3_recursive_frozen: x3Receipt.recursiveFrozen,
        x3_input_alias_count: x3Receipt.inputAliasCount,
        x3_caller_object_frozen_count: x3Receipt.callerObjectFrozenCount,
        x3_exact_state_property: 'decision.consumption_state',
        x3_exact_digest_property: 'decision.schema_sha256',
        x3_alias_derived_from_exact_state_property_count: 10,
        x3_state_alias_mutation_count: 10,
        x3_state_alias_mutation_pass_count: x3Receipt.stateAliasPasses,
        x3_returned_state_container_mutation_count: 5,
        x3_returned_state_container_mutation_pass_count:
          x3Receipt.returnedStateContainerPasses,
        x3_reflect_false_case_count: x3Receipt.reflectFalse,
        x3_reflect_false_pass_count: x3Receipt.reflectFalsePasses,
        x3_primitive_prototype_case_count: 0,
        x3_missing_property_target_count: 0,
        x3_exact_decision_property_mutation_count: 3,
        x3_exact_decision_property_mutation_pass_count:
          x3Receipt.exactDecisionPropertyPasses,
        x3_abstract_local_target_count: 0,
        external_effect_authority: 'external_order1_import_runtime_guard_only',
        package_authority: false,
        runtime_authority: false,
        database_authority: false,
        queue_authority: false,
        job_authority: false,
        claim_authority: false,
        handler_authority: false,
        model_authority: false,
        session_authority: false,
        f4b_authority: false,
        lane_d_authority: false,
      }),
    );
  });
});
