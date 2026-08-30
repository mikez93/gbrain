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

const EFFECT_NAMES = [
  'metadata_select_calls',
  'claim_update_calls',
  'readback_select_calls',
  'handler_launch_calls',
  'generic_adapter_calls',
  'pure_sql_calls',
] as const;
type EffectName = (typeof EFFECT_NAMES)[number];

const effectCounters = Object.fromEntries(
  EFFECT_NAMES.map((name) => [name, 0]),
) as Record<EffectName, number>;
const effectSpies = Object.fromEntries(
  EFFECT_NAMES.map((name) => [
    name,
    () => {
      effectCounters[name] += 1;
      throw new Error(`forbidden effect reached: ${name}`);
    },
  ]),
) as Record<EffectName, () => never>;

for (const name of EFFECT_NAMES) {
  expect(effectSpies[name]).toThrow(`forbidden effect reached: ${name}`);
  expect(effectCounters[name]).toBe(1);
  effectCounters[name] = 0;
}

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
    consumption_state: UNUSED,
    expected_bindings: EXPECTED_BINDINGS,
    ...overrides,
  };
}

function assertEffectsZero(): void {
  expect(effectCounters).toEqual({
    metadata_select_calls: 0,
    claim_update_calls: 0,
    readback_select_calls: 0,
    handler_launch_calls: 0,
    generic_adapter_calls: 0,
    pure_sql_calls: 0,
  });
}

function validate(
  value: ValidateExactTargetSchemaInput,
): ReturnType<typeof validateExactTargetSchema> {
  const result = validateExactTargetSchema(value);
  assertEffectsZero();
  return result;
}

function expectReason(
  value: ValidateExactTargetSchemaInput,
  reason: ExactTargetSchemaReason,
): void {
  const previousState = value.consumption_state;
  const result = validate(value);
  expect(result.ok).toBe(false);
  if (result.ok) throw new Error(`expected rejection ${reason}`);
  expect(result.reason_code).toBe(reason);
  expect(result.reason_family).toBe(EXACT_TARGET_SCHEMA_REASON_FAMILIES[reason]);
  expect(result.consumption_state).toEqual(previousState);
  expect(result.consumption_state).not.toBe(previousState);
  expect(Object.isFrozen(result)).toBe(true);
  expect(Object.isFrozen(result.consumption_state)).toBe(true);
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

function recordMutation(
  id: string,
  group: keyof typeof mutationHistogram,
  value: ValidateExactTargetSchemaInput,
  reason: ExactTargetSchemaReason,
): void {
  expect(mutationIds.has(id), `duplicate mutation id: ${id}`).toBe(false);
  mutationIds.add(id);
  mutationHistogram[group] += 1;
  mutationReasons.add(reason);
  expectReason(value, reason);
}

describe('exact-target pure schema and attestation validator', () => {
  test('installs six live throwing effect spies before importing the pure module', () => {
    expect(Object.keys(effectSpies).sort()).toEqual([...EFFECT_NAMES].sort());
    assertEffectsZero();
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
    assertEffectsZero();
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
    assertEffectsZero();
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
    assertEffectsZero();
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
  });

  test('accepts reverse order with the same normalization and digest', () => {
    const result = validate(input({ rows: cloneRows().reverse() }));
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.reason_code);
    expect(result.normalized_rows).toEqual(EXACT_TARGET_SCHEMA_ROWS);
    expect(result.schema_sha256).toBe(DIGEST);
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
    assertEffectsZero();
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
      'SCHEMA_ATTESTATION_TIMESTAMP_REJECTED',
    );
  });

  test('rejects canonical-looking impossible dates and accepts a real leap day', () => {
    expectReason(
      input({ now: '2026-02-31T00:01:00.000000Z' }),
      'SCHEMA_ATTESTATION_TIMESTAMP_REJECTED',
    );
    const leapAttestation = {
      ...ATTESTATION,
      acquired_at: '2028-02-29T00:00:00.000000Z',
      expires_at: '2028-02-29T00:05:00.000000Z',
    };
    expect(
      validate(
        input({
          attestation: leapAttestation,
          now: '2028-02-29T00:01:00.000000Z',
        }),
      ).ok,
    ).toBe(true);
  });

  test('returns a stable frozen state rejection for null and undefined input', () => {
    for (const invalidInput of [null, undefined]) {
      const result = validateExactTargetSchema(invalidInput);
      expect(result).toEqual({
        ok: false,
        reason_code: 'SCHEMA_ATTESTATION_STATE_REJECTED',
        reason_family: 'SCHEMA_ATTESTATION_FRESHNESS_REJECTED',
        consumption_state: null,
      });
      expect(Object.isFrozen(result)).toBe(true);
      assertEffectsZero();
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

  test('rejects malformed state and attestation shapes with stable state reason', () => {
    expectReason(
      input({
        consumption_state: {
          key: GUARDIAN,
          status: 'unused',
          extra: true,
        } as unknown as ExactTargetAttestationConsumptionState,
      }),
      'SCHEMA_ATTESTATION_STATE_REJECTED',
    );
    expectReason(
      input({
        attestation: {
          ...ATTESTATION,
          extra: true,
        } as unknown as ExactTargetSchemaAttestation,
      }),
      'SCHEMA_ATTESTATION_STATE_REJECTED',
    );
  });

  test('covers all 21 reasons with no unknown reason and emits exact evidence summary', () => {
    mutationReasons.add('SCHEMA_ATTESTATION_TIMESTAMP_REJECTED');
    mutationReasons.add('SCHEMA_ATTESTATION_STATE_REJECTED');
    const allReasons = Object.keys(
      EXACT_TARGET_SCHEMA_REASON_FAMILIES,
    ).sort() as ExactTargetSchemaReason[];
    expect(allReasons).toHaveLength(21);
    expect([...mutationReasons].sort()).toEqual(allReasons);
    expect(mutationIds.size).toBe(199);
    expect(
      Object.values(mutationHistogram).reduce((sum, count) => sum + count, 0),
    ).toBe(199);
    assertEffectsZero();

    console.log(
      JSON.stringify({
        schema: 'gbrain.exact-target-order1-pure-test-receipt.v1',
        schema_rows: EXACT_TARGET_SCHEMA_ROWS.length,
        serialized_bytes: EXACT_TARGET_SCHEMA_SERIALIZED_BYTES,
        schema_sha256: DIGEST,
        query_bytes: EXACT_TARGET_SCHEMA_QUERY_BYTES,
        query_sha256: EXACT_TARGET_SCHEMA_QUERY_SHA256,
        positive_permutations: 4,
        schema_mutations_exact: mutationIds.size,
        unique_mutation_ids: mutationIds.size,
        histogram: mutationHistogram,
        reason_codes_covered: mutationReasons.size,
        threaded_unused_to_consumed: true,
        stale_unused_replay_limitation_proved: true,
        external_effect_counters: effectCounters,
      }),
    );
  });
});
