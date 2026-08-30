import { describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync } from 'node:fs';
import './exact-target-pure-effect-tripwire.test.ts';
import {
  EXACT_TARGET_APPROVED_LOCK_DURATION_MS,
  EXACT_TARGET_FIELDS,
  EXACT_TARGET_SCHEMA_DIGEST,
} from '../src/core/minions/exact-target-contract.ts';
import * as pureTypes from '../src/core/minions/exact-target-pure-types.ts';
import {
  EXACT_TARGET_ALIASED_REQUIRE_FALSIFIER,
  EXACT_TARGET_FORBIDDEN_CASES,
} from './fixtures/exact-target-forbidden-effects/cases.ts';

const ROOTS = [
  'src/core/minions/exact-target-contract.ts',
  'src/core/minions/exact-target-pure-types.ts',
] as const;

const FORBID_PROFILE = {
  id: 'exact-target-orders-0-2-v2',
  allowed_bare_imports: ['node:crypto', 'node:util'],
  forbidden_path_fragments: [
    'src/core/ai/',
    'src/core/engine.ts',
    'src/core/postgres-engine.ts',
    'src/core/minions/queue.ts',
    'src/core/minions/worker.ts',
    'src/commands/',
  ],
  fail_closed: true,
} as const;

function text(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonical(object[key])}`)
    .join(',')}}`;
}

function sha256Canonical(value: unknown): string {
  return sha256(new TextEncoder().encode(canonical(value)));
}

function run(command: readonly string[]) {
  const result = Bun.spawnSync([...command], {
    cwd: process.cwd(),
    env: { PATH: process.env.PATH ?? '' },
    stdin: 'ignore',
    stdout: 'pipe',
    stderr: 'pipe',
  });
  return {
    exitCode: result.exitCode,
    stdout: text(result.stdout),
    stderr: text(result.stderr),
  };
}

function astCommand(extra: readonly string[] = []): string[] {
  return [
    process.execPath,
    'scripts/exact-target-typescript-ast.ts',
    '--loader',
    'scripts/vendor/web-tree-sitter-0.22.6/tree-sitter.cjs',
    '--loader-sha256',
    'ddcacb69cd26c07322c51b798a63805fd99c272177c9633a978f3886358ca070',
    '--license',
    'scripts/vendor/web-tree-sitter-0.22.6/LICENSE',
    '--license-sha256',
    '5f9cf9fb6acb1972b35ae29119ce563bb60ec097656bc4b69b9bac2d04c7a147',
    '--lock',
    'bun.lock',
    '--lock-integrity',
    'sha512-hS87TH71Zd6mGAmYCvlgxeGDjqd9GTeqXNqTT+u0Gs51uIozNIaaq/kUAbV/Zf56jb2ZOyG8BxZs2GG9wbLi6Q==',
    '--runtime',
    'src/assets/wasm/tree-sitter.wasm',
    '--runtime-sha256',
    '29208e71028ab0c11dfcc941255075aad75545394467aa22d817a6356714090f',
    '--grammar',
    'src/assets/wasm/grammars/tree-sitter-typescript.wasm',
    '--grammar-sha256',
    '8515404dceed38e1ed86aa34b09fcf3379fff1b4ff9dd3967bcd6d1eb5ac3d8f',
    '--json',
    ...extra,
  ];
}

function guardCommand(): string[] {
  return [
    '/usr/bin/python3',
    'scripts/run-exact-target-pure-import-guard.py',
    '--repo',
    '.',
    '--order',
    '0',
    '--root',
    ROOTS[0],
    '--root',
    ROOTS[1],
    '--forbid-profile',
    'exact-target-orders-0-2-v2',
    '--output-mode',
    'owner-temp-exclusive',
    '--stdout-summary',
  ];
}

describe('exact-target pure import boundary', () => {
  test('exports the exact unique 46-field transport order', () => {
    expect(EXACT_TARGET_FIELDS).toHaveLength(46);
    expect(new Set(EXACT_TARGET_FIELDS).size).toBe(46);
    expect(EXACT_TARGET_FIELDS[0]).toBe('id');
    expect(EXACT_TARGET_FIELDS.at(-1)).toBe('updated_at');
  });

  test('pins the accepted schema and policy constants', () => {
    expect(EXACT_TARGET_SCHEMA_DIGEST).toBe(
      '3e4ce8713061b39feff9cb0ba4ba9f9e321322231c743d41ad51bd350b26c4e6',
    );
    expect(EXACT_TARGET_APPROVED_LOCK_DURATION_MS).toBe(45_000);
  });

  test('keeps the type-only module runtime-empty', () => {
    expect(Object.keys(pureTypes)).toEqual([]);
    expect(Object.isFrozen(EXACT_TARGET_FIELDS)).toBe(false);
  });

  test('parses both pure roots with zero forbidden matches', () => {
    const command = astCommand(ROOTS.flatMap((root) => ['--scan-file', root]));
    const result = run(command);
    expect(result.exitCode, result.stderr).toBe(0);
    const receipt = JSON.parse(result.stdout);
    expect(receipt.fixtures).toBe(2);
    expect(receipt.rejected).toBe(0);
    expect(receipt.parser_errors).toBe(0);
    expect(receipt.loader.owner_temp_copy.imported).toBe(true);
  });

  test('reproduces deterministic 30-fixture AST evidence twice', () => {
    expect(EXACT_TARGET_FORBIDDEN_CASES).toHaveLength(30);
    const result = run(
      astCommand(['--minimum-static-rejections', '30', '--repeat', '2']),
    );
    expect(result.exitCode, result.stderr).toBe(0);
    const receipt = JSON.parse(result.stdout);
    expect(receipt.rejected).toBe(30);
    expect(receipt.identical).toBe(true);
    expect(receipt.evidence_sha256).toHaveLength(64);
  });

  test('resolves the transitive graph without queue, engine, gateway, or ai', () => {
    const command = [
      '/usr/bin/python3',
      'scripts/check-exact-target-pure-imports.py',
      '--repo',
      '.',
      ...ROOTS.flatMap((root) => ['--root', root]),
      '--forbid-profile',
      'exact-target-orders-0-2-v2',
      '--json',
    ];
    const results = [run(command), run(command)];
    for (const result of results) {
      expect(result.exitCode, result.stderr).toBe(0);
    }
    const receipts = results.map((result) => JSON.parse(result.stdout));
    expect(receipts[0].forbidden_match_count).toBe(0);
    expect(receipts[0].resolved_transitive_modules).toEqual([...ROOTS].sort());
    expect(receipts[0].edge_count).toBe(1);
    expect(receipts[0].graph_sha256).toHaveLength(64);
    expect(receipts[1].graph_sha256).toBe(receipts[0].graph_sha256);
    expect(receipts[1].module_sha256).toEqual(receipts[0].module_sha256);
  });

  test('publishes an exclusive owner-only bound receipt', () => {
    const result = run(guardCommand());
    expect(result.exitCode, result.stderr).toBe(0);
    const summary = JSON.parse(result.stdout);
    const runDirectory = lstatSync(summary.run_directory_path);
    const receiptInfo = lstatSync(summary.receipt_path);
    const receiptBytes = readFileSync(summary.receipt_path);
    const receipt = JSON.parse(receiptBytes.toString());
    expect(summary.pass).toBe(true);
    expect(summary.roots).toBe(2);
    expect(summary.receipt_mode).toBe('0600');
    expect(summary.run_directory_mode).toBe('0700');
    expect(summary.receipt_sha256).toHaveLength(64);
    expect(summary.graph_repeat_runs).toBe(2);
    expect(summary.graph_repeat_identical).toBe(true);
    expect(summary.runtime_fixture_count).toBe(30);
    expect(summary.runtime_executor_invocations).toBe(0);
    expect(summary.runtime_effect_total).toBe(0);
    expect(summary.runtime_all_children_stubbed).toBe(true);
    expect(summary.verified_loader_copy_count).toBe(2);
    expect(runDirectory.isDirectory()).toBe(true);
    expect(runDirectory.mode & 0o777).toBe(0o700);
    expect(receiptInfo.isFile()).toBe(true);
    expect(receiptInfo.isSymbolicLink()).toBe(false);
    expect(receiptInfo.mode & 0o777).toBe(0o600);
    expect(receiptInfo.nlink).toBe(1);
    expect(sha256(receiptBytes)).toBe(summary.receipt_sha256);
    expect(receipt.command_argv[0]).toMatch(/\/usr\/bin\/python3$/);
    expect(receipt.command_argv.slice(1)).toEqual(guardCommand().slice(1));
    expect(sha256Canonical(receipt.command_argv)).toBe(
      receipt.command_argv_sha256,
    );
    expect(receipt.command_argv_sha256).toBe(summary.command_argv_sha256);
    expect(receipt.scanner_command_argv[0]).toMatch(/\/usr\/bin\/python3$/);
    expect(receipt.scanner_command_argv.slice(1)).toEqual([
      'scripts/check-exact-target-pure-imports.py',
      '--repo',
      '.',
      ...ROOTS.flatMap((root) => ['--root', root]),
      '--forbid-profile',
      FORBID_PROFILE.id,
      '--json',
    ]);
    expect(sha256Canonical(receipt.scanner_command_argv)).toBe(
      receipt.scanner_command_argv_sha256,
    );
    expect(receipt.roots).toEqual(ROOTS);
    expect(receipt.profile).toBe(FORBID_PROFILE.id);
    expect(receipt.run_challenge).toMatch(/^[0-9a-f]{64}$/);
    expect(sha256(new TextEncoder().encode(receipt.run_challenge))).toBe(
      summary.run_challenge_sha256,
    );
    expect(receipt.source.commit).toBe(summary.source_commit);
    expect(receipt.source.tree).toBe(summary.source_tree);
    expect(receipt.source.commit).toBe(run(['git', 'rev-parse', 'HEAD']).stdout.trim());
    expect(receipt.source.tree).toBe(
      run(['git', 'rev-parse', 'HEAD^{tree}']).stdout.trim(),
    );
    expect(receipt.graph_repeat).toEqual({
      runs: 2,
      identical: true,
      graph_sha256: summary.graph_sha256,
    });
    expect(summary.receipt_ino).toBeGreaterThan(0);
    expect(summary.run_directory_ino).toBeGreaterThan(0);
    expect(summary.receipt_path).toBe(`${summary.run_directory_path}/receipt.json`);
    expect(summary.receipt_dev).toBe(Number(receiptInfo.dev));
    expect(summary.receipt_ino).toBe(Number(receiptInfo.ino));
    expect(summary.run_directory_dev).toBe(Number(runDirectory.dev));
    expect(summary.run_directory_ino).toBe(Number(runDirectory.ino));

    const expectedModules = Object.fromEntries(
      ROOTS.map((root) => [root, sha256(readFileSync(root))]),
    );
    const expectedEdges = [[ROOTS[0], ROOTS[1]]];
    const expectedGraph = {
      roots: [...ROOTS],
      modules: expectedModules,
      edges: expectedEdges,
    };
    expect(receipt.guard.roots).toEqual(ROOTS);
    expect(receipt.guard.resolved_transitive_modules).toEqual([...ROOTS].sort());
    expect(receipt.guard.module_sha256).toEqual(expectedModules);
    expect(receipt.guard.edges).toEqual(expectedEdges);
    expect(receipt.guard.edge_count).toBe(expectedEdges.length);
    expect(receipt.guard.graph_sha256).toBe(sha256Canonical(expectedGraph));
    expect(receipt.guard.graph_sha256).toBe(summary.graph_sha256);
    expect(receipt.guard.profile).toBe(FORBID_PROFILE.id);
    expect(receipt.guard.profile_sha256).toBe(sha256Canonical(FORBID_PROFILE));
    expect(receipt.guard.scanner_sha256).toBe(
      sha256(readFileSync('scripts/check-exact-target-pure-imports.py')),
    );
    expect(receipt.guard.ast_scanner_sha256).toBe(
      sha256(readFileSync('scripts/exact-target-typescript-ast.ts')),
    );
    expect(receipt.guard.forbidden_match_count).toBe(0);
    expect(receipt.guard.dynamic_import_matches).toBe(0);
    expect(receipt.guard.environment_access_matches).toBe(0);

    expect(receipt.guard_runs).toHaveLength(2);
    expect(receipt.guard_runs.map((guard: { graph_sha256: string }) => guard.graph_sha256)).toEqual([
      summary.graph_sha256,
      summary.graph_sha256,
    ]);
    const loaderCopies = receipt.guard_runs.flatMap(
      (guard: { ast_runs: Array<{ loader: { owner_temp_copy: unknown } }> }) =>
        guard.ast_runs.map((astRun) => astRun.loader.owner_temp_copy),
    );
    expect(loaderCopies).toHaveLength(2);
    expect(new Set(loaderCopies.map((copy: { ino: number }) => copy.ino)).size).toBe(2);
    for (const copy of loaderCopies as Array<{
      dev: number;
      ino: number;
      mode: string;
      directory_mode: string;
      imported: boolean;
      sha256: string;
    }>) {
      expect(copy.dev).toBeGreaterThan(0);
      expect(copy.ino).toBeGreaterThan(0);
      expect(copy.mode).toBe('0600');
      expect(copy.directory_mode).toBe('0700');
      expect(copy.imported).toBe(true);
      expect(copy.sha256).toBe(
        'ddcacb69cd26c07322c51b798a63805fd99c272177c9633a978f3886358ca070',
      );
    }
    for (const guardRun of receipt.guard_runs) {
      expect(guardRun.module_sha256).toEqual(expectedModules);
      expect(guardRun.edges).toEqual(expectedEdges);
      expect(guardRun.profile_sha256).toBe(sha256Canonical(FORBID_PROFILE));
      expect(guardRun.scanner_sha256).toBe(receipt.guard.scanner_sha256);
      expect(guardRun.ast_scanner_sha256).toBe(
        receipt.guard.ast_scanner_sha256,
      );
      for (const astRun of guardRun.ast_runs) {
        const astArgv = [
          'bun',
          'scripts/exact-target-typescript-ast.ts',
          '--json',
          ...astRun.module_batch.flatMap((root: string) => [
            '--scan-file',
            root,
          ]),
        ];
        expect(sha256Canonical(astArgv)).toBe(astRun.command_argv_sha256);
        expect(astRun.parser_errors).toBe(0);
        expect(astRun.loader.source_sha256).toBe(
          'ddcacb69cd26c07322c51b798a63805fd99c272177c9633a978f3886358ca070',
        );
        expect(astRun.loader.license_sha256).toBe(
          '5f9cf9fb6acb1972b35ae29119ce563bb60ec097656bc4b69b9bac2d04c7a147',
        );
        expect(astRun.loader.runtime_sha256).toBe(
          '29208e71028ab0c11dfcc941255075aad75545394467aa22d817a6356714090f',
        );
        expect(astRun.loader.grammar_sha256).toBe(
          '8515404dceed38e1ed86aa34b09fcf3379fff1b4ff9dd3967bcd6d1eb5ac3d8f',
        );
      }
    }

    const runtime = receipt.runtime_tripwire;
    expect(runtime.command_argv).toEqual([
      'bun',
      '--config=/dev/null',
      'test/helpers/exact-target-effect-tripwire.ts',
      '--suite',
    ]);
    expect(sha256Canonical(runtime.command_argv)).toBe(
      runtime.command_argv_sha256,
    );
    expect(runtime.helper_sha256).toBe(
      sha256(readFileSync('test/helpers/exact-target-effect-tripwire.ts')),
    );
    expect(runtime.fixtures_sha256).toBe(
      sha256(
        readFileSync('test/fixtures/exact-target-forbidden-effects/cases.ts'),
      ),
    );
    expect(runtime.receipt.fixture_count).toBe(30);
    expect(runtime.receipt.isolated_child_count).toBe(30);
    expect(runtime.receipt.required_stubs_per_child).toBe(26);
    expect(runtime.receipt.total_stub_installs).toBe(780);
    expect(runtime.receipt.all_children_stubbed).toBe(true);
    expect(runtime.receipt.rejection_count).toBe(30);
    expect(runtime.receipt.executor_invocations).toBe(0);
    expect(runtime.receipt.effect_total).toBe(0);
    expect(
      Object.values(runtime.receipt.effect_vector).every((count) => count === 0),
    ).toBe(true);
    expect(receipt.observed_counts).toEqual({
      static_forbidden_matches: 0,
      dynamic_import_matches: 0,
      environment_access_matches: 0,
      runtime_executor_invocations: 0,
      runtime_effect_total: 0,
    });
  });

  test('uses cause-bound receipt oracles and two full concurrent guards', () => {
    const result = run([
      '/usr/bin/python3',
      'scripts/run-exact-target-pure-import-guard.py',
      '--self-test-receipt-safety',
    ]);
    expect(result.exitCode, result.stderr).toBe(0);
    const receipt = JSON.parse(result.stdout);
    expect(receipt.pass).toBe(true);
    expect(receipt.case_count).toBe(9);
    expect(receipt.cases.map((entry: { name: string }) => entry.name)).toEqual([
      'precreated_receipt_regular_file',
      'receipt_symlink',
      'receipt_hardlink_nlink_gt_one',
      'stale_prior_receipt',
      'precreated_run_directory_name_collision',
      'unsafe_run_directory_mode',
      'injected_effective_uid_owner_mismatch',
      'named_opened_inode_swap',
      'two_overlapping_full_guard_invocations',
    ]);
    for (const entry of receipt.cases) expect(entry.pass).toBe(true);
    const hostile = receipt.cases.slice(0, 8);
    for (const entry of hostile) {
      expect(entry.expected_class).toBe('ReceiptSafetyError');
      expect(entry.observed_class).toBe(entry.expected_class);
      expect(entry.observed_reason).toBe(entry.expected_reason);
      expect(entry.observed_seam).toBe(entry.expected_seam);
    }
    const ownerMismatch = hostile.find(
      (entry: { name: string }) =>
        entry.name === 'injected_effective_uid_owner_mismatch',
    );
    expect(ownerMismatch.expected_reason).toBe('run_directory_owner_mismatch');
    expect(ownerMismatch.expected_seam).toBe('verify_run_directory');
    const concurrency = receipt.cases[8];
    expect(concurrency.barrier_parties).toBe(2);
    expect(concurrency.full_guard_invocations).toBe(2);
    expect(concurrency.both_complete_bindings).toBe(true);
    expect(Object.values(concurrency.distinct).every(Boolean)).toBe(true);
    expect(concurrency.no_overwrite_or_cross_trust).toBe(true);
    expect(concurrency.deterministic_bindings_equal).toBe(true);
    expect(receipt.oracle_falsifier.pass).toBe(true);
    expect(receipt.oracle_falsifier.probe.pass).toBe(false);
    expect(receipt.oracle_falsifier.probe.observed_class).toBe('RuntimeError');
    expect(receipt.oracle_falsifier.probe.observed_reason).toBeNull();
    expect(receipt.oracle_falsifier.probe.observed_seam).toBeNull();
  });

  test('rejects a synthetic forbidden import without evaluating it', () => {
    const encoded = Buffer.from("import 'ai'; export const value = 1;").toString(
      'base64',
    );
    const result = run(
      astCommand([
        '--source-base64',
        encoded,
        '--minimum-static-rejections',
        '1',
      ]),
    );
    expect(result.exitCode, result.stderr).toBe(0);
    const receipt = JSON.parse(result.stdout);
    expect(receipt.rejected).toBe(1);
    expect(receipt.scans[0].violations[0].kind).toBe('forbidden_import');
  });

  test('rejects aliased require through AST identity propagation', () => {
    const result = run(
      astCommand([
        '--source-base64',
        Buffer.from(EXACT_TARGET_ALIASED_REQUIRE_FALSIFIER.source).toString(
          'base64',
        ),
        '--minimum-static-rejections',
        '1',
      ]),
    );
    expect(result.exitCode, result.stderr).toBe(0);
    const receipt = JSON.parse(result.stdout);
    expect(receipt.fixtures).toBe(1);
    expect(receipt.rejected).toBe(1);
    expect(receipt.scans[0].violations.map((entry: { kind: string }) => entry.kind)).toEqual(
      ['forbidden_require_alias', 'aliased_require_call'],
    );
  });

  test('uses exact immutable vendor blobs', () => {
    expect(readFileSync('scripts/vendor/web-tree-sitter-0.22.6/LICENSE')).toHaveLength(
      1085,
    );
    expect(
      lstatSync('scripts/vendor/web-tree-sitter-0.22.6/tree-sitter.cjs').isFile(),
    ).toBe(true);
    expect(
      lstatSync('scripts/vendor/web-tree-sitter-0.22.6/tree-sitter.cjs').isSymbolicLink(),
    ).toBe(false);
  });
});
