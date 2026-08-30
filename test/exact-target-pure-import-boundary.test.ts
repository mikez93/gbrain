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
import { EXACT_TARGET_FORBIDDEN_CASES } from './fixtures/exact-target-forbidden-effects/cases.ts';

const ROOTS = [
  'src/core/minions/exact-target-contract.ts',
  'src/core/minions/exact-target-pure-types.ts',
] as const;

function text(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
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
    expect(runDirectory.isDirectory()).toBe(true);
    expect(runDirectory.mode & 0o777).toBe(0o700);
    expect(receiptInfo.isFile()).toBe(true);
    expect(receiptInfo.isSymbolicLink()).toBe(false);
    expect(receiptInfo.mode & 0o777).toBe(0o600);
    expect(receiptInfo.nlink).toBe(1);
    expect(sha256(receiptBytes)).toBe(summary.receipt_sha256);
    expect(receipt.source.commit).toBe(summary.source_commit);
    expect(receipt.source.tree).toBe(summary.source_tree);
    expect(receipt.graph_repeat).toEqual({
      runs: 2,
      identical: true,
      graph_sha256: summary.graph_sha256,
    });
    expect(summary.receipt_ino).toBeGreaterThan(0);
    expect(summary.run_directory_ino).toBeGreaterThan(0);
    expect(summary.receipt_path.startsWith(summary.run_directory_path)).toBe(true);
  });

  test('fails closed on all eight receipt integrity mutations', () => {
    const result = run([
      '/usr/bin/python3',
      'scripts/run-exact-target-pure-import-guard.py',
      '--self-test-receipt-safety',
    ]);
    expect(result.exitCode, result.stderr).toBe(0);
    const receipt = JSON.parse(result.stdout);
    expect(receipt.pass).toBe(true);
    expect(receipt.case_count).toBe(8);
    expect(receipt.cases.map((entry: { name: string }) => entry.name)).toEqual([
      'precreated_receipt_regular_file',
      'receipt_symlink',
      'receipt_hardlink_nlink_gt_one',
      'stale_prior_receipt',
      'precreated_run_directory_name_collision',
      'unsafe_run_directory_mode_or_owner',
      'named_opened_inode_swap',
      'two_concurrent_runs_distinct_dirs_receipts_challenges_bindings',
    ]);
    for (const entry of receipt.cases) expect(entry.pass).toBe(true);
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
