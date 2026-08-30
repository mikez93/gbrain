#!/usr/bin/env bun

import { createHash } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  constants,
  fchmodSync,
  fsyncSync,
  lstatSync,
  mkdtempSync,
  openSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { EXACT_TARGET_FORBIDDEN_CASES } from '../test/fixtures/exact-target-forbidden-effects/cases.ts';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, '..');
const DEFAULT_LOADER = join(
  SCRIPT_DIR,
  'vendor/web-tree-sitter-0.22.6/tree-sitter.cjs',
);
const DEFAULT_LICENSE = join(
  SCRIPT_DIR,
  'vendor/web-tree-sitter-0.22.6/LICENSE',
);
const DEFAULT_LOCK = join(REPO_ROOT, 'bun.lock');
const DEFAULT_RUNTIME = join(REPO_ROOT, 'src/assets/wasm/tree-sitter.wasm');
const DEFAULT_GRAMMAR = join(
  REPO_ROOT,
  'src/assets/wasm/grammars/tree-sitter-typescript.wasm',
);

export const EXACT_LOADER_SHA256 =
  'ddcacb69cd26c07322c51b798a63805fd99c272177c9633a978f3886358ca070';
export const EXACT_LICENSE_SHA256 =
  '5f9cf9fb6acb1972b35ae29119ce563bb60ec097656bc4b69b9bac2d04c7a147';
export const EXACT_RUNTIME_SHA256 =
  '29208e71028ab0c11dfcc941255075aad75545394467aa22d817a6356714090f';
export const EXACT_GRAMMAR_SHA256 =
  '8515404dceed38e1ed86aa34b09fcf3379fff1b4ff9dd3967bcd6d1eb5ac3d8f';
export const EXACT_LOCK_INTEGRITY =
  'sha512-hS87TH71Zd6mGAmYCvlgxeGDjqd9GTeqXNqTT+u0Gs51uIozNIaaq/kUAbV/Zf56jb2ZOyG8BxZs2GG9wbLi6Q==';

type SyntaxNode = {
  type: string;
  text: string;
  startIndex: number;
  endIndex: number;
  namedChildCount: number;
  namedChild(index: number): SyntaxNode | null;
  childForFieldName(name: string): SyntaxNode | null;
};

type ParserInstance = {
  setLanguage(language: unknown): void;
  parse(source: string): {
    rootNode: SyntaxNode & { hasError: boolean };
    delete(): void;
  };
  delete(): void;
};

type ParserConstructor = {
  new (): ParserInstance;
  init(options?: { locateFile?: (name: string) => string }): Promise<void>;
  Language: { load(path: string): Promise<unknown> };
};

export interface AstViolation {
  readonly kind: string;
  readonly text: string;
  readonly start: number;
  readonly end: number;
}

export interface AstScanResult {
  readonly label: string;
  readonly root: string;
  readonly has_error: boolean;
  readonly imports: readonly string[];
  readonly violations: readonly AstViolation[];
}

interface ParserContext {
  readonly parser: ParserInstance;
  readonly tempDir: string;
  readonly loaderCopyStat: {
    readonly dev: number;
    readonly ino: number;
    readonly mode: string;
    readonly sha256: string;
  };
}

function sha256(bytes: Uint8Array | string): string {
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

function verifiedRegularFile(path: string, expectedHash: string): Uint8Array {
  const before = lstatSync(path);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1) {
    throw new Error(`unsafe parser input: ${path}`);
  }
  const bytes = readFileSync(path);
  if (sha256(bytes) !== expectedHash) {
    throw new Error(`parser input hash mismatch: ${path}`);
  }
  const after = statSync(path);
  if (before.dev !== after.dev || before.ino !== after.ino) {
    throw new Error(`parser input changed while reading: ${path}`);
  }
  return bytes;
}

function copyExclusive(path: string, bytes: Uint8Array): void {
  const flags =
    constants.O_WRONLY |
    constants.O_CREAT |
    constants.O_EXCL |
    (constants.O_NOFOLLOW ?? 0);
  const fd = openSync(path, flags, 0o600);
  try {
    fchmodSync(fd, 0o600);
    writeFileSync(fd, bytes);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

async function createParserContext(options: {
  loader: string;
  loaderSha256: string;
  license: string;
  licenseSha256: string;
  lock: string;
  lockIntegrity: string;
  runtime: string;
  runtimeSha256: string;
  grammar: string;
  grammarSha256: string;
}): Promise<ParserContext> {
  const loaderBytes = verifiedRegularFile(options.loader, options.loaderSha256);
  verifiedRegularFile(options.license, options.licenseSha256);
  verifiedRegularFile(options.runtime, options.runtimeSha256);
  verifiedRegularFile(options.grammar, options.grammarSha256);
  const lockText = readFileSync(options.lock, 'utf8');
  if (
    !lockText.includes('web-tree-sitter@0.22.6') ||
    !lockText.includes(options.lockIntegrity)
  ) {
    throw new Error('locked parser version/integrity mismatch');
  }

  const tempDir = mkdtempSync(join(tmpdir(), 'gbrain-exact-target-ast-'));
  chmodSync(tempDir, 0o700);
  const loaderCopy = join(tempDir, 'tree-sitter.cjs');
  copyExclusive(loaderCopy, loaderBytes);
  const copied = lstatSync(loaderCopy);
  if (
    !copied.isFile() ||
    copied.isSymbolicLink() ||
    copied.nlink !== 1 ||
    copied.uid !== process.geteuid?.()
  ) {
    throw new Error('unsafe verified loader copy');
  }
  const copiedHash = sha256(readFileSync(loaderCopy));
  if (copiedHash !== options.loaderSha256) {
    throw new Error('verified loader copy hash mismatch');
  }

  const localRequire = createRequire(import.meta.url);
  const imported = localRequire(loaderCopy) as
    | ParserConstructor
    | { default?: ParserConstructor };
  const Parser =
    typeof imported === 'function'
      ? imported
      : (imported.default as ParserConstructor | undefined);
  if (!Parser) throw new Error('verified loader did not export Parser');
  await Parser.init({ locateFile: () => options.runtime });
  const language = await Parser.Language.load(options.grammar);
  const parser = new Parser();
  parser.setLanguage(language);
  return {
    parser,
    tempDir,
    loaderCopyStat: {
      dev: Number(copied.dev),
      ino: Number(copied.ino),
      mode: (copied.mode & 0o777).toString(8).padStart(4, '0'),
      sha256: copiedHash,
    },
  };
}

function walk(node: SyntaxNode, visit: (node: SyntaxNode) => void): void {
  visit(node);
  for (let index = 0; index < node.namedChildCount; index += 1) {
    const child = node.namedChild(index);
    if (child) walk(child, visit);
  }
}

function stringSpecifier(node: SyntaxNode): string | null {
  const source = node.childForFieldName('source');
  if (source) {
    const quoted = source.text.match(/^['"]([^'"]+)['"]$/);
    return quoted?.[1] ?? null;
  }
  const pattern =
    node.type === 'export_statement'
      ? /\bfrom\s+['"]([^'"]+)['"]/
      : /\bimport\s+['"]([^'"]+)['"]/;
  return node.text.match(pattern)?.[1] ?? null;
}

function compact(text: string): string {
  return text.replace(/\s+/g, '');
}

function violationForNode(node: SyntaxNode): string | null {
  const text = compact(node.text);
  if (node.type === 'call_expression' && /^import(?:\?\.)?\(/.test(text)) {
    return 'dynamic_import';
  }
  if (
    (node.type === 'call_expression' || node.type === 'new_expression') &&
    /^(?:new)?(?:globalThis\.)?(?:eval|Function|AsyncFunction|GeneratorFunction)(?:\?\.)?\(/.test(
      text,
    )
  ) {
    return 'dynamic_code';
  }
  if (
    node.type === 'call_expression' &&
    /^(?:globalThis\.)?(?:fetch)(?:\?\.)?\(/.test(text)
  ) {
    return 'network_global';
  }
  if (
    node.type === 'new_expression' &&
    /^new(?:globalThis\.)?WebSocket(?:\?\.)?\(/.test(text)
  ) {
    return 'network_global';
  }
  if (
    node.type === 'call_expression' &&
    /^(?:require|[A-Za-z_$][\w$]*)(?:\?\.)?\(/.test(text) &&
    /^require(?:\?\.)?\(/.test(text)
  ) {
    return 'require_call';
  }
  if (
    (node.type === 'member_expression' ||
      node.type === 'subscript_expression' ||
      node.type === 'optional_chain') &&
    /^(?:Bun|process|globalThis|import\.meta|WebAssembly)(?:\.|\[|\?\.)/.test(text)
  ) {
    return 'forbidden_global_access';
  }
  if (
    node.type === 'variable_declarator' &&
    /=\s*(?:Bun|process|globalThis|eval|Function|AsyncFunction|GeneratorFunction|fetch|WebSocket)\s*;?$/.test(
      node.text,
    )
  ) {
    return 'forbidden_global_alias';
  }
  if (
    (node.type === 'call_expression' || node.type === 'new_expression') &&
    /^(?:Bun|process|globalThis|WebAssembly)(?:\.|\[|\?\.)/.test(text)
  ) {
    return 'forbidden_global_call';
  }
  return null;
}

const FORBIDDEN_IMPORTS = [
  /^ai$/,
  /^@ai-sdk\//,
  /(?:^|\/)src\/core\/ai(?:\/|$)/,
  /(?:^|\/)src\/core\/(?:engine|postgres-engine)\.ts$/,
  /(?:^|\/)src\/core\/minions\/(?:queue|worker)\.ts$/,
  /(?:^|\/)src\/commands(?:\/|$)/,
  /^(?:postgres|pg|@electric-sql\/pglite)$/,
  /^(?:node:)?(?:child_process|net|http|https|fs)$/,
];

function importViolation(specifier: string): string | null {
  return FORBIDDEN_IMPORTS.some((pattern) => pattern.test(specifier))
    ? 'forbidden_import'
    : null;
}

export function scanTypeScriptSource(
  parser: ParserInstance,
  source: string,
  label: string,
): AstScanResult {
  const tree = parser.parse(source);
  try {
    const imports = new Set<string>();
    const violations: AstViolation[] = [];
    walk(tree.rootNode, (node) => {
      if (node.type === 'import_statement' || node.type === 'export_statement') {
        const specifier = stringSpecifier(node);
        if (specifier) {
          imports.add(specifier);
          const kind = importViolation(specifier);
          if (kind) {
            violations.push({
              kind,
              text: specifier,
              start: node.startIndex,
              end: node.endIndex,
            });
          }
        }
      }
      const kind = violationForNode(node);
      if (kind) {
        violations.push({
          kind,
          text: node.text.slice(0, 160),
          start: node.startIndex,
          end: node.endIndex,
        });
      }
    });
    const unique = new Map<string, AstViolation>();
    for (const violation of violations) {
      unique.set(
        `${violation.kind}:${violation.start}:${violation.end}`,
        violation,
      );
    }
    return {
      label,
      root: tree.rootNode.type,
      has_error: tree.rootNode.hasError,
      imports: [...imports].sort(),
      violations: [...unique.values()].sort(
        (left, right) =>
          left.start - right.start || left.kind.localeCompare(right.kind),
      ),
    };
  } finally {
    tree.delete();
  }
}

function argumentMap(argv: readonly string[]): Map<string, string[]> {
  const values = new Map<string, string[]>();
  for (let index = 0; index < argv.length; index += 1) {
    const key = argv[index]!;
    if (!key.startsWith('--')) throw new Error(`unexpected argument: ${key}`);
    const next = argv[index + 1];
    if (!next || next.startsWith('--')) {
      values.set(key, [...(values.get(key) ?? []), 'true']);
      continue;
    }
    values.set(key, [...(values.get(key) ?? []), next]);
    index += 1;
  }
  return values;
}

function one(
  args: Map<string, string[]>,
  name: string,
  fallback?: string,
): string {
  const values = args.get(name);
  if (!values?.length) {
    if (fallback !== undefined) return fallback;
    throw new Error(`missing argument: ${name}`);
  }
  if (values.length !== 1) throw new Error(`duplicate argument: ${name}`);
  return values[0]!;
}

function resolvedPath(value: string): string {
  return isAbsolute(value) ? value : resolve(REPO_ROOT, value);
}

async function main(argv: readonly string[]): Promise<number> {
  const args = argumentMap(argv);
  const allowedArguments = new Set([
    '--loader',
    '--loader-sha256',
    '--license',
    '--license-sha256',
    '--lock',
    '--lock-integrity',
    '--runtime',
    '--runtime-sha256',
    '--grammar',
    '--grammar-sha256',
    '--copy-verified-loader-owner-temp',
    '--fixtures',
    '--minimum-static-rejections',
    '--repeat',
    '--scan-file',
    '--source-base64',
    '--json',
  ]);
  for (const key of args.keys()) {
    if (!allowedArguments.has(key)) throw new Error(`unknown argument: ${key}`);
  }
  const fixturePath = args.get('--fixtures');
  if (fixturePath) {
    const expected = resolve(
      REPO_ROOT,
      'test/fixtures/exact-target-forbidden-effects/cases.ts',
    );
    if (fixturePath.length !== 1 || resolvedPath(fixturePath[0]!) !== expected) {
      throw new Error('fixture path does not match the accepted Order-0 corpus');
    }
    const fixtureInfo = lstatSync(expected);
    if (!fixtureInfo.isFile() || fixtureInfo.isSymbolicLink()) {
      throw new Error('unsafe Order-0 fixture corpus');
    }
  }
  const options = {
    loader: resolvedPath(one(args, '--loader', DEFAULT_LOADER)),
    loaderSha256: one(args, '--loader-sha256', EXACT_LOADER_SHA256),
    license: resolvedPath(one(args, '--license', DEFAULT_LICENSE)),
    licenseSha256: one(args, '--license-sha256', EXACT_LICENSE_SHA256),
    lock: resolvedPath(one(args, '--lock', DEFAULT_LOCK)),
    lockIntegrity: one(args, '--lock-integrity', EXACT_LOCK_INTEGRITY),
    runtime: resolvedPath(one(args, '--runtime', DEFAULT_RUNTIME)),
    runtimeSha256: one(args, '--runtime-sha256', EXACT_RUNTIME_SHA256),
    grammar: resolvedPath(one(args, '--grammar', DEFAULT_GRAMMAR)),
    grammarSha256: one(args, '--grammar-sha256', EXACT_GRAMMAR_SHA256),
  };
  const context = await createParserContext(options);
  try {
    const scanFiles = args.get('--scan-file') ?? [];
    const encodedSources = args.get('--source-base64') ?? [];
    const minimum = Number(one(args, '--minimum-static-rejections', '0'));
    const repeat = Number(one(args, '--repeat', '1'));
    if (!Number.isInteger(repeat) || repeat < 1 || repeat > 8) {
      throw new Error('repeat must be an integer from 1 to 8');
    }

    const runs: AstScanResult[][] = [];
    for (let run = 0; run < repeat; run += 1) {
      const results: AstScanResult[] = [];
      for (const path of scanFiles) {
        const absolute = resolvedPath(path);
        results.push(
          scanTypeScriptSource(
            context.parser,
            readFileSync(absolute, 'utf8'),
            path,
          ),
        );
      }
      for (let index = 0; index < encodedSources.length; index += 1) {
        results.push(
          scanTypeScriptSource(
            context.parser,
            Buffer.from(encodedSources[index]!, 'base64').toString('utf8'),
            `inline-${index}`,
          ),
        );
      }
      if (!scanFiles.length && !encodedSources.length) {
        for (const fixture of EXACT_TARGET_FORBIDDEN_CASES) {
          results.push(
            scanTypeScriptSource(context.parser, fixture.source, fixture.id),
          );
        }
      }
      runs.push(results);
    }

    const evidence = runs.map((results) => ({
      parser_errors: results.filter((result) => result.has_error).length,
      fixtures: results.length,
      rejected: results.filter((result) => result.violations.length > 0).length,
      results,
    }));
    const digests = evidence.map((run) => sha256(canonical(run)));
    const first = evidence[0]!;
    const pass =
      first.parser_errors === 0 &&
      first.rejected >= minimum &&
      digests.every((digest) => digest === digests[0]);
    const output = {
      schema: 'gbrain.exact-target-typescript-ast.v1',
      pass,
      loader: {
        source_sha256: options.loaderSha256,
        license_sha256: options.licenseSha256,
        runtime_sha256: options.runtimeSha256,
        grammar_sha256: options.grammarSha256,
        lock_integrity: options.lockIntegrity,
        owner_temp_copy: {
          directory_mode: '0700',
          ...context.loaderCopyStat,
          imported: true,
        },
      },
      repeat,
      identical: digests.every((digest) => digest === digests[0]),
      evidence_sha256: digests[0],
      parser_errors: first.parser_errors,
      fixtures: first.fixtures,
      rejected: first.rejected,
      scans: first.results,
    };
    process.stdout.write(`${canonical(output)}\n`);
    return pass ? 0 : 1;
  } finally {
    context.parser.delete();
    rmSync(context.tempDir, { recursive: true, force: true });
  }
}

if (import.meta.main) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (error) => {
      process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
      process.exit(1);
    },
  );
}
