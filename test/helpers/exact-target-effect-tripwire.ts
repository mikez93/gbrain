import { resolve } from 'node:path';

export interface TripwireScan {
  readonly label: string;
  readonly violations: readonly { readonly kind: string }[];
  readonly has_error: boolean;
}

export interface TripwireResult {
  readonly exitCode: number;
  readonly effectCount: 0;
  readonly scans: readonly TripwireScan[];
  readonly stderr: string;
}

/**
 * Run untrusted snippets only through the isolated AST child. The snippets are
 * never evaluated: a zero effect count means rejection happened before an
 * effect-capable runtime received source authority.
 */
export function runRejectedEffectTripwire(
  sources: readonly string[],
): TripwireResult {
  const command = [
    process.execPath,
    resolve('scripts/exact-target-typescript-ast.ts'),
    '--json',
    '--minimum-static-rejections',
    String(sources.length),
  ];
  for (const source of sources) {
    command.push('--source-base64', Buffer.from(source).toString('base64'));
  }
  const child = Bun.spawnSync(command, {
    cwd: process.cwd(),
    env: { PATH: process.env.PATH ?? '' },
    stdin: 'ignore',
    stdout: 'pipe',
    stderr: 'pipe',
  });
  const stdout = new TextDecoder().decode(child.stdout);
  const stderr = new TextDecoder().decode(child.stderr);
  const parsed = stdout ? JSON.parse(stdout) : { scans: [] };
  return {
    exitCode: child.exitCode,
    effectCount: 0,
    scans: parsed.scans ?? [],
    stderr,
  };
}
