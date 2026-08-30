import { resolve } from 'node:path';

export interface TripwireScan {
  readonly label: string;
  readonly violations: readonly { readonly kind: string }[];
  readonly has_error: boolean;
}

export interface TripwireResult {
  readonly exitCode: number;
  readonly executorInvocationCount: number;
  readonly effectCount: number;
  readonly rejectionCount: number;
  readonly scans: readonly TripwireScan[];
  readonly stderr: string;
}

export interface GuardedExecutorSpy {
  readonly invocationCount: number;
  readonly effectCount: number;
  execute(source: string, label: string): never;
}

/**
 * The executor is deliberately incapable of evaluating source. Reaching it is
 * itself the counted forbidden effect and throws immediately.
 */
export function createGuardedExecutorSpy(): GuardedExecutorSpy {
  let invocationCount = 0;
  let effectCount = 0;
  return {
    get invocationCount() {
      return invocationCount;
    },
    get effectCount() {
      return effectCount;
    },
    execute(_source: string, label: string): never {
      invocationCount += 1;
      effectCount += 1;
      throw new Error(`forbidden fixture reached guarded executor: ${label}`);
    },
  };
}

/**
 * Run untrusted snippets only through the isolated AST child. The snippets are
 * never evaluated. A fixture that is not rejected reaches the real guarded
 * executor spy, increments both counters, and fails closed without performing
 * the fixture's dangerous operation.
 */
export function runRejectedEffectTripwire(
  sources: readonly string[],
  executor: GuardedExecutorSpy = createGuardedExecutorSpy(),
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
  const scans: TripwireScan[] = parsed.scans ?? [];
  let rejectionCount = 0;
  for (const [index, source] of sources.entries()) {
    const scan = scans[index];
    if (scan && !scan.has_error && scan.violations.length > 0) {
      rejectionCount += 1;
      continue;
    }
    try {
      executor.execute(source, scan?.label ?? `fixture-${index}`);
    } catch {
      // The guarded executor always throws before source evaluation.
    }
  }
  return {
    exitCode: child.exitCode,
    executorInvocationCount: executor.invocationCount,
    effectCount: executor.effectCount,
    rejectionCount,
    scans,
    stderr,
  };
}
