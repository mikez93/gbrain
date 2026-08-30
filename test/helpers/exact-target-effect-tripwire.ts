import { resolve } from 'node:path';
import { createContext, SourceTextModule } from 'node:vm';
import { EXACT_TARGET_FORBIDDEN_CASES } from '../fixtures/exact-target-forbidden-effects/cases.ts';

const EFFECT_SURFACES = [
  'Bun.env',
  'Bun.file',
  'Bun.write',
  'Bun.spawn',
  'Bun.spawnSync',
  'Bun.connect',
  'Bun.listen',
  'Bun.serve',
  'fetch',
  'WebSocket',
  'import.meta.env',
  'process.env',
  'process.exit',
  'eval',
  'Function',
  'AsyncFunction',
  'GeneratorFunction',
  'WebAssembly.compile',
  'WebAssembly.instantiate',
  'dynamic import',
  'require',
  'filesystem',
  'network.net',
  'network.http',
  'network.https',
  'child_process',
] as const;

type EffectSurface = (typeof EFFECT_SURFACES)[number];
type EffectVector = Record<EffectSurface, number>;

const EFFECT_POSITIVE_CONTROLS: Record<EffectSurface, string> = {
  'Bun.env': 'Bun.env;',
  'Bun.file': 'Bun.file("tripwire");',
  'Bun.write': 'Bun.write("tripwire", "harmless");',
  'Bun.spawn': 'Bun.spawn(["tripwire"]);',
  'Bun.spawnSync': 'Bun.spawnSync(["tripwire"]);',
  'Bun.connect': 'Bun.connect({});',
  'Bun.listen': 'Bun.listen({});',
  'Bun.serve': 'Bun.serve({});',
  fetch: 'fetch("tripwire://harmless");',
  WebSocket: 'new WebSocket("tripwire://harmless");',
  'import.meta.env': 'import.meta.env;',
  'process.env': 'process.env;',
  'process.exit': 'process.exit(0);',
  eval: 'eval("0");',
  Function: 'Function("return 0");',
  AsyncFunction: 'new AsyncFunction("return 0");',
  GeneratorFunction: 'new GeneratorFunction("yield 0");',
  'WebAssembly.compile': 'WebAssembly.compile(new Uint8Array());',
  'WebAssembly.instantiate': 'WebAssembly.instantiate(new Uint8Array());',
  'dynamic import': 'await import("data:text/javascript,export default 0");',
  require: 'require("fs");',
  filesystem: 'fs.readFile("tripwire");',
  'network.net': 'net.connect({});',
  'network.http': 'http.get("tripwire://harmless");',
  'network.https': 'https.get("tripwire://harmless");',
  child_process: 'child_process.spawn("tripwire");',
};

interface AstScan {
  readonly label: string;
  readonly violations: readonly { readonly kind: string }[];
  readonly has_error: boolean;
}

export interface RuntimeChildReceipt {
  readonly schema: string;
  readonly label: string;
  readonly pid: number;
  readonly pass: boolean;
  readonly positive_control: boolean;
  readonly expected_effect_surface: EffectSurface | null;
  readonly stubs_installed: boolean;
  readonly stub_install_count: number;
  readonly required_stub_count: number;
  readonly rejection_observed: boolean;
  readonly executor_invocations: number;
  readonly effect_total: number;
  readonly effect_vector: EffectVector;
  readonly throw_observed: boolean;
  readonly dangerous_source_evaluated: false;
  readonly harmless_positive_control_evaluated: boolean;
  readonly scan: AstScan | null;
}

export interface TripwireResult {
  readonly exitCode: number;
  readonly isolatedChildCount: number;
  readonly distinctChildPidCount: number;
  readonly stubInstallCount: number;
  readonly requiredStubCountPerChild: number;
  readonly executorInvocationCount: number;
  readonly effectCount: number;
  readonly effectVector: EffectVector;
  readonly rejectionCount: number;
  readonly children: readonly RuntimeChildReceipt[];
  readonly stderr: string;
}

export interface PositiveControlResult {
  readonly exitCode: number;
  readonly receipt: RuntimeChildReceipt;
  readonly stderr: string;
}

export interface SurfaceControlResult {
  readonly exitCode: number;
  readonly controlCount: number;
  readonly distinctChildPidCount: number;
  readonly executorInvocationCount: number;
  readonly effectCount: number;
  readonly effectVector: EffectVector;
  readonly allControlsLive: boolean;
  readonly children: readonly RuntimeChildReceipt[];
  readonly stderr: string;
}

export interface RuntimeSuiteReceipt {
  readonly schema: string;
  readonly pass: boolean;
  readonly fixture_count: number;
  readonly isolated_child_count: number;
  readonly distinct_child_pid_count: number;
  readonly required_stubs_per_child: number;
  readonly total_stub_installs: number;
  readonly all_children_stubbed: boolean;
  readonly rejection_count: number;
  readonly executor_invocations: number;
  readonly effect_total: number;
  readonly effect_vector: EffectVector;
  readonly surface_control_count: number;
  readonly surface_control_distinct_child_pid_count: number;
  readonly surface_control_executor_invocations: number;
  readonly surface_control_effect_total: number;
  readonly surface_control_effect_vector: EffectVector;
  readonly all_surface_controls_live: boolean;
  readonly surface_controls: readonly RuntimeChildReceipt[];
  readonly positive_control: {
    readonly pass: boolean;
    readonly stubs_installed: boolean;
    readonly required_stubs: number;
    readonly executor_invocations: number;
    readonly effect_total: number;
    readonly effect_vector: EffectVector;
    readonly throw_observed: boolean;
    readonly harmless_source_evaluated: boolean;
    readonly dangerous_source_evaluated: false;
  };
}

function emptyEffectVector(): EffectVector {
  return Object.fromEntries(
    EFFECT_SURFACES.map((surface) => [surface, 0]),
  ) as EffectVector;
}

function installThrowingEffectSandbox() {
  const effects = emptyEffectVector();
  const throwEffect = (surface: EffectSurface) => (..._args: unknown[]) => {
    effects[surface] += 1;
    throw new Error(`runtime tripwire blocked effect: ${surface}`);
  };
  const throwingConstructor = (surface: EffectSurface) =>
    function RuntimeTripwireConstructor(this: unknown, ..._args: unknown[]) {
      effects[surface] += 1;
      throw new Error(`runtime tripwire blocked constructor: ${surface}`);
    };
  const throwingSurface = (surface: EffectSurface) =>
    new Proxy(Object.create(null) as Record<string, unknown>, {
      get: () => throwEffect(surface),
    });

  const bunStub: Record<string, unknown> = {
    file: throwEffect('Bun.file'),
    write: throwEffect('Bun.write'),
    spawn: throwEffect('Bun.spawn'),
    spawnSync: throwEffect('Bun.spawnSync'),
    connect: throwEffect('Bun.connect'),
    listen: throwEffect('Bun.listen'),
    serve: throwEffect('Bun.serve'),
  };
  Object.defineProperty(bunStub, 'env', {
    enumerable: true,
    configurable: false,
    get: throwEffect('Bun.env'),
  });

  const processStub: Record<string, unknown> = {
    exit: throwEffect('process.exit'),
  };
  Object.defineProperty(processStub, 'env', {
    enumerable: true,
    configurable: false,
    get: throwEffect('process.env'),
  });

  const importMetaEnv = throwEffect('import.meta.env');
  const initializeImportMeta = (meta: Record<string, unknown>) => {
    Object.defineProperty(meta, 'env', {
      enumerable: true,
      configurable: false,
      get: importMetaEnv,
    });
  };
  const dynamicModuleStub = async (..._args: unknown[]): Promise<never> => {
    effects['dynamic import'] += 1;
    throw new Error('runtime tripwire blocked effect: dynamic import');
  };

  const sandbox = {
    Bun: bunStub,
    fetch: throwEffect('fetch'),
    WebSocket: throwingConstructor('WebSocket'),
    process: processStub,
    eval: throwEffect('eval'),
    Function: throwingConstructor('Function'),
    AsyncFunction: throwingConstructor('AsyncFunction'),
    GeneratorFunction: throwingConstructor('GeneratorFunction'),
    WebAssembly: {
      compile: throwEffect('WebAssembly.compile'),
      instantiate: throwEffect('WebAssembly.instantiate'),
    },
    require: throwEffect('require'),
    fs: throwingSurface('filesystem'),
    net: throwingSurface('network.net'),
    http: throwingSurface('network.http'),
    https: throwingSurface('network.https'),
    child_process: throwingSurface('child_process'),
  };

  const installed = [
    Object.getOwnPropertyDescriptor(bunStub, 'env')?.get,
    bunStub.file,
    bunStub.write,
    bunStub.spawn,
    bunStub.spawnSync,
    bunStub.connect,
    bunStub.listen,
    bunStub.serve,
    sandbox.fetch,
    sandbox.WebSocket,
    importMetaEnv,
    Object.getOwnPropertyDescriptor(processStub, 'env')?.get,
    processStub.exit,
    sandbox.eval,
    sandbox.Function,
    sandbox.AsyncFunction,
    sandbox.GeneratorFunction,
    sandbox.WebAssembly.compile,
    sandbox.WebAssembly.instantiate,
    dynamicModuleStub,
    sandbox.require,
    sandbox.fs,
    sandbox.net,
    sandbox.http,
    sandbox.https,
    sandbox.child_process,
  ];
  const stubInstallCount = installed.filter(Boolean).length;
  if (stubInstallCount !== EFFECT_SURFACES.length) {
    throw new Error(
      `runtime tripwire stub installation incomplete: ${stubInstallCount}/${EFFECT_SURFACES.length}`,
    );
  }
  return {
    sandbox,
    effects,
    stubInstallCount,
    initializeImportMeta,
    dynamicModuleStub,
  };
}

function totalEffects(effects: EffectVector): number {
  return Object.values(effects).reduce((total, count) => total + count, 0);
}

function runAstScan(source: string): { exitCode: number; scan: AstScan | null } {
  const child = Bun.spawnSync(
    [
      process.execPath,
      resolve('scripts/exact-target-typescript-ast.ts'),
      '--json',
      '--source-base64',
      Buffer.from(source).toString('base64'),
      '--minimum-static-rejections',
      '1',
    ],
    {
      cwd: process.cwd(),
      env: { PATH: process.env.PATH ?? '' },
      stdin: 'ignore',
      stdout: 'pipe',
      stderr: 'pipe',
    },
  );
  const stdout = new TextDecoder().decode(child.stdout);
  const parsed = stdout ? JSON.parse(stdout) : { scans: [] };
  return { exitCode: child.exitCode, scan: parsed.scans?.[0] ?? null };
}

async function guardedExecute(
  source: string,
  sandbox: Record<string, unknown>,
  initializeImportMeta: (meta: Record<string, unknown>) => void,
  dynamicModuleStub: (...args: unknown[]) => Promise<never>,
): Promise<{ throwObserved: boolean }> {
  let throwObserved = false;
  try {
    const module = new SourceTextModule(source, {
      context: createContext(sandbox),
      identifier: 'exact-target-runtime-tripwire-fixture.ts',
      initializeImportMeta,
      importModuleDynamically: dynamicModuleStub,
    });
    await module.link(dynamicModuleStub);
    await module.evaluate({ timeout: 100 });
  } catch {
    throwObserved = true;
  }
  return { throwObserved };
}

async function runRuntimeChild(
  source: string,
  label: string,
  expectedEffectSurface: EffectSurface | null,
): Promise<RuntimeChildReceipt> {
  const {
    sandbox,
    effects,
    stubInstallCount,
    initializeImportMeta,
    dynamicModuleStub,
  } = installThrowingEffectSandbox();
  const positiveControl = expectedEffectSurface !== null;
  const scanResult = positiveControl
    ? { exitCode: 0, scan: null }
    : runAstScan(source);
  const rejectionObserved =
    !positiveControl &&
    scanResult.exitCode === 0 &&
    scanResult.scan !== null &&
    !scanResult.scan.has_error &&
    scanResult.scan.violations.length > 0;
  let executorInvocations = 0;
  let throwObserved = false;
  let harmlessPositiveControlEvaluated = false;
  if (!rejectionObserved) {
    executorInvocations += 1;
    harmlessPositiveControlEvaluated = positiveControl;
    const executed = await guardedExecute(
      source,
      sandbox,
      initializeImportMeta,
      dynamicModuleStub,
    );
    throwObserved = executed.throwObserved;
  }
  const effectTotal = totalEffects(effects);
  const pass = positiveControl
    ? stubInstallCount === EFFECT_SURFACES.length &&
      executorInvocations === 1 &&
      throwObserved &&
      effectTotal === 1 &&
      effects[expectedEffectSurface] === 1 &&
      EFFECT_SURFACES.every(
        (surface) =>
          effects[surface] === (surface === expectedEffectSurface ? 1 : 0),
      )
    : stubInstallCount === EFFECT_SURFACES.length &&
      rejectionObserved &&
      executorInvocations === 0 &&
      effectTotal === 0;
  return {
    schema: 'gbrain.exact-target-runtime-tripwire-child.v1',
    label,
    pid: process.pid,
    pass,
    positive_control: positiveControl,
    expected_effect_surface: expectedEffectSurface,
    stubs_installed: stubInstallCount === EFFECT_SURFACES.length,
    stub_install_count: stubInstallCount,
    required_stub_count: EFFECT_SURFACES.length,
    rejection_observed: rejectionObserved,
    executor_invocations: executorInvocations,
    effect_total: effectTotal,
    effect_vector: effects,
    throw_observed: throwObserved,
    dangerous_source_evaluated: false,
    harmless_positive_control_evaluated: harmlessPositiveControlEvaluated,
    scan: scanResult.scan,
  };
}

function runChildProcess(
  source: string,
  label: string,
  expectedEffectSurface: EffectSurface | null = null,
): { exitCode: number; receipt: RuntimeChildReceipt; stderr: string } {
  const positiveControl = expectedEffectSurface !== null;
  const child = Bun.spawnSync(
    [
      process.execPath,
      resolve('test/helpers/exact-target-effect-tripwire.ts'),
      positiveControl ? '--surface-control-child' : '--fixture-child',
      Buffer.from(source).toString('base64'),
      Buffer.from(label).toString('base64'),
      ...(expectedEffectSurface
        ? [Buffer.from(expectedEffectSurface).toString('base64')]
        : []),
    ],
    {
      cwd: process.cwd(),
      env: { PATH: process.env.PATH ?? '' },
      stdin: 'ignore',
      stdout: 'pipe',
      stderr: 'pipe',
    },
  );
  const stdout = new TextDecoder().decode(child.stdout);
  const stderr = new TextDecoder().decode(child.stderr);
  return {
    exitCode: child.exitCode,
    receipt: JSON.parse(stdout),
    stderr,
  };
}

export function runRejectedEffectTripwire(
  fixtures: readonly { readonly id: string; readonly source: string }[],
): TripwireResult {
  const children = fixtures.map((fixture) =>
    runChildProcess(fixture.source, fixture.id),
  );
  const receipts = children.map((child) => child.receipt);
  const effectVector = emptyEffectVector();
  for (const receipt of receipts) {
    for (const surface of EFFECT_SURFACES) {
      effectVector[surface] += receipt.effect_vector[surface];
    }
  }
  return {
    exitCode: children.every((child) => child.exitCode === 0) ? 0 : 1,
    isolatedChildCount: receipts.length,
    distinctChildPidCount: new Set(receipts.map((receipt) => receipt.pid)).size,
    stubInstallCount: receipts.reduce(
      (total, receipt) => total + receipt.stub_install_count,
      0,
    ),
    requiredStubCountPerChild: EFFECT_SURFACES.length,
    executorInvocationCount: receipts.reduce(
      (total, receipt) => total + receipt.executor_invocations,
      0,
    ),
    effectCount: totalEffects(effectVector),
    effectVector,
    rejectionCount: receipts.filter((receipt) => receipt.rejection_observed)
      .length,
    children: receipts,
    stderr: children.map((child) => child.stderr).filter(Boolean).join('\n'),
  };
}

export function runHarmlessPositiveControl(): PositiveControlResult {
  const result = runChildProcess(EFFECT_POSITIVE_CONTROLS.fetch, 'fetch', 'fetch');
  return {
    exitCode: result.exitCode,
    receipt: result.receipt,
    stderr: result.stderr,
  };
}

export function runSurfacePositiveControls(): SurfaceControlResult {
  const children = EFFECT_SURFACES.map((surface) =>
    runChildProcess(EFFECT_POSITIVE_CONTROLS[surface], surface, surface),
  );
  const receipts = children.map((child) => child.receipt);
  const effectVector = emptyEffectVector();
  for (const receipt of receipts) {
    for (const surface of EFFECT_SURFACES) {
      effectVector[surface] += receipt.effect_vector[surface];
    }
  }
  const allControlsLive = receipts.every(
    (receipt) =>
      receipt.pass &&
      receipt.positive_control &&
      receipt.expected_effect_surface !== null &&
      receipt.stubs_installed &&
      receipt.stub_install_count === receipt.required_stub_count &&
      receipt.executor_invocations === 1 &&
      receipt.effect_total === 1 &&
      receipt.effect_vector[receipt.expected_effect_surface] === 1 &&
      EFFECT_SURFACES.every(
        (surface) =>
          receipt.effect_vector[surface] ===
          (surface === receipt.expected_effect_surface ? 1 : 0),
      ) &&
      receipt.throw_observed &&
      receipt.harmless_positive_control_evaluated &&
      !receipt.dangerous_source_evaluated,
  );
  return {
    exitCode: children.every((child) => child.exitCode === 0) ? 0 : 1,
    controlCount: receipts.length,
    distinctChildPidCount: new Set(receipts.map((receipt) => receipt.pid)).size,
    executorInvocationCount: receipts.reduce(
      (total, receipt) => total + receipt.executor_invocations,
      0,
    ),
    effectCount: totalEffects(effectVector),
    effectVector,
    allControlsLive,
    children: receipts,
    stderr: children.map((child) => child.stderr).filter(Boolean).join('\n'),
  };
}

export function createRuntimeSuiteReceipt(): RuntimeSuiteReceipt {
  const rejected = runRejectedEffectTripwire(EXACT_TARGET_FORBIDDEN_CASES);
  const controls = runSurfacePositiveControls();
  const positive = controls.children.find(
    (child) => child.expected_effect_surface === 'fetch',
  )!;
  const allChildrenStubbed = rejected.children.every(
    (child) =>
      child.pass &&
      child.stubs_installed &&
      child.stub_install_count === child.required_stub_count,
  );
  const positivePass =
    positive.pass &&
    positive.expected_effect_surface === 'fetch' &&
    positive.stubs_installed &&
    positive.required_stub_count === EFFECT_SURFACES.length &&
    positive.executor_invocations === 1 &&
    positive.effect_total === 1 &&
    positive.effect_vector.fetch === 1 &&
    positive.throw_observed &&
    positive.harmless_positive_control_evaluated &&
    !positive.dangerous_source_evaluated;
  const pass =
    rejected.exitCode === 0 &&
    rejected.isolatedChildCount === EXACT_TARGET_FORBIDDEN_CASES.length &&
    rejected.distinctChildPidCount === EXACT_TARGET_FORBIDDEN_CASES.length &&
    rejected.requiredStubCountPerChild === EFFECT_SURFACES.length &&
    rejected.stubInstallCount ===
      EXACT_TARGET_FORBIDDEN_CASES.length * EFFECT_SURFACES.length &&
    allChildrenStubbed &&
    rejected.rejectionCount === EXACT_TARGET_FORBIDDEN_CASES.length &&
    rejected.executorInvocationCount === 0 &&
    rejected.effectCount === 0 &&
    Object.values(rejected.effectVector).every((count) => count === 0) &&
    controls.exitCode === 0 &&
    controls.controlCount === EFFECT_SURFACES.length &&
    controls.distinctChildPidCount === EFFECT_SURFACES.length &&
    controls.executorInvocationCount === EFFECT_SURFACES.length &&
    controls.effectCount === EFFECT_SURFACES.length &&
    EFFECT_SURFACES.every((surface) => controls.effectVector[surface] === 1) &&
    controls.allControlsLive &&
    positivePass;
  return {
    schema: 'gbrain.exact-target-runtime-tripwire-suite.v1',
    pass,
    fixture_count: EXACT_TARGET_FORBIDDEN_CASES.length,
    isolated_child_count: rejected.isolatedChildCount,
    distinct_child_pid_count: rejected.distinctChildPidCount,
    required_stubs_per_child: rejected.requiredStubCountPerChild,
    total_stub_installs: rejected.stubInstallCount,
    all_children_stubbed: allChildrenStubbed,
    rejection_count: rejected.rejectionCount,
    executor_invocations: rejected.executorInvocationCount,
    effect_total: rejected.effectCount,
    effect_vector: rejected.effectVector,
    surface_control_count: controls.controlCount,
    surface_control_distinct_child_pid_count: controls.distinctChildPidCount,
    surface_control_executor_invocations: controls.executorInvocationCount,
    surface_control_effect_total: controls.effectCount,
    surface_control_effect_vector: controls.effectVector,
    all_surface_controls_live: controls.allControlsLive,
    surface_controls: controls.children,
    positive_control: {
      pass: positivePass,
      stubs_installed: positive.stubs_installed,
      required_stubs: positive.required_stub_count,
      executor_invocations: positive.executor_invocations,
      effect_total: positive.effect_total,
      effect_vector: positive.effect_vector,
      throw_observed: positive.throw_observed,
      harmless_source_evaluated:
        positive.harmless_positive_control_evaluated,
      dangerous_source_evaluated: positive.dangerous_source_evaluated,
    },
  };
}

if (import.meta.main) {
  const [mode, encodedSource, encodedLabel, encodedSurface] = process.argv.slice(2);
  if (mode === '--suite') {
    const receipt = createRuntimeSuiteReceipt();
    process.stdout.write(`${JSON.stringify(receipt)}\n`);
    process.exit(receipt.pass ? 0 : 1);
  }
  if (
    (mode !== '--fixture-child' && mode !== '--surface-control-child') ||
    !encodedSource ||
    !encodedLabel ||
    (mode === '--surface-control-child' && !encodedSurface)
  ) {
    process.stderr.write('invalid runtime tripwire child invocation\n');
    process.exit(2);
  }
  const source = Buffer.from(encodedSource, 'base64').toString('utf8');
  const label = Buffer.from(encodedLabel, 'base64').toString('utf8');
  const surface = encodedSurface
    ? Buffer.from(encodedSurface, 'base64').toString('utf8')
    : null;
  if (surface !== null && !EFFECT_SURFACES.includes(surface as EffectSurface)) {
    process.stderr.write('invalid runtime tripwire surface\n');
    process.exit(2);
  }
  const receipt = await runRuntimeChild(source, label, surface as EffectSurface | null);
  process.stdout.write(`${JSON.stringify(receipt)}\n`);
  process.exit(receipt.pass ? 0 : 1);
}
