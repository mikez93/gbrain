export interface ExactTargetForbiddenCase {
  readonly id: string;
  readonly source: string;
}

/** One fixture for each accepted Order-0 static/runtime effect class. */
export const EXACT_TARGET_FORBIDDEN_CASES: readonly ExactTargetForbiddenCase[] = [
  { id: 'bun-env', source: 'const value = Bun.env;' },
  { id: 'bun-file', source: 'const value = Bun.file("x");' },
  { id: 'bun-write', source: 'Bun.write("x", "y");' },
  { id: 'bun-spawn', source: 'Bun.spawn(["true"]);' },
  { id: 'bun-spawn-sync', source: 'Bun.spawnSync(["true"]);' },
  { id: 'bun-connect', source: 'Bun.connect({ hostname: "x", port: 1, socket: {} });' },
  { id: 'bun-listen', source: 'Bun.listen({ hostname: "x", port: 1, socket: {} });' },
  { id: 'bun-serve', source: 'Bun.serve({ fetch() { return new Response(); } });' },
  { id: 'fetch', source: 'fetch("https://example.invalid");' },
  { id: 'global-fetch', source: 'globalThis.fetch("https://example.invalid");' },
  { id: 'websocket', source: 'new WebSocket("wss://example.invalid");' },
  { id: 'global-websocket', source: 'new globalThis.WebSocket("wss://example.invalid");' },
  { id: 'import-meta-env', source: 'const value = import.meta.env;' },
  { id: 'process-env-single', source: "const value = process['env'];" },
  { id: 'process-env-template', source: 'const value = process[`env`];' },
  { id: 'global-process-computed', source: 'const value = globalThis["process"]["env"];' },
  { id: 'bun-computed-file', source: 'Bun["file"]("x");' },
  { id: 'global-computed-fetch', source: 'globalThis["fetch"]("https://example.invalid");' },
  { id: 'eval', source: 'eval("1");' },
  { id: 'global-eval', source: 'globalThis.eval("1");' },
  { id: 'function', source: 'Function("return 1")();' },
  { id: 'global-function', source: 'new globalThis.Function("return 1");' },
  { id: 'async-function', source: 'new AsyncFunction("return 1");' },
  { id: 'generator-function', source: 'new GeneratorFunction("yield 1");' },
  { id: 'wasm-compile', source: 'WebAssembly.compile(new Uint8Array());' },
  { id: 'wasm-instantiate', source: 'WebAssembly.instantiate(new Uint8Array());' },
  { id: 'dynamic-data-import', source: 'import("data:text/javascript,export default 1");' },
  { id: 'dynamic-blob-import', source: 'import("blob:https://example.invalid/id");' },
  { id: 'aliased-global', source: 'const runtime = Bun; runtime.file("x");' },
  { id: 'optional-member', source: 'Bun?.file?.("x");' },
] as const;
