import { describe, expect, test } from 'bun:test';
import { EXACT_TARGET_FORBIDDEN_CASES } from './fixtures/exact-target-forbidden-effects/cases.ts';
import { runRejectedEffectTripwire } from './helpers/exact-target-effect-tripwire.ts';

describe('exact-target effect tripwire', () => {
  test('rejects all 30 evasive fixtures before any effect', () => {
    const result = runRejectedEffectTripwire(
      EXACT_TARGET_FORBIDDEN_CASES.map((fixture) => fixture.source),
    );
    expect(result.exitCode).toBe(0);
    expect(result.effectCount).toBe(0);
    expect(result.scans).toHaveLength(30);
    for (const [index, fixture] of EXACT_TARGET_FORBIDDEN_CASES.entries()) {
      const scan = result.scans[index];
      expect(scan?.has_error).toBe(false);
      expect(scan?.violations.length).toBeGreaterThan(0);
      expect(fixture.id.length).toBeGreaterThan(0);
    }
  });
});
