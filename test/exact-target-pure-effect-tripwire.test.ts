import { describe, expect, test } from 'bun:test';
import { EXACT_TARGET_FORBIDDEN_CASES } from './fixtures/exact-target-forbidden-effects/cases.ts';
import {
  runRejectedEffectTripwire,
  runSurfacePositiveControls,
} from './helpers/exact-target-effect-tripwire.ts';

describe('exact-target effect tripwire', () => {
  test('rejects all 30 fixtures in isolated fully stubbed children before executor authority', () => {
    const result = runRejectedEffectTripwire(EXACT_TARGET_FORBIDDEN_CASES);

    expect(result.exitCode).toBe(0);
    expect(result.stderr).toBe('');
    expect(result.isolatedChildCount).toBe(30);
    expect(result.distinctChildPidCount).toBe(30);
    expect(result.requiredStubCountPerChild).toBe(26);
    expect(result.stubInstallCount).toBe(
      result.isolatedChildCount * result.requiredStubCountPerChild,
    );
    expect(result.rejectionCount).toBe(30);
    expect(result.executorInvocationCount).toBe(0);
    expect(result.effectCount).toBe(0);
    expect(Object.values(result.effectVector).every((count) => count === 0)).toBe(
      true,
    );
    expect(result.children).toHaveLength(30);

    for (const [index, fixture] of EXACT_TARGET_FORBIDDEN_CASES.entries()) {
      const child = result.children[index];
      expect(child?.label).toBe(fixture.id);
      expect(child?.pid).toBeGreaterThan(0);
      expect(child?.pass).toBe(true);
      expect(child?.positive_control).toBe(false);
      expect(child?.stubs_installed).toBe(true);
      expect(child?.stub_install_count).toBe(child?.required_stub_count);
      expect(child?.rejection_observed).toBe(true);
      expect(child?.executor_invocations).toBe(0);
      expect(child?.effect_total).toBe(0);
      expect(
        Object.values(child?.effect_vector ?? {}).every((count) => count === 0),
      ).toBe(true);
      expect(child?.throw_observed).toBe(false);
      expect(child?.dangerous_source_evaluated).toBe(false);
      expect(child?.harmless_positive_control_evaluated).toBe(false);
      expect(child?.scan?.has_error).toBe(false);
      expect(child?.scan?.violations.length).toBeGreaterThan(0);
    }
  });

  test('26 isolated cause-bound controls prove every stub counter and throw path live', () => {
    const result = runSurfacePositiveControls();
    expect(result.exitCode).toBe(0);
    expect(result.stderr).toBe('');
    expect(result.controlCount).toBe(26);
    expect(result.distinctChildPidCount).toBe(26);
    expect(result.executorInvocationCount).toBe(26);
    expect(result.effectCount).toBe(26);
    expect(Object.values(result.effectVector).every((count) => count === 1)).toBe(
      true,
    );
    expect(result.allControlsLive).toBe(true);
    expect(result.children).toHaveLength(26);
    for (const receipt of result.children) {
      expect(receipt.pass).toBe(true);
      expect(receipt.positive_control).toBe(true);
      expect(receipt.expected_effect_surface).not.toBeNull();
      expect(receipt.stubs_installed).toBe(true);
      expect(receipt.required_stub_count).toBe(26);
      expect(receipt.stub_install_count).toBe(receipt.required_stub_count);
      expect(receipt.rejection_observed).toBe(false);
      expect(receipt.executor_invocations).toBe(1);
      expect(receipt.effect_total).toBe(1);
      expect(receipt.effect_vector[receipt.expected_effect_surface!]).toBe(1);
      expect(
        Object.entries(receipt.effect_vector)
          .filter(([surface]) => surface !== receipt.expected_effect_surface)
          .every(([, count]) => count === 0),
      ).toBe(true);
      expect(receipt.throw_observed).toBe(true);
      expect(receipt.dangerous_source_evaluated).toBe(false);
      expect(receipt.harmless_positive_control_evaluated).toBe(true);
    }
  });
});
