import type { BrainEngine } from '../../engine.ts';
import { runCycle, type PhaseResult } from '../../cycle.ts';
import {
  assertCanonicalOwnerTurnPage,
  ownerTurnPageContentHash,
  parseOwnerTurnLifecycleIdentity,
} from '../../cycle/owner-turn-lifecycle.ts';
import { UnrecoverableError, type MinionHandler } from '../types.ts';

const PHASES = [
  'extract_atoms',
  'propose_takes',
] as const;

export function isOwnerTurnPhaseComplete(result: PhaseResult): boolean {
  return result.status === 'ok' || (
    result.phase === 'extract_atoms' &&
    result.status === 'skipped' &&
    result.details.reason === 'no_work'
  );
}

export function makeOwnerTurnLifecycleHandler(engine: BrainEngine): MinionHandler {
  return async (job) => {
    let identity: ReturnType<typeof parseOwnerTurnLifecycleIdentity>;
    try {
      identity = parseOwnerTurnLifecycleIdentity(job.data);
    } catch (error) {
      throw new UnrecoverableError(error instanceof Error ? error.message : String(error));
    }

    const page = await engine.getPage(identity.slug, { sourceId: identity.sourceId });
    if (!page) {
      return { status: 'skipped', reason: 'page_missing', source_id: identity.sourceId };
    }
    try {
      assertCanonicalOwnerTurnPage(identity.sourceId, page);
    } catch (error) {
      throw new UnrecoverableError(error instanceof Error ? error.message : String(error));
    }
    if (ownerTurnPageContentHash(page) !== identity.pageContentHash) {
      return { status: 'skipped', reason: 'page_superseded', source_id: identity.sourceId };
    }

    const configuredChatModel = await engine.getConfig('models.chat');
    if (!configuredChatModel) {
      throw new UnrecoverableError('owner-turn-lifecycle models.chat is unavailable');
    }
    const report = await runCycle(engine, {
      brainDir: null,
      pull: false,
      sourceId: identity.sourceId,
      phases: [...PHASES],
      targetSlugs: [identity.slug],
      forcePhaseGates: [...PHASES],
      extractAtomsModel: configuredChatModel,
      proposeTakesModel: configuredChatModel,
      signal: job.signal,
      deadlineAtMs: job.deadlineAtMs,
      privateQueueOwnerJobId: job.id,
      yieldBetweenPhases: async () => {
        await new Promise<void>((resolve) => setImmediate(resolve));
      },
    });
    const results = new Map(report.phases.map((phase) => [phase.phase, phase]));
    const incomplete = PHASES.filter((phase) => {
      const result = results.get(phase);
      return !result || !isOwnerTurnPhaseComplete(result);
    });
    if (incomplete.length > 0) {
      throw new Error(
        `owner-turn-lifecycle incomplete phases: ${incomplete
          .map((phase) => `${phase}=${results.get(phase)?.status ?? 'missing'}`)
          .join(',')}`,
      );
    }
    return {
      status: 'ok',
      source_id: identity.sourceId,
      phases: [...PHASES],
      report,
    };
  };
}
