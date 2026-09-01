import { createHash } from 'node:crypto';
import type { BrainEngine } from '../engine.ts';
import type { Page } from '../types.ts';
import { MinionQueue } from '../minions/queue.ts';
import type { MinionJob } from '../minions/types.ts';
import { assertValidSourceId } from '../source-id.ts';

export const OWNER_TURN_LIFECYCLE_JOB = 'owner-turn-lifecycle';
export const OWNER_TURN_LIFECYCLE_PAYLOAD_VERSION = 1;

export const OWNER_TURN_SOURCE_AGENTS = {
  ezra: 'ezra',
  'marco-sessions': 'marco',
  'valentina-hermes': 'valentina',
} as const;

export interface OwnerTurnLifecycleIdentity {
  sourceId: string;
  slug: string;
  pageContentHash: string;
}

export function ownerTurnPageContentHash(page: Pick<Page, 'compiled_truth'>): string {
  return createHash('sha256').update(page.compiled_truth ?? '').digest('hex');
}

export function assertCanonicalOwnerTurnPage(sourceId: string, page: Page): void {
  const agent = OWNER_TURN_SOURCE_AGENTS[sourceId as keyof typeof OWNER_TURN_SOURCE_AGENTS];
  if (!agent) {
    throw new Error(`owner-turn-lifecycle source is not allowlisted: ${sourceId}`);
  }
  const match = page.slug.match(
    new RegExp(`^daily/hermes/${agent}/([0-9a-f]{20})/([0-9a-f]{20})-([0-9a-f]{12})$`),
  );
  if (!match || page.type !== 'conversation') {
    throw new Error('owner-turn-lifecycle page is not a canonical Hermes conversation');
  }
  const [, sessionRef, turnRef, contentPrefix] = match;
  const fm = page.frontmatter;
  const contentHash = fm.hermes_content_sha256;
  if (
    fm.captured_via !== 'hermes-post-llm' ||
    fm.hermes_agent !== agent ||
    fm.hermes_session_ref !== sessionRef ||
    fm.hermes_turn_ref !== turnRef ||
    typeof contentHash !== 'string' ||
    !/^[0-9a-f]{64}$/.test(contentHash) ||
    !contentHash.startsWith(contentPrefix ?? '')
  ) {
    throw new Error('owner-turn-lifecycle Hermes lineage is invalid');
  }
}

export function ownerTurnLifecycleIdempotencyKey(
  identity: OwnerTurnLifecycleIdentity,
): string {
  const canonical = JSON.stringify([
    OWNER_TURN_LIFECYCLE_JOB,
    OWNER_TURN_LIFECYCLE_PAYLOAD_VERSION,
    identity.sourceId,
    identity.slug,
    identity.pageContentHash,
  ] as const);
  return `${OWNER_TURN_LIFECYCLE_JOB}:v${OWNER_TURN_LIFECYCLE_PAYLOAD_VERSION}:` +
    createHash('sha256').update(canonical).digest('hex');
}

export function parseOwnerTurnLifecycleIdentity(
  data: Record<string, unknown>,
): OwnerTurnLifecycleIdentity {
  if (data.payload_lineage_version !== OWNER_TURN_LIFECYCLE_PAYLOAD_VERSION) {
    throw new Error('owner-turn-lifecycle payload version is invalid');
  }
  if (typeof data.sourceId !== 'string') {
    throw new Error('owner-turn-lifecycle sourceId is missing');
  }
  assertValidSourceId(data.sourceId);
  if (!(data.sourceId in OWNER_TURN_SOURCE_AGENTS)) {
    throw new Error(`owner-turn-lifecycle source is not allowlisted: ${data.sourceId}`);
  }
  if (typeof data.slug !== 'string' || !data.slug || data.slug.trim() !== data.slug) {
    throw new Error('owner-turn-lifecycle slug is invalid');
  }
  if (
    typeof data.pageContentHash !== 'string' ||
    !/^[0-9a-f]{64}$/.test(data.pageContentHash)
  ) {
    throw new Error('owner-turn-lifecycle pageContentHash is invalid');
  }
  return {
    sourceId: data.sourceId,
    slug: data.slug,
    pageContentHash: data.pageContentHash,
  };
}

export async function submitOwnerTurnLifecycle(
  engine: BrainEngine,
  identity: OwnerTurnLifecycleIdentity,
): Promise<MinionJob> {
  parseOwnerTurnLifecycleIdentity({
    payload_lineage_version: OWNER_TURN_LIFECYCLE_PAYLOAD_VERSION,
    ...identity,
  });
  const queue = new MinionQueue(engine);
  return queue.add(
    OWNER_TURN_LIFECYCLE_JOB,
    {
      payload_lineage_version: OWNER_TURN_LIFECYCLE_PAYLOAD_VERSION,
      ...identity,
    },
    {
      queue: 'default',
      idempotency_key: ownerTurnLifecycleIdempotencyKey(identity),
      max_attempts: 3,
      backoff_delay: 60_000,
      timeout_ms: 30 * 60_000,
    },
    { allowProtectedSubmit: true },
  );
}
