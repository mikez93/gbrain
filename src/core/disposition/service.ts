import type { BrainEngine } from '../engine.ts';
import {
  asIso,
  assertActor,
  deterministicDuplicateSetId,
  DispositionError,
  newOpaqueUuid,
  normalizeDuplicateSetId,
  normalizeIdempotencyKey,
  normalizeMetadata,
  normalizeReason,
  requestHash,
  type DispositionActor,
  type DispositionEventReceipt,
  type DispositionOperationKind,
  type DispositionProjection,
  type DispositionReceipt,
  type DispositionResultingState,
  type DispositionState,
} from './model.ts';

interface PageRow {
  id: number;
  source_id: string;
  slug: string;
  deleted_at: unknown;
}

interface ProjectionRow {
  page_id: number;
  state: DispositionState;
  duplicate_set_id: string | null;
  canonical_page_id: number | null;
  last_event_id: number;
}

interface EventRow {
  id: number;
  page_id: number;
  event_kind: 'set' | 'reverse';
  resulting_state: DispositionResultingState;
  duplicate_set_id: string | null;
  canonical_page_id: number | null;
}

function normalizeEventRow(row: EventRow): EventRow {
  return {
    ...row,
    id: Number(row.id),
    page_id: Number(row.page_id),
    canonical_page_id: row.canonical_page_id == null ? null : Number(row.canonical_page_id),
  };
}

interface BaseWriteInput {
  actor: DispositionActor;
  reason: string;
  idempotencyKey: string;
  metadata?: Record<string, unknown>;
}

export interface SetPageDispositionInput extends BaseWriteInput {
  sourceId: string;
  slug: string;
  state: DispositionState;
  duplicateSetId?: string;
  canonical?: { sourceId: string; slug: string };
}

export interface SetDuplicateSetInput extends BaseWriteInput {
  sourceId: string;
  canonicalSlug: string;
  supersededSlugs?: readonly string[];
  superseded?: ReadonlyArray<{ sourceId: string; slug: string }>;
  duplicateSetId?: string;
}

export interface ReversePageDispositionInput extends BaseWriteInput {
  sourceId: string;
  slug: string;
  eventId: number;
}

export interface ReverseDuplicateSetInput extends BaseWriteInput {
  operationUuid: string;
}

export type DispositionBatchItem =
  | {
    kind: 'duplicate_set';
    sourceId: string;
    canonicalSlug: string;
    supersededSlugs?: readonly string[];
    superseded?: ReadonlyArray<{ sourceId: string; slug: string }>;
    duplicateSetId?: string;
  }
  | {
    kind: 'page';
    sourceId: string;
    slug: string;
    state: DispositionState;
    duplicateSetId?: string;
    canonical?: { sourceId: string; slug: string };
  };

export interface SetDispositionBatchInput extends BaseWriteInput {
  items: readonly DispositionBatchItem[];
}

export interface ReverseDispositionBatchInput extends BaseWriteInput {
  operationUuid: string;
}

const MAX_BATCH_ITEMS = 200;
const MAX_BATCH_PAGES = 500;

interface OperationRow {
  id: number;
  operation_uuid: string;
  request_hash: string;
  kind: DispositionOperationKind;
  actor: DispositionActor;
  reason: string;
  metadata: Record<string, unknown> | string;
}

function validateWriteBase(input: BaseWriteInput) {
  assertActor(input.actor);
  return {
    actor: input.actor,
    reason: normalizeReason(input.reason),
    idempotencyKey: normalizeIdempotencyKey(input.idempotencyKey),
    metadata: normalizeMetadata(input.metadata),
  };
}

async function resolvePagesForUpdate(
  engine: BrainEngine,
  refs: Array<{ sourceId: string; slug: string }>,
): Promise<PageRow[]> {
  const sourceIds = refs.map(ref => ref.sourceId);
  const slugs = refs.map(ref => ref.slug);
  const rows = await engine.executeRaw<PageRow>(
    `SELECT p.id, p.source_id, p.slug, p.deleted_at
     FROM pages p
     JOIN unnest($1::text[], $2::text[]) AS wanted(source_id, slug)
       ON wanted.source_id = p.source_id AND wanted.slug = p.slug
     WHERE p.deleted_at IS NULL
     ORDER BY p.id
     FOR UPDATE`,
    [sourceIds, slugs],
  );
  const byKey = new Map(rows.map(row => [`${row.source_id}\u0000${row.slug}`, row]));
  const ordered: PageRow[] = [];
  for (const ref of refs) {
    const row = byKey.get(`${ref.sourceId}\u0000${ref.slug}`);
    if (!row) {
      throw new DispositionError('page_not_found', `Live page not found: ${ref.sourceId}:${ref.slug}`);
    }
    ordered.push(row);
  }
  return ordered;
}

async function insertOperationOrReplay(
  engine: BrainEngine,
  input: {
    kind: DispositionOperationKind;
    actor: DispositionActor;
    reason: string;
    idempotencyKey: string;
    requestHash: string;
    metadata: Record<string, unknown>;
  },
): Promise<{ operation: OperationRow; replay: boolean }> {
  const inserted = await engine.executeRaw<OperationRow>(
    `INSERT INTO page_disposition_operations
       (operation_uuid, idempotency_key, request_hash, kind, actor, reason, metadata)
     VALUES ($1::uuid, $2, $3, $4, $5, $6, $7::text::jsonb)
     ON CONFLICT (idempotency_key) DO NOTHING
     RETURNING id, operation_uuid, request_hash, kind, actor, reason, metadata`,
    [newOpaqueUuid(), input.idempotencyKey, input.requestHash, input.kind, input.actor, input.reason, JSON.stringify(input.metadata)],
  );
  if (inserted[0]) return { operation: inserted[0], replay: false };

  const existing = await engine.executeRaw<OperationRow>(
    `SELECT id, operation_uuid, request_hash, kind, actor, reason, metadata
     FROM page_disposition_operations WHERE idempotency_key = $1`,
    [input.idempotencyKey],
  );
  const operation = existing[0];
  if (!operation) throw new DispositionError('database_error', 'Idempotency record disappeared during retry.');
  if (operation.request_hash !== input.requestHash || operation.kind !== input.kind) {
    throw new DispositionError('idempotency_conflict', 'The idempotency key was already used for a different disposition request.');
  }
  return { operation, replay: true };
}

async function appendEvent(
  engine: BrainEngine,
  input: {
    operationId: number;
    pageId: number;
    eventKind: 'set' | 'reverse';
    state: DispositionResultingState;
    duplicateSetId: string | null;
    canonicalPageId: number | null;
    reversesEventId?: number | null;
  },
): Promise<number> {
  const rows = await engine.executeRaw<{ id: number }>(
    `INSERT INTO page_disposition_events
       (event_uuid, operation_id, page_id, event_kind, resulting_state,
        duplicate_set_id, canonical_page_id, reverses_event_id)
     VALUES ($1::uuid, $2, $3, $4, $5, $6::uuid, $7, $8)
     RETURNING id`,
    [
      newOpaqueUuid(), input.operationId, input.pageId, input.eventKind, input.state,
      input.duplicateSetId, input.canonicalPageId, input.reversesEventId ?? null,
    ],
  );
  return Number(rows[0]!.id);
}

async function applyProjection(
  engine: BrainEngine,
  input: {
    pageId: number;
    state: DispositionResultingState;
    duplicateSetId: string | null;
    canonicalPageId: number | null;
    eventId: number;
    actor: DispositionActor;
    reason: string;
  },
): Promise<void> {
  if (input.state === 'undispositioned') {
    await engine.executeRaw(`DELETE FROM page_dispositions WHERE page_id = $1`, [input.pageId]);
    return;
  }
  await engine.executeRaw(
    `INSERT INTO page_dispositions
       (page_id, state, duplicate_set_id, canonical_page_id, last_event_id, reason, actor, updated_at)
     VALUES ($1, $2, $3::uuid, $4, $5, $6, $7, now())
     ON CONFLICT (page_id) DO UPDATE SET
       state = EXCLUDED.state,
       duplicate_set_id = EXCLUDED.duplicate_set_id,
       canonical_page_id = EXCLUDED.canonical_page_id,
       last_event_id = EXCLUDED.last_event_id,
       reason = EXCLUDED.reason,
       actor = EXCLUDED.actor,
       updated_at = now()`,
    [input.pageId, input.state, input.duplicateSetId, input.canonicalPageId, input.eventId, input.reason, input.actor],
  );
}

async function incrementGeneration(engine: BrainEngine): Promise<number> {
  const rows = await engine.executeRaw<{ generation: number }>(
    `UPDATE page_disposition_state
     SET generation = generation + 1
     WHERE id = 1
     RETURNING generation`,
  );
  return Number(rows[0]!.generation);
}

async function assertProjectionInvariant(engine: BrainEngine): Promise<void> {
  const rows = await engine.executeRaw<{ n: number }>(
    `SELECT COUNT(*)::int AS n
     FROM page_dispositions d
     JOIN pages p ON p.id = d.page_id
     LEFT JOIN page_dispositions c
       ON c.page_id = d.canonical_page_id
      AND c.state = 'canonical'
      AND c.duplicate_set_id = d.duplicate_set_id
     LEFT JOIN pages cp ON cp.id = c.page_id
     WHERE d.state = 'superseded'
       AND (c.page_id IS NULL OR cp.deleted_at IS NOT NULL)`,
  );
  if (Number(rows[0]?.n ?? 0) !== 0) {
    throw new DispositionError('disposition_invariant_failed', 'A superseded page lacks a live canonical in this brain.');
  }
}

function parseMetadata(value: OperationRow['metadata']): Record<string, unknown> {
  if (typeof value !== 'string') return value ?? {};
  try { return JSON.parse(value) as Record<string, unknown>; } catch { return {}; }
}

async function buildReceipt(
  engine: BrainEngine,
  operation: OperationRow,
  replay: boolean,
): Promise<DispositionReceipt> {
  const eventRows = await engine.executeRaw<Record<string, unknown>>(
    `SELECT e.id AS event_id, e.event_uuid, e.page_id, p.source_id, p.slug,
            e.event_kind, e.resulting_state, e.duplicate_set_id,
            e.canonical_page_id, cp.source_id AS canonical_source_id,
            cp.slug AS canonical_slug, e.reverses_event_id, e.created_at
     FROM page_disposition_events e
     JOIN pages p ON p.id = e.page_id
     LEFT JOIN pages cp ON cp.id = e.canonical_page_id
     WHERE e.operation_id = $1
     ORDER BY e.id`,
    [operation.id],
  );
  const events: DispositionEventReceipt[] = eventRows.map(row => ({
    event_id: Number(row.event_id),
    event_uuid: String(row.event_uuid),
    page_id: Number(row.page_id),
    source_id: String(row.source_id),
    slug: String(row.slug),
    event_kind: row.event_kind as 'set' | 'reverse',
    resulting_state: row.resulting_state as DispositionResultingState,
    duplicate_set_id: row.duplicate_set_id == null ? null : String(row.duplicate_set_id),
    canonical: row.canonical_page_id == null ? null : {
      page_id: Number(row.canonical_page_id),
      source_id: String(row.canonical_source_id),
      slug: String(row.canonical_slug),
    },
    reverses_event_id: row.reverses_event_id == null ? null : Number(row.reverses_event_id),
    created_at: asIso(row.created_at),
  }));
  const pageIds = Array.from(new Set(events.map(event => event.page_id)));
  const projections = pageIds.length > 0
    ? await loadProjections(engine, pageIds)
    : [];
  const generationRows = await engine.executeRaw<{ generation: number }>(
    `SELECT generation FROM page_disposition_state WHERE id = 1`,
  );
  const metadata = parseMetadata(operation.metadata);
  return {
    operation_id: Number(operation.id),
    operation_uuid: String(operation.operation_uuid),
    kind: operation.kind,
    actor: operation.actor,
    reason: operation.reason,
    idempotent_replay: replay,
    noop: metadata.noop === true,
    generation: Number(generationRows[0]?.generation ?? 0),
    events,
    projections,
    affected_pages: events.map(event => ({ page_id: event.page_id, source_id: event.source_id, slug: event.slug })),
  };
}

async function loadProjections(engine: BrainEngine, pageIds: number[]): Promise<DispositionProjection[]> {
  if (pageIds.length === 0) return [];
  const rows = await engine.executeRaw<Record<string, unknown>>(
    `SELECT d.page_id, p.source_id, p.slug, d.state, d.duplicate_set_id,
            d.canonical_page_id, cp.source_id AS canonical_source_id,
            cp.slug AS canonical_slug, d.last_event_id, d.reason, d.actor, d.updated_at
     FROM page_dispositions d
     JOIN pages p ON p.id = d.page_id
     LEFT JOIN pages cp ON cp.id = d.canonical_page_id
     WHERE d.page_id = ANY($1::int[])
     ORDER BY d.page_id`,
    [pageIds],
  );
  return rows.map(row => ({
    page_id: Number(row.page_id),
    source_id: String(row.source_id),
    slug: String(row.slug),
    state: row.state as DispositionState,
    duplicate_set_id: row.duplicate_set_id == null ? null : String(row.duplicate_set_id),
    canonical: row.canonical_page_id == null ? null : {
      page_id: Number(row.canonical_page_id),
      source_id: String(row.canonical_source_id),
      slug: String(row.canonical_slug),
    },
    last_event_id: Number(row.last_event_id),
    reason: String(row.reason),
    actor: row.actor as DispositionActor,
    updated_at: asIso(row.updated_at),
  }));
}

async function currentProjection(engine: BrainEngine, pageId: number): Promise<ProjectionRow | null> {
  const rows = await engine.executeRaw<ProjectionRow>(
    `SELECT page_id, state, duplicate_set_id, canonical_page_id, last_event_id
     FROM page_dispositions WHERE page_id = $1`,
    [pageId],
  );
  return rows[0] ?? null;
}

async function previousState(engine: BrainEngine, event: EventRow): Promise<{
  state: DispositionResultingState;
  duplicateSetId: string | null;
  canonicalPageId: number | null;
}> {
  const rows = await engine.executeRaw<EventRow>(
    `SELECT id, page_id, event_kind, resulting_state, duplicate_set_id, canonical_page_id
     FROM page_disposition_events
     WHERE page_id = $1 AND id < $2
     ORDER BY id DESC LIMIT 1`,
    [event.page_id, event.id],
  );
  const prior = rows[0];
  return prior
    ? { state: prior.resulting_state, duplicateSetId: prior.duplicate_set_id, canonicalPageId: prior.canonical_page_id }
    : { state: 'undispositioned', duplicateSetId: null, canonicalPageId: null };
}

function mapConstraintError(err: unknown): never {
  const message = err instanceof Error ? err.message : String(err);
  if (/page_dispositions_one_canonical_per_set|duplicate key.*duplicate_set/i.test(message)) {
    throw new DispositionError('canonical_conflict', 'The duplicate set already has an active canonical.');
  }
  throw err;
}

export async function setDuplicateSet(engine: BrainEngine, input: SetDuplicateSetInput): Promise<DispositionReceipt> {
  const base = validateWriteBase(input);
  const duplicateSetId = normalizeDuplicateSetId(input.duplicateSetId)
    ?? deterministicDuplicateSetId(base.idempotencyKey);
  const supersededRefs = input.superseded
    ?? (input.supersededSlugs ?? []).map(slug => ({ sourceId: input.sourceId, slug }));
  if (supersededRefs.length < 1) {
    throw new DispositionError('invalid_params', 'set_duplicate_set requires at least one superseded page.');
  }
  const refs = [{ sourceId: input.sourceId, slug: input.canonicalSlug }, ...supersededRefs];
  const keys = refs.map(ref => `${ref.sourceId}\u0000${ref.slug}`);
  if (new Set(keys).size !== keys.length) {
    throw new DispositionError('invalid_params', 'Canonical and superseded page members must be distinct.');
  }

  try {
    return await engine.transaction(async tx => {
      const pages = await resolvePagesForUpdate(tx, refs);
      const canonical = pages[0]!;
      const requestedIds = new Set(pages.map(page => page.id));
      const existingSet = await tx.executeRaw<{ page_id: number }>(
        `SELECT page_id FROM page_dispositions WHERE duplicate_set_id = $1::uuid FOR UPDATE`,
        [duplicateSetId],
      );
      if (existingSet.some(row => !requestedIds.has(Number(row.page_id)))) {
        throw new DispositionError('partial_duplicate_set', 'Atomic duplicate-set replacement must include every active member.');
      }
      const existingMembers = await tx.executeRaw<ProjectionRow>(
        `SELECT page_id, state, duplicate_set_id, canonical_page_id, last_event_id
         FROM page_dispositions WHERE page_id = ANY($1::int[]) FOR UPDATE`,
        [pages.map(page => page.id)],
      );
      if (existingMembers.some(row => row.duplicate_set_id && row.duplicate_set_id !== duplicateSetId)) {
        throw new DispositionError('projection_conflict', 'A requested page belongs to another active duplicate set.');
      }

      const normalized = {
        kind: 'set_duplicate_set', actor: base.actor, reason: base.reason,
        duplicate_set_id: duplicateSetId,
        canonical_page_id: canonical.id,
        superseded_page_ids: pages.slice(1).map(page => page.id).sort((a, b) => a - b),
        metadata: base.metadata,
      };
      const op = await insertOperationOrReplay(tx, {
        kind: 'set_duplicate_set', ...base, requestHash: requestHash(normalized),
      });
      if (op.replay) return buildReceipt(tx, op.operation, true);

      const staged: Array<{ page: PageRow; state: DispositionState; eventId: number; canonicalPageId: number }> = [];
      for (const [index, page] of pages.entries()) {
        const state: DispositionState = index === 0 ? 'canonical' : 'superseded';
        const eventId = await appendEvent(tx, {
          operationId: op.operation.id,
          pageId: page.id,
          eventKind: 'set',
          state,
          duplicateSetId,
          canonicalPageId: canonical.id,
        });
        staged.push({ page, state, eventId, canonicalPageId: canonical.id });
      }
      for (const item of staged.filter(item => item.state !== 'canonical')) {
        await applyProjection(tx, {
          pageId: item.page.id, state: item.state, duplicateSetId,
          canonicalPageId: canonical.id, eventId: item.eventId, actor: base.actor, reason: base.reason,
        });
      }
      for (const item of staged.filter(item => item.state === 'canonical')) {
        await applyProjection(tx, {
          pageId: item.page.id, state: item.state, duplicateSetId,
          canonicalPageId: canonical.id, eventId: item.eventId, actor: base.actor, reason: base.reason,
        });
      }
      await incrementGeneration(tx);
      await assertProjectionInvariant(tx);
      return buildReceipt(tx, op.operation, false);
    });
  } catch (err) {
    mapConstraintError(err);
  }
}

export async function setPageDisposition(engine: BrainEngine, input: SetPageDispositionInput): Promise<DispositionReceipt> {
  const base = validateWriteBase(input);
  const duplicateSetId = normalizeDuplicateSetId(input.duplicateSetId) ?? null;
  if ((input.state === 'canonical' || input.state === 'superseded') && !duplicateSetId) {
    throw new DispositionError('invalid_params', 'canonical and superseded states require duplicate_set_id.');
  }
  if (input.state === 'superseded' && !input.canonical) {
    throw new DispositionError('invalid_params', 'superseded state requires a canonical page reference.');
  }
  try {
    return await engine.transaction(async tx => {
      const refs = [{ sourceId: input.sourceId, slug: input.slug }];
      if (input.canonical) refs.push(input.canonical);
      const pages = await resolvePagesForUpdate(tx, refs);
      const page = pages[0]!;
      const canonicalPage = input.state === 'canonical' ? page : pages[1] ?? null;
      const projection = await currentProjection(tx, page.id);
      const desiredCanonicalId = canonicalPage?.id ?? null;
      const same = projection?.state === input.state
        && projection.duplicate_set_id === duplicateSetId
        && projection.canonical_page_id === desiredCanonicalId;
      if (projection && !same) {
        throw new DispositionError('projection_conflict', 'Page already has a conflicting active disposition.');
      }
      if (input.state === 'canonical') {
        const dependents = await tx.executeRaw<{ page_id: number; state: string }>(
          `SELECT page_id, state FROM page_dispositions
           WHERE duplicate_set_id = $1::uuid AND page_id <> $2 FOR UPDATE`,
          [duplicateSetId, page.id],
        );
        if (dependents.length > 0) {
          throw new DispositionError('partial_duplicate_set', 'Use set_duplicate_set to establish or replace a canonical with active members.');
        }
      }
      if (input.state === 'superseded') {
        const target = await currentProjection(tx, canonicalPage!.id);
        if (target?.state !== 'canonical' || target.duplicate_set_id !== duplicateSetId) {
          throw new DispositionError('canonical_not_active', 'Superseded state requires the active canonical in the same duplicate set.');
        }
      }

      const normalized = {
        kind: 'set_page', actor: base.actor, reason: base.reason,
        page_id: page.id, state: input.state, duplicate_set_id: duplicateSetId,
        canonical_page_id: desiredCanonicalId, metadata: base.metadata,
      };
      const operationMetadata = same ? { ...base.metadata, noop: true } : base.metadata;
      const op = await insertOperationOrReplay(tx, {
        kind: 'set_page', ...base, metadata: operationMetadata, requestHash: requestHash(normalized),
      });
      if (op.replay || same) return buildReceipt(tx, op.operation, op.replay);

      const eventId = await appendEvent(tx, {
        operationId: op.operation.id, pageId: page.id, eventKind: 'set', state: input.state,
        duplicateSetId, canonicalPageId: desiredCanonicalId,
      });
      await applyProjection(tx, {
        pageId: page.id, state: input.state, duplicateSetId, canonicalPageId: desiredCanonicalId,
        eventId, actor: base.actor, reason: base.reason,
      });
      await incrementGeneration(tx);
      await assertProjectionInvariant(tx);
      return buildReceipt(tx, op.operation, false);
    });
  } catch (err) {
    mapConstraintError(err);
  }
}

interface BatchDesiredPage {
  page: PageRow;
  state: DispositionState;
  duplicateSetId: string | null;
  canonicalPageId: number | null;
  itemIndex: number;
  itemKind: DispositionBatchItem['kind'];
}

interface NormalizedDuplicateSetBatchItem {
  kind: 'duplicate_set';
  itemIndex: number;
  duplicateSetId: string;
  refs: Array<{ sourceId: string; slug: string }>;
}

interface NormalizedPageBatchItem {
  kind: 'page';
  itemIndex: number;
  sourceId: string;
  slug: string;
  state: DispositionState;
  duplicateSetId: string | null;
  canonical: { sourceId: string; slug: string } | undefined;
}

type NormalizedBatchItem = NormalizedDuplicateSetBatchItem | NormalizedPageBatchItem;

/** Apply a bounded owner-curation batch in one transaction and one durable operation receipt. */
export async function setDispositionBatch(
  engine: BrainEngine,
  input: SetDispositionBatchInput,
): Promise<DispositionReceipt> {
  const base = validateWriteBase(input);
  if (!Array.isArray(input.items) || input.items.length < 1 || input.items.length > MAX_BATCH_ITEMS) {
    throw new DispositionError('invalid_params', `items must contain 1 to ${MAX_BATCH_ITEMS} disposition groups.`);
  }

  const normalizedItems: NormalizedBatchItem[] = input.items.map((item, itemIndex) => {
    if (item.kind === 'duplicate_set') {
      const superseded: ReadonlyArray<{ sourceId: string; slug: string }> = item.superseded
        ?? (item.supersededSlugs ?? []).map((slug: string) => ({ sourceId: item.sourceId, slug }));
      if (superseded.length < 1) {
        throw new DispositionError('invalid_params', 'Each duplicate_set item requires at least one superseded page.');
      }
      const refs = [{ sourceId: item.sourceId, slug: item.canonicalSlug }, ...superseded];
      const keys = refs.map(ref => `${ref.sourceId}\u0000${ref.slug}`);
      if (new Set(keys).size !== keys.length) {
        throw new DispositionError('invalid_params', 'Canonical and superseded page members must be distinct.');
      }
      return {
        kind: item.kind,
        itemIndex,
        duplicateSetId: normalizeDuplicateSetId(item.duplicateSetId)
          ?? deterministicDuplicateSetId(`${base.idempotencyKey}:${itemIndex}`),
        refs,
      };
    }

    let duplicateSetId: string | null = null;
    let canonical = item.canonical;
    if (item.state === 'canonical') {
      duplicateSetId = normalizeDuplicateSetId(item.duplicateSetId)
        ?? deterministicDuplicateSetId(`${base.idempotencyKey}:${itemIndex}`);
      canonical = { sourceId: item.sourceId, slug: item.slug };
    } else if (item.state === 'superseded') {
      duplicateSetId = normalizeDuplicateSetId(item.duplicateSetId) ?? null;
      if (!duplicateSetId || !canonical) {
        throw new DispositionError('invalid_params', 'A superseded page requires duplicate_set_id and canonical.');
      }
    } else if (item.duplicateSetId || canonical) {
      throw new DispositionError('invalid_params', 'A quarantined page cannot name a duplicate set or canonical.');
    }
    return {
      kind: item.kind,
      itemIndex,
      sourceId: item.sourceId,
      slug: item.slug,
      state: item.state,
      duplicateSetId,
      canonical,
    };
  });

  const targetRefs: Array<{ sourceId: string; slug: string }> = [];
  const referenceRefs: Array<{ sourceId: string; slug: string }> = [];
  const duplicateSetIds = new Set<string>();
  for (const item of normalizedItems) {
    if (item.kind === 'duplicate_set') {
      if (duplicateSetIds.has(item.duplicateSetId)) {
        throw new DispositionError('invalid_params', 'A duplicate_set_id may appear in only one batch item.');
      }
      duplicateSetIds.add(item.duplicateSetId);
      targetRefs.push(...item.refs);
    } else {
      targetRefs.push({ sourceId: item.sourceId, slug: item.slug });
      if (item.duplicateSetId) {
        if (duplicateSetIds.has(item.duplicateSetId)) {
          throw new DispositionError('invalid_params', 'A duplicate_set_id may appear in only one batch item.');
        }
        duplicateSetIds.add(item.duplicateSetId);
      }
      if (item.canonical) referenceRefs.push(item.canonical);
    }
  }
  const targetKeys = targetRefs.map(ref => `${ref.sourceId}\u0000${ref.slug}`);
  if (new Set(targetKeys).size !== targetKeys.length) {
    throw new DispositionError('invalid_params', 'A page may be dispositioned only once per batch.');
  }
  if (targetRefs.length > MAX_BATCH_PAGES) {
    throw new DispositionError('invalid_params', `A batch may disposition at most ${MAX_BATCH_PAGES} pages.`);
  }

  try {
    return await engine.transaction(async tx => {
      const uniqueRefs = Array.from(
        new Map([...targetRefs, ...referenceRefs].map(ref => [`${ref.sourceId}\u0000${ref.slug}`, ref])).values(),
      );
      const pages = await resolvePagesForUpdate(tx, uniqueRefs);
      const pageByKey = new Map(pages.map(page => [`${page.source_id}\u0000${page.slug}`, page]));
      const desired: BatchDesiredPage[] = [];

      for (const item of normalizedItems) {
        if (item.kind === 'duplicate_set') {
          const members = item.refs.map(ref => pageByKey.get(`${ref.sourceId}\u0000${ref.slug}`)!);
          const canonical = members[0]!;
          const requestedIds = new Set(members.map(page => page.id));
          const existingSet = await tx.executeRaw<{ page_id: number }>(
            `SELECT page_id FROM page_dispositions WHERE duplicate_set_id = $1::uuid FOR UPDATE`,
            [item.duplicateSetId],
          );
          if (existingSet.some(row => !requestedIds.has(Number(row.page_id)))) {
            throw new DispositionError('partial_duplicate_set', 'Atomic batch replacement must include every active duplicate-set member.');
          }
          members.forEach((page, memberIndex) => desired.push({
            page,
            state: memberIndex === 0 ? 'canonical' : 'superseded',
            duplicateSetId: item.duplicateSetId,
            canonicalPageId: canonical.id,
            itemIndex: item.itemIndex,
            itemKind: item.kind,
          }));
          continue;
        }

        const page = pageByKey.get(`${item.sourceId}\u0000${item.slug}`)!;
        const canonicalPage = item.canonical
          ? pageByKey.get(`${item.canonical.sourceId}\u0000${item.canonical.slug}`)!
          : null;
        desired.push({
          page,
          state: item.state,
          duplicateSetId: item.duplicateSetId,
          canonicalPageId: canonicalPage?.id ?? null,
          itemIndex: item.itemIndex,
          itemKind: item.kind,
        });
      }

      const currentRows = await tx.executeRaw<ProjectionRow>(
        `SELECT page_id, state, duplicate_set_id, canonical_page_id, last_event_id
         FROM page_dispositions WHERE page_id = ANY($1::int[]) FOR UPDATE`,
        [desired.map(item => item.page.id)],
      );
      const currentByPage = new Map(currentRows.map(row => [Number(row.page_id), row]));
      const desiredByPage = new Map(desired.map(item => [item.page.id, item]));

      for (const item of desired) {
        const current = currentByPage.get(item.page.id);
        const same = current?.state === item.state
          && current.duplicate_set_id === item.duplicateSetId
          && current.canonical_page_id === item.canonicalPageId;
        if (same) continue;
        if (item.itemKind === 'page' && current) {
          throw new DispositionError('projection_conflict', 'A batch page item already has a conflicting active disposition.');
        }
        if (item.itemKind === 'duplicate_set' && current?.duplicate_set_id
          && current.duplicate_set_id !== item.duplicateSetId) {
          throw new DispositionError('projection_conflict', 'A requested page belongs to another active duplicate set.');
        }
        if (item.itemKind === 'page' && item.state === 'canonical') {
          const dependents = await tx.executeRaw<{ page_id: number }>(
            `SELECT page_id FROM page_dispositions
             WHERE duplicate_set_id = $1::uuid AND page_id <> $2 FOR UPDATE`,
            [item.duplicateSetId, item.page.id],
          );
          if (dependents.length > 0) {
            throw new DispositionError('partial_duplicate_set', 'Use a duplicate_set batch item when a canonical has active members.');
          }
        }
        if (item.itemKind === 'page' && item.state === 'superseded') {
          const desiredCanonical = desiredByPage.get(item.canonicalPageId!);
          const currentCanonical = currentByPage.get(item.canonicalPageId!);
          const canonicalIsActive = desiredCanonical?.state === 'canonical'
            && desiredCanonical.duplicateSetId === item.duplicateSetId;
          const canonicalStaysActive = currentCanonical?.state === 'canonical'
            && currentCanonical.duplicate_set_id === item.duplicateSetId;
          if (!canonicalIsActive && !canonicalStaysActive) {
            throw new DispositionError('canonical_not_active', 'Superseded state requires the active canonical in the same duplicate set.');
          }
        }
      }

      const normalized = {
        kind: 'set_batch',
        actor: base.actor,
        reason: base.reason,
        items: desired.map(item => ({
          item_index: item.itemIndex,
          item_kind: item.itemKind,
          page_id: item.page.id,
          state: item.state,
          duplicate_set_id: item.duplicateSetId,
          canonical_page_id: item.canonicalPageId,
        })),
        metadata: base.metadata,
      };
      const changed = desired.filter(item => {
        const current = currentByPage.get(item.page.id);
        return current?.state !== item.state
          || current.duplicate_set_id !== item.duplicateSetId
          || current.canonical_page_id !== item.canonicalPageId;
      });
      const operationMetadata = {
        ...base.metadata,
        batch_item_count: normalizedItems.length,
        requested_page_count: desired.length,
        ...(changed.length === 0 ? { noop: true } : {}),
      };
      const op = await insertOperationOrReplay(tx, {
        kind: 'set_batch', ...base, metadata: operationMetadata, requestHash: requestHash(normalized),
      });
      if (op.replay || changed.length === 0) return buildReceipt(tx, op.operation, op.replay);

      const staged: Array<{ desired: BatchDesiredPage; eventId: number }> = [];
      for (const item of changed) {
        const eventId = await appendEvent(tx, {
          operationId: op.operation.id,
          pageId: item.page.id,
          eventKind: 'set',
          state: item.state,
          duplicateSetId: item.duplicateSetId,
          canonicalPageId: item.canonicalPageId,
        });
        staged.push({ desired: item, eventId });
      }
      for (const item of staged.filter(item => item.desired.state !== 'canonical')) {
        await applyProjection(tx, {
          pageId: item.desired.page.id,
          state: item.desired.state,
          duplicateSetId: item.desired.duplicateSetId,
          canonicalPageId: item.desired.canonicalPageId,
          eventId: item.eventId,
          actor: base.actor,
          reason: base.reason,
        });
      }
      for (const item of staged.filter(item => item.desired.state === 'canonical')) {
        await applyProjection(tx, {
          pageId: item.desired.page.id,
          state: item.desired.state,
          duplicateSetId: item.desired.duplicateSetId,
          canonicalPageId: item.desired.canonicalPageId,
          eventId: item.eventId,
          actor: base.actor,
          reason: base.reason,
        });
      }
      await incrementGeneration(tx);
      await assertProjectionInvariant(tx);
      return buildReceipt(tx, op.operation, false);
    });
  } catch (err) {
    mapConstraintError(err);
  }
}

async function applyReversal(
  tx: BrainEngine,
  operation: OperationRow,
  base: ReturnType<typeof validateWriteBase>,
  targets: EventRow[],
): Promise<void> {
  const staged: Array<{
    target: EventRow;
    state: DispositionResultingState;
    duplicateSetId: string | null;
    canonicalPageId: number | null;
    eventId: number;
  }> = [];
  for (const target of targets) {
    const prior = await previousState(tx, target);
    const eventId = await appendEvent(tx, {
      operationId: operation.id,
      pageId: target.page_id,
      eventKind: 'reverse',
      state: prior.state,
      duplicateSetId: prior.duplicateSetId,
      canonicalPageId: prior.canonicalPageId,
      reversesEventId: target.id,
    });
    staged.push({ target, ...prior, eventId });
  }
  const order = (item: typeof staged[number]) =>
    item.state === 'undispositioned' ? 0 : item.state === 'canonical' ? 2 : 1;
  for (const item of [...staged].sort((a, b) => order(a) - order(b))) {
    await applyProjection(tx, {
      pageId: item.target.page_id,
      state: item.state,
      duplicateSetId: item.duplicateSetId,
      canonicalPageId: item.canonicalPageId,
      eventId: item.eventId,
      actor: base.actor,
      reason: base.reason,
    });
  }
}

export async function reversePageDisposition(engine: BrainEngine, input: ReversePageDispositionInput): Promise<DispositionReceipt> {
  const base = validateWriteBase(input);
  if (!Number.isInteger(input.eventId) || input.eventId <= 0) {
    throw new DispositionError('invalid_params', 'event_id must be a positive integer.');
  }
  return engine.transaction(async tx => {
    const [page] = await resolvePagesForUpdate(tx, [{ sourceId: input.sourceId, slug: input.slug }]);
    const targetRows = await tx.executeRaw<EventRow>(
      `SELECT id, page_id, event_kind, resulting_state, duplicate_set_id, canonical_page_id
       FROM page_disposition_events WHERE id = $1 AND page_id = $2`,
      [input.eventId, page!.id],
    );
    const target = targetRows[0] ? normalizeEventRow(targetRows[0]) : undefined;
    const latestRows = await tx.executeRaw<{ id: number }>(
      `SELECT id FROM page_disposition_events WHERE page_id = $1 ORDER BY id DESC LIMIT 1 FOR UPDATE`,
      [page!.id],
    );
    if (!target || Number(latestRows[0]?.id) !== target.id) {
      throw new DispositionError('stale_reversal', 'The named event is not the page current disposition event.');
    }
    if (target.resulting_state === 'canonical' && target.duplicate_set_id) {
      const dependents = await tx.executeRaw<{ n: number }>(
        `SELECT COUNT(*)::int AS n FROM page_dispositions
         WHERE duplicate_set_id = $1::uuid AND state = 'superseded'`,
        [target.duplicate_set_id],
      );
      if (Number(dependents[0]?.n ?? 0) > 0) {
        throw new DispositionError('canonical_has_dependents', 'Reverse the complete duplicate set while superseded pages depend on this canonical.');
      }
    }
    const normalized = {
      kind: 'reverse_page', actor: base.actor, reason: base.reason,
      page_id: page!.id, event_id: target.id, metadata: base.metadata,
    };
    const op = await insertOperationOrReplay(tx, {
      kind: 'reverse_page', ...base, requestHash: requestHash(normalized),
    });
    if (op.replay) return buildReceipt(tx, op.operation, true);
    await applyReversal(tx, op.operation, base, [target]);
    await incrementGeneration(tx);
    await assertProjectionInvariant(tx);
    return buildReceipt(tx, op.operation, false);
  });
}

async function reverseOperation(
  engine: BrainEngine,
  input: ReverseDuplicateSetInput | ReverseDispositionBatchInput,
  reverseKind: 'reverse_duplicate_set' | 'reverse_batch',
  targetKind: 'set_duplicate_set' | 'set_batch',
): Promise<DispositionReceipt> {
  const base = validateWriteBase(input);
  const operationUuid = input.operationUuid.trim().toLowerCase();
  return engine.transaction(async tx => {
    const targetOps = await tx.executeRaw<{ id: number; kind: DispositionOperationKind }>(
      `SELECT id, kind FROM page_disposition_operations WHERE operation_uuid = $1::uuid`,
      [operationUuid],
    );
    const targetOperationId = Number(targetOps[0]?.id ?? 0);
    if (!targetOperationId) throw new DispositionError('operation_not_found', 'Disposition operation not found.');
    if (targetOps[0]!.kind !== targetKind) {
      throw new DispositionError('operation_kind_mismatch', `Expected a ${targetKind} operation.`);
    }
    const targetRows = await tx.executeRaw<EventRow>(
      `SELECT id, page_id, event_kind, resulting_state, duplicate_set_id, canonical_page_id
       FROM page_disposition_events WHERE operation_id = $1 ORDER BY id FOR UPDATE`,
      [targetOperationId],
    );
    const targets = targetRows.map(normalizeEventRow);
    if (targets.length === 0) throw new DispositionError('operation_not_reversible', 'The operation has no member events to reverse.');
    await tx.executeRaw(
      `SELECT id FROM pages WHERE id = ANY($1::int[]) ORDER BY id FOR UPDATE`,
      [targets.map(target => target.page_id)],
    );
    const latest = await tx.executeRaw<{ page_id: number; id: number }>(
      `SELECT DISTINCT ON (page_id) page_id, id
       FROM page_disposition_events
       WHERE page_id = ANY($1::int[])
       ORDER BY page_id, id DESC`,
      [targets.map(target => target.page_id)],
    );
    const latestByPage = new Map(latest.map(row => [Number(row.page_id), Number(row.id)]));
    if (targets.some(target => latestByPage.get(target.page_id) !== target.id)) {
      throw new DispositionError('stale_reversal', 'One or more operation members have a newer disposition event.');
    }
    const normalized = {
      kind: reverseKind, actor: base.actor, reason: base.reason,
      target_operation_id: targetOperationId,
      target_event_ids: targets.map(target => target.id), metadata: base.metadata,
    };
    const op = await insertOperationOrReplay(tx, {
      kind: reverseKind, ...base, requestHash: requestHash(normalized),
    });
    if (op.replay) return buildReceipt(tx, op.operation, true);
    await applyReversal(tx, op.operation, base, targets);
    await incrementGeneration(tx);
    await assertProjectionInvariant(tx);
    return buildReceipt(tx, op.operation, false);
  });
}

export async function reverseDuplicateSet(
  engine: BrainEngine,
  input: ReverseDuplicateSetInput,
): Promise<DispositionReceipt> {
  return reverseOperation(engine, input, 'reverse_duplicate_set', 'set_duplicate_set');
}

/** Reverse every event from one set_batch operation with one compensating receipt. */
export async function reverseDispositionBatch(
  engine: BrainEngine,
  input: ReverseDispositionBatchInput,
): Promise<DispositionReceipt> {
  return reverseOperation(engine, input, 'reverse_batch', 'set_batch');
}

export async function getPageDisposition(
  engine: BrainEngine,
  input: { sourceId: string; slug: string; historyLimit?: number },
): Promise<{ projection: DispositionProjection; history: DispositionEventReceipt[] }> {
  const pages = await engine.executeRaw<PageRow>(
    `SELECT id, source_id, slug, deleted_at FROM pages
     WHERE source_id = $1 AND slug = $2 AND deleted_at IS NULL`,
    [input.sourceId, input.slug],
  );
  const page = pages[0];
  if (!page) throw new DispositionError('page_not_found', `Live page not found: ${input.sourceId}:${input.slug}`);
  const projections = await loadProjections(engine, [page.id]);
  const projection = projections[0] ?? {
    page_id: page.id,
    source_id: page.source_id,
    slug: page.slug,
    state: 'undispositioned' as const,
    duplicate_set_id: null,
    canonical: null,
    last_event_id: null,
    reason: null,
    actor: null,
    updated_at: null,
  };
  const limit = Math.min(Math.max(1, input.historyLimit ?? 20), 100);
  const eventRows = await engine.executeRaw<Record<string, unknown>>(
    `SELECT e.id AS event_id, e.event_uuid, e.page_id, p.source_id, p.slug,
            e.event_kind, e.resulting_state, e.duplicate_set_id,
            e.canonical_page_id, cp.source_id AS canonical_source_id,
            cp.slug AS canonical_slug, e.reverses_event_id, e.created_at
     FROM page_disposition_events e
     JOIN pages p ON p.id = e.page_id
     LEFT JOIN pages cp ON cp.id = e.canonical_page_id
     WHERE e.page_id = $1 ORDER BY e.id DESC LIMIT $2`,
    [page.id, limit],
  );
  const history: DispositionEventReceipt[] = eventRows.map(row => ({
    event_id: Number(row.event_id), event_uuid: String(row.event_uuid), page_id: Number(row.page_id),
    source_id: String(row.source_id), slug: String(row.slug), event_kind: row.event_kind as 'set' | 'reverse',
    resulting_state: row.resulting_state as DispositionResultingState,
    duplicate_set_id: row.duplicate_set_id == null ? null : String(row.duplicate_set_id),
    canonical: row.canonical_page_id == null ? null : {
      page_id: Number(row.canonical_page_id), source_id: String(row.canonical_source_id), slug: String(row.canonical_slug),
    },
    reverses_event_id: row.reverses_event_id == null ? null : Number(row.reverses_event_id),
    created_at: asIso(row.created_at),
  }));
  return { projection, history };
}

export async function listPageDispositions(
  engine: BrainEngine,
  input: { sourceId: string; state?: DispositionState; duplicateSetId?: string; limit?: number; cursor?: string },
): Promise<{ items: DispositionProjection[]; generation: number; next_cursor: string | null }> {
  const limit = Math.min(Math.max(1, input.limit ?? 50), 100);
  const params: unknown[] = [input.sourceId];
  let filter = '';
  if (input.state) {
    params.push(input.state);
    filter += ` AND d.state = $${params.length}`;
  }
  if (input.duplicateSetId) {
    params.push(normalizeDuplicateSetId(input.duplicateSetId));
    filter += ` AND d.duplicate_set_id = $${params.length}::uuid`;
  }
  if (input.cursor) {
    const [updatedAt, pageId] = input.cursor.split('|');
    if (!updatedAt || !pageId || !Number.isInteger(Number(pageId))) {
      throw new DispositionError('invalid_params', 'Invalid disposition cursor.');
    }
    params.push(updatedAt, Number(pageId));
    filter += ` AND (d.updated_at, d.page_id) < ($${params.length - 1}::timestamptz, $${params.length})`;
  }
  params.push(limit + 1);
  const rows = await engine.executeRaw<{ page_id: number; updated_at: unknown }>(
    `SELECT d.page_id, d.updated_at
     FROM page_dispositions d JOIN pages p ON p.id = d.page_id
     WHERE p.source_id = $1 ${filter}
     ORDER BY d.updated_at DESC, d.page_id DESC LIMIT $${params.length}`,
    params,
  );
  const page = rows.slice(0, limit);
  const items = await loadProjections(engine, page.map(row => Number(row.page_id)));
  const byId = new Map(items.map(item => [item.page_id, item]));
  const ordered = page.map(row => byId.get(Number(row.page_id))!).filter(Boolean);
  const generationRows = await engine.executeRaw<{ generation: number }>(
    `SELECT generation FROM page_disposition_state WHERE id = 1`,
  );
  const last = rows.length > limit ? page.at(-1) : undefined;
  return {
    items: ordered,
    generation: Number(generationRows[0]?.generation ?? 0),
    next_cursor: last ? `${asIso(last.updated_at)}|${last.page_id}` : null,
  };
}
