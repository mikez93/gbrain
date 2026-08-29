/** Authenticated owner-curation operations for reversible page dispositions. */

import {
  DISPOSITION_ACTORS,
  DispositionError,
  deterministicDuplicateSetId,
  requestHash,
  type DispositionActor,
  type DispositionState,
} from '../disposition/model.ts';
import {
  getPageDisposition,
  listPageDispositions,
  reverseDispositionBatch,
  reverseDuplicateSet,
  reversePageDisposition,
  setDispositionBatch,
  setDuplicateSet,
  setPageDisposition,
  type DispositionBatchItem,
} from '../disposition/service.ts';
import { isValidSourceId } from '../source-id.ts';
import { OperationError } from './contract.ts';
import type { Operation, OperationContext } from './contract.ts';

const STATES = new Set<DispositionState>(['canonical', 'superseded', 'quarantined']);

function hasOwn(value: object, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function rejectActorSpoof(params: Record<string, unknown>): void {
  if (hasOwn(params, 'actor')) {
    throw new OperationError(
      'permission_denied',
      'actor is derived from the authenticated durable fleet role and cannot be supplied.',
    );
  }
}

function durableActor(ctx: OperationContext): DispositionActor {
  if (ctx.remote !== true || ctx.transport !== 'http' || !ctx.auth) {
    throw new OperationError(
      'permission_denied',
      'Page dispositions require an authenticated HTTP fleet-role client.',
    );
  }
  const actor = ctx.auth.clientName?.trim().toLowerCase();
  if (!actor || !(DISPOSITION_ACTORS as readonly string[]).includes(actor)) {
    throw new OperationError(
      'permission_denied',
      'The authenticated client is not a durable fleet disposition role.',
    );
  }
  return actor as DispositionActor;
}

/** Default ordinary retrieval to competing rows; curation is fleet-role-only. */
export function resolveDispositionScope(
  ctx: OperationContext,
  raw: unknown,
): 'competing' | 'curation' {
  if (raw === undefined || raw === null || raw === 'competing') return 'competing';
  if (raw !== 'curation') {
    throw new OperationError('invalid_params', 'disposition_scope must be competing or curation.');
  }
  durableActor(ctx);
  return 'curation';
}

function requiredString(params: Record<string, unknown>, key: string): string {
  const value = params[key];
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new OperationError('invalid_params', `${key} must be a non-empty string.`);
  }
  return value.trim();
}

function optionalString(params: Record<string, unknown>, key: string): string | undefined {
  const value = params[key];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new OperationError('invalid_params', `${key} must be a non-empty string when supplied.`);
  }
  return value.trim();
}

function sourceId(params: Record<string, unknown>): string {
  const value = requiredString(params, 'source_id');
  if (!isValidSourceId(value)) {
    throw new OperationError('invalid_params', 'source_id is not a valid GBrain source identifier.');
  }
  return value;
}

function metadata(params: Record<string, unknown>): Record<string, unknown> | undefined {
  const value = params.metadata;
  if (value === undefined) return undefined;
  if (!value || Array.isArray(value) || typeof value !== 'object') {
    throw new OperationError('invalid_params', 'metadata must be an object.');
  }
  return value as Record<string, unknown>;
}

function canonicalRef(value: unknown): { sourceId: string; slug: string } | undefined {
  if (value === undefined || value === null) return undefined;
  if (!value || Array.isArray(value) || typeof value !== 'object') {
    throw new OperationError('invalid_params', 'canonical must be an object with source_id and slug.');
  }
  const record = value as Record<string, unknown>;
  const unknown = Object.keys(record).filter(key => !['source_id', 'slug'].includes(key));
  if (unknown.length > 0) {
    throw new OperationError('invalid_params', `canonical contains unknown fields: ${unknown.join(', ')}`);
  }
  return { sourceId: sourceId(record), slug: requiredString(record, 'slug') };
}

function state(params: Record<string, unknown>): DispositionState {
  const value = requiredString(params, 'state') as DispositionState;
  if (!STATES.has(value)) {
    throw new OperationError('invalid_params', 'state must be canonical, superseded, or quarantined.');
  }
  return value;
}

function stringArray(value: unknown, name: string): string[] | undefined {
  if (value === undefined || value === null) return undefined;
  if (!Array.isArray(value) || value.some(item => typeof item !== 'string' || item.trim().length === 0)) {
    throw new OperationError('invalid_params', `${name} must be an array of non-empty strings.`);
  }
  return value.map(item => (item as string).trim());
}

function pageRefArray(value: unknown, name: string): Array<{ sourceId: string; slug: string }> | undefined {
  if (value === undefined || value === null) return undefined;
  if (!Array.isArray(value) || value.length === 0) {
    throw new OperationError('invalid_params', `${name} must be a non-empty array of page refs.`);
  }
  return value.map((item, index) => {
    const ref = canonicalRef(item);
    if (!ref) throw new OperationError('invalid_params', `${name}[${index}] must be a page ref.`);
    return ref;
  });
}

function batchItems(ctx: OperationContext, value: unknown): DispositionBatchItem[] {
  if (!Array.isArray(value)) {
    throw new OperationError('invalid_params', 'items must be an array.');
  }
  return value.map((entry, index) => {
    if (!entry || Array.isArray(entry) || typeof entry !== 'object') {
      throw new OperationError('invalid_params', `items[${index}] must be an object.`);
    }
    const item = entry as Record<string, unknown>;
    if (hasOwn(item, 'actor')) {
      throw new OperationError('permission_denied', `items[${index}].actor cannot be supplied.`);
    }
    const kind = requiredString(item, 'kind');
    if (kind === 'duplicate_set') {
      const allowed = new Set(['kind', 'source_id', 'canonical_slug', 'superseded_slugs', 'superseded', 'duplicate_set_id']);
      const unknown = Object.keys(item).filter(key => !allowed.has(key));
      if (unknown.length > 0) {
        throw new OperationError('invalid_params', `items[${index}] contains unknown fields: ${unknown.join(', ')}`);
      }
      const requestedSource = sourceId(item);
      return {
        kind,
        sourceId: requestedSource,
        canonicalSlug: requiredString(item, 'canonical_slug'),
        supersededSlugs: stringArray(item.superseded_slugs, `items[${index}].superseded_slugs`),
        superseded: pageRefArray(item.superseded, `items[${index}].superseded`),
        duplicateSetId: optionalString(item, 'duplicate_set_id'),
      };
    }
    if (kind === 'page') {
      const allowed = new Set(['kind', 'source_id', 'slug', 'state', 'duplicate_set_id', 'canonical']);
      const unknown = Object.keys(item).filter(key => !allowed.has(key));
      if (unknown.length > 0) {
        throw new OperationError('invalid_params', `items[${index}] contains unknown fields: ${unknown.join(', ')}`);
      }
      const requestedSource = sourceId(item);
      const canonical = canonicalRef(item.canonical);
      return {
        kind,
        sourceId: requestedSource,
        slug: requiredString(item, 'slug'),
        state: state(item),
        duplicateSetId: optionalString(item, 'duplicate_set_id'),
        canonical,
      };
    }
    throw new OperationError('invalid_params', `items[${index}].kind must be duplicate_set or page.`);
  });
}

async function invoke<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (err) {
    if (err instanceof DispositionError) {
      throw new OperationError(err.code, err.message);
    }
    throw err;
  }
}

function writeBase(ctx: OperationContext, params: Record<string, unknown>) {
  rejectActorSpoof(params);
  return {
    actor: durableActor(ctx),
    reason: requiredString(params, 'reason'),
    idempotencyKey: requiredString(params, 'idempotency_key'),
    metadata: metadata(params),
  };
}

function preparedRecordKey(
  record: Record<string, unknown>,
  key: 'set_idempotency_key' | 'reversal_idempotency_key',
  index: number,
): string {
  const value = record[key];
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new OperationError('invalid_params', `records[${index}].${key} must be a non-empty string.`);
  }
  return value.trim();
}

function positivePageId(value: unknown, name: string): number {
  const id = typeof value === 'string' && /^\d+$/.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(id) || Number(id) <= 0) {
    throw new OperationError('invalid_params', `${name} must be a positive page ID.`);
  }
  return Number(id);
}

interface PreparedOwnerRecord {
  record: Record<string, unknown>;
  disposition: Record<string, unknown>;
  setKey: string;
  reversalKey: string;
  pageIds: number[];
}

function parsePreparedRecords(value: unknown): PreparedOwnerRecord[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new OperationError('invalid_params', 'records must be a non-empty array of prepared owner records.');
  }
  return value.map((entry, index) => {
    if (!entry || Array.isArray(entry) || typeof entry !== 'object') {
      throw new OperationError('invalid_params', `records[${index}] must be an object.`);
    }
    const record = entry as Record<string, unknown>;
    if (hasOwn(record, 'actor')) {
      throw new OperationError('permission_denied', `records[${index}].actor cannot be supplied.`);
    }
    if (!record.disposition || Array.isArray(record.disposition) || typeof record.disposition !== 'object') {
      throw new OperationError('invalid_params', `records[${index}].disposition must be an object.`);
    }
    const disposition = record.disposition as Record<string, unknown>;
    if (hasOwn(disposition, 'actor')) {
      throw new OperationError('permission_denied', `records[${index}].disposition.actor cannot be supplied.`);
    }
    const operation = requiredString(disposition, 'operation');
    let pageIds: number[];
    if (operation === 'set_duplicate_set') {
      const canonicalId = positivePageId(disposition.canonical_page_id, `records[${index}].disposition.canonical_page_id`);
      if (!Array.isArray(disposition.superseded_page_ids) || disposition.superseded_page_ids.length === 0) {
        throw new OperationError('invalid_params', `records[${index}].disposition.superseded_page_ids must be non-empty.`);
      }
      pageIds = [canonicalId, ...disposition.superseded_page_ids.map((id, memberIndex) =>
        positivePageId(id, `records[${index}].disposition.superseded_page_ids[${memberIndex}]`))];
    } else if (operation === 'set_page_disposition') {
      pageIds = [positivePageId(disposition.page_id, `records[${index}].disposition.page_id`)];
    } else {
      throw new OperationError(
        'invalid_params',
        `records[${index}].disposition.operation must be set_duplicate_set or set_page_disposition.`,
      );
    }
    if (new Set(pageIds).size !== pageIds.length) {
      throw new OperationError('invalid_params', `records[${index}] repeats a page ID.`);
    }
    return {
      record,
      disposition,
      setKey: preparedRecordKey(record, 'set_idempotency_key', index),
      reversalKey: preparedRecordKey(record, 'reversal_idempotency_key', index),
      pageIds,
    };
  });
}

async function preparedBatchItems(
  ctx: OperationContext,
  records: PreparedOwnerRecord[],
): Promise<DispositionBatchItem[]> {
  const allIds = records.flatMap(record => record.pageIds);
  if (new Set(allIds).size !== allIds.length) {
    throw new OperationError('invalid_params', 'A page ID may appear in only one prepared record per batch.');
  }
  const rows = await ctx.engine.executeRaw<{ id: number; source_id: string; slug: string }>(
    `SELECT id, source_id, slug FROM pages
     WHERE id = ANY($1::int[]) AND deleted_at IS NULL
     ORDER BY id`,
    [allIds],
  );
  const byId = new Map(rows.map(row => [Number(row.id), row]));
  const missing = allIds.filter(id => !byId.has(id));
  if (missing.length > 0) {
    throw new OperationError('page_not_found', `Live page IDs not found in this brain: ${missing.join(', ')}`);
  }
  return records.map((prepared, index) => {
    const operation = requiredString(prepared.disposition, 'operation');
    if (operation === 'set_duplicate_set') {
      const [canonicalId, ...supersededIds] = prepared.pageIds;
      const canonical = byId.get(canonicalId!)!;
      const duplicateSetKey = optionalString(prepared.disposition, 'duplicate_set_key') ?? prepared.setKey;
      return {
        kind: 'duplicate_set' as const,
        sourceId: canonical.source_id,
        canonicalSlug: canonical.slug,
        superseded: supersededIds.map(id => {
          const page = byId.get(id)!;
          return { sourceId: page.source_id, slug: page.slug };
        }),
        duplicateSetId: deterministicDuplicateSetId(duplicateSetKey),
      };
    }
    const page = byId.get(prepared.pageIds[0]!)!;
    const requestedState = requiredString(prepared.disposition, 'state');
    if (requestedState !== 'quarantined') {
      throw new OperationError(
        'invalid_params',
        `records[${index}] set_page_disposition currently supports the standalone quarantined state.`,
      );
    }
    return { kind: 'page' as const, sourceId: page.source_id, slug: page.slug, state: 'quarantined' as const };
  });
}

function derivedRecordIdempotencyKey(
  prefix: 'set' | 'reverse',
  records: PreparedOwnerRecord[],
): string {
  const keys = records.map(record => prefix === 'set' ? record.setKey : record.reversalKey);
  if (new Set(keys).size !== keys.length) {
    throw new OperationError('invalid_params', `Prepared ${prefix} idempotency keys must be unique within a batch.`);
  }
  return `prepared-${prefix}-batch:${requestHash(keys)}`;
}

const commonWriteParams = {
  reason: { type: 'string', required: true, description: 'Bounded owner explanation recorded on the immutable operation.' },
  idempotency_key: { type: 'string', required: true, description: 'Caller-stable retry key; same key and request replays one receipt.' },
  metadata: { type: 'object', description: 'Optional bounded receipt-safe metadata; no page bodies or credentials.' },
} as const;

const set_page_disposition: Operation = {
  name: 'set_page_disposition',
  description: 'Set one live page canonical, superseded, or quarantined through the append-only owner-curation ledger.',
  params: {
    source_id: { type: 'string', required: true, description: 'Authorized source containing the page.' },
    slug: { type: 'string', required: true, description: 'Live page slug.' },
    state: { type: 'string', required: true, enum: [...STATES], description: 'Resulting page disposition.' },
    duplicate_set_id: { type: 'string', description: 'Opaque duplicate-set UUID for canonical or superseded state.' },
    canonical: { type: 'object', description: 'Canonical target {source_id, slug} required for superseded state.' },
    ...commonWriteParams,
  },
  handler: async (ctx, p) => {
    const base = writeBase(ctx, p);
    const requestedSource = sourceId(p);
    const canonical = canonicalRef(p.canonical);
    return invoke(() => setPageDisposition(ctx.engine, {
      ...base,
      sourceId: requestedSource,
      slug: requiredString(p, 'slug'),
      state: state(p),
      duplicateSetId: optionalString(p, 'duplicate_set_id'),
      canonical,
    }));
  },
  mutating: true,
  scope: 'write',
  annotations: { destructiveHint: false, idempotentHint: true },
};

const set_duplicate_set: Operation = {
  name: 'set_duplicate_set',
  description: 'Atomically choose one canonical page and supersede named members across sources in the same authenticated brain.',
  params: {
    source_id: { type: 'string', required: true, description: 'Source containing the canonical page.' },
    canonical_slug: { type: 'string', required: true, description: 'Slug of the one canonical member.' },
    superseded_slugs: { type: 'array', items: { type: 'string' }, description: 'One or more same-source slugs superseded by the canonical.' },
    superseded: { type: 'array', items: { type: 'object' }, description: 'Cross-source members as {source_id, slug}; use instead of superseded_slugs.' },
    duplicate_set_id: { type: 'string', description: 'Existing opaque duplicate-set UUID; generated deterministically when absent.' },
    ...commonWriteParams,
  },
  handler: async (ctx, p) => {
    const base = writeBase(ctx, p);
    const requestedSource = sourceId(p);
    return invoke(() => setDuplicateSet(ctx.engine, {
      ...base,
      sourceId: requestedSource,
      canonicalSlug: requiredString(p, 'canonical_slug'),
      supersededSlugs: stringArray(p.superseded_slugs, 'superseded_slugs'),
      superseded: pageRefArray(p.superseded, 'superseded'),
      duplicateSetId: optionalString(p, 'duplicate_set_id'),
    }));
  },
  mutating: true,
  scope: 'write',
  annotations: { destructiveHint: false, idempotentHint: true },
};

const set_disposition_batch: Operation = {
  name: 'set_disposition_batch',
  description: 'Atomically apply either native disposition groups or prepared owner page-ID records with one durable receipt and no partial writes.',
  params: {
    items: { type: 'array', items: { type: 'object' }, description: 'Native 1-200 duplicate_set/page groups affecting at most 500 unique pages.' },
    records: { type: 'array', items: { type: 'object' }, description: 'Prepared owner records with disposition, set_idempotency_key, and reversal_idempotency_key.' },
    reason: commonWriteParams.reason,
    idempotency_key: { type: 'string', description: 'Required for native items; derived from prepared record set keys when records are supplied.' },
    metadata: commonWriteParams.metadata,
  },
  handler: async (ctx, p) => {
    const hasItems = p.items !== undefined;
    const hasRecords = p.records !== undefined;
    if (hasItems === hasRecords) {
      throw new OperationError('invalid_params', 'Supply exactly one of items or records.');
    }
    if (hasItems) {
      const base = writeBase(ctx, p);
      return invoke(() => setDispositionBatch(ctx.engine, { ...base, items: batchItems(ctx, p.items) }));
    }
    rejectActorSpoof(p);
    const records = parsePreparedRecords(p.records);
    const recordItems = await preparedBatchItems(ctx, records);
    const callerMetadata = metadata(p) ?? {};
    const base = {
      actor: durableActor(ctx),
      reason: requiredString(p, 'reason'),
      idempotencyKey: optionalString(p, 'idempotency_key') ?? derivedRecordIdempotencyKey('set', records),
      metadata: {
        ...callerMetadata,
        prepared_record_count: records.length,
        prepared_record_key_hash: requestHash(records.map(record => ({
          set: record.setKey,
          reverse: record.reversalKey,
        }))),
      },
    };
    return invoke(() => setDispositionBatch(ctx.engine, { ...base, items: recordItems }));
  },
  mutating: true,
  scope: 'write',
  annotations: { destructiveHint: false, idempotentHint: true },
};

const reverse_page_disposition: Operation = {
  name: 'reverse_page_disposition',
  description: 'Append a compensating event for one page current disposition event.',
  params: {
    source_id: { type: 'string', required: true, description: 'Authorized source containing the page.' },
    slug: { type: 'string', required: true, description: 'Live page slug.' },
    event_id: { type: 'number', required: true, description: 'Exact current event ID to reverse.' },
    ...commonWriteParams,
  },
  handler: async (ctx, p) => {
    const base = writeBase(ctx, p);
    const requestedSource = sourceId(p);
    return invoke(() => reversePageDisposition(ctx.engine, {
      ...base,
      sourceId: requestedSource,
      slug: requiredString(p, 'slug'),
      eventId: Number(p.event_id),
    }));
  },
  mutating: true,
  scope: 'write',
  annotations: { destructiveHint: false, idempotentHint: true },
};

function reverseOperation(name: 'reverse_duplicate_set' | 'reverse_disposition_batch'): Operation {
  const batch = name === 'reverse_disposition_batch';
  return {
    name,
    description: batch
      ? 'Atomically compensate every event in one exact set_batch operation with one reversal receipt.'
      : 'Atomically compensate every member event in one exact set_duplicate_set operation.',
    params: {
      operation_uuid: { type: 'string', required: true, description: 'Opaque UUID of the exact operation to reverse.' },
      reason: commonWriteParams.reason,
      idempotency_key: batch
        ? { type: 'string', description: 'Derived from prepared reversal keys when records are supplied; otherwise required.' }
        : commonWriteParams.idempotency_key,
      ...(batch ? {
        records: { type: 'array', items: { type: 'object' }, description: 'The same prepared owner records used for the batch apply.' },
      } : {}),
      metadata: commonWriteParams.metadata,
    },
    handler: async (ctx, p) => {
      let base: ReturnType<typeof writeBase>;
      if (batch && p.records !== undefined) {
        rejectActorSpoof(p);
        const records = parsePreparedRecords(p.records);
        base = {
          actor: durableActor(ctx),
          reason: requiredString(p, 'reason'),
          idempotencyKey: optionalString(p, 'idempotency_key') ?? derivedRecordIdempotencyKey('reverse', records),
          metadata: {
            ...(metadata(p) ?? {}),
            prepared_record_count: records.length,
            prepared_reversal_key_hash: requestHash(records.map(record => record.reversalKey)),
          },
        };
      } else {
        base = writeBase(ctx, p);
      }
      const input = { ...base, operationUuid: requiredString(p, 'operation_uuid') };
      return invoke(() => batch
        ? reverseDispositionBatch(ctx.engine, input)
        : reverseDuplicateSet(ctx.engine, input));
    },
    mutating: true,
    scope: 'write',
    annotations: { destructiveHint: false, idempotentHint: true },
  };
}

const get_page_disposition: Operation = {
  name: 'get_page_disposition',
  description: 'Read one page current disposition plus bounded newest-first immutable event history; never returns the page body.',
  params: {
    source_id: { type: 'string', required: true, description: 'Authorized source containing the page.' },
    slug: { type: 'string', required: true, description: 'Live page slug.' },
    history_limit: { type: 'number', description: 'Event-history limit, clamped to 1-100 (default 20).' },
  },
  handler: async (ctx, p) => {
    rejectActorSpoof(p);
    durableActor(ctx);
    const requestedSource = sourceId(p);
    return invoke(() => getPageDisposition(ctx.engine, {
      sourceId: requestedSource,
      slug: requiredString(p, 'slug'),
      historyLimit: p.history_limit === undefined ? undefined : Number(p.history_limit),
    }));
  },
  scope: 'read',
  annotations: { readOnlyHint: true },
};

const list_page_dispositions: Operation = {
  name: 'list_page_dispositions',
  description: 'List bounded current page dispositions in one authorized source with generation and a stable cursor; never returns page bodies.',
  params: {
    source_id: { type: 'string', required: true, description: 'Authorized source to list.' },
    state: { type: 'string', enum: [...STATES], description: 'Optional canonical, superseded, or quarantined filter.' },
    duplicate_set_id: { type: 'string', description: 'Optional duplicate-set UUID filter.' },
    limit: { type: 'number', description: 'Page limit, clamped to 1-100 (default 50).' },
    cursor: { type: 'string', description: 'Opaque updated_at|page_id cursor from the prior response.' },
  },
  handler: async (ctx, p) => {
    rejectActorSpoof(p);
    durableActor(ctx);
    const requestedSource = sourceId(p);
    const stateFilter = p.state === undefined ? undefined : state(p);
    return invoke(() => listPageDispositions(ctx.engine, {
      sourceId: requestedSource,
      state: stateFilter,
      duplicateSetId: optionalString(p, 'duplicate_set_id'),
      limit: p.limit === undefined ? undefined : Number(p.limit),
      cursor: optionalString(p, 'cursor'),
    }));
  },
  scope: 'read',
  annotations: { readOnlyHint: true },
};

export const dispositionOperations: Operation[] = [
  set_page_disposition,
  set_duplicate_set,
  set_disposition_batch,
  reverse_page_disposition,
  reverseOperation('reverse_duplicate_set'),
  reverseOperation('reverse_disposition_batch'),
  get_page_disposition,
  list_page_dispositions,
];
