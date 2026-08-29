import { createHash, randomUUID } from 'node:crypto';

export const DISPOSITION_ACTORS = ['ezra', 'marco', 'valentina', 'kepler', 'vector'] as const;
export type DispositionActor = typeof DISPOSITION_ACTORS[number];
export type DispositionState = 'canonical' | 'superseded' | 'quarantined';
export type DispositionResultingState = DispositionState | 'undispositioned';
export type DispositionScope = 'competing' | 'curation';
export type DispositionOperationKind =
  | 'set_page'
  | 'set_duplicate_set'
  | 'set_batch'
  | 'reverse_page'
  | 'reverse_duplicate_set'
  | 'reverse_batch';

export interface DispositionPageRef {
  sourceId: string;
  slug: string;
}

export interface DispositionProjection {
  page_id: number;
  source_id: string;
  slug: string;
  state: DispositionResultingState;
  duplicate_set_id: string | null;
  canonical: { page_id: number; source_id: string; slug: string } | null;
  last_event_id: number | null;
  reason: string | null;
  actor: DispositionActor | null;
  updated_at: string | null;
}

export interface DispositionEventReceipt {
  event_id: number;
  event_uuid: string;
  page_id: number;
  source_id: string;
  slug: string;
  event_kind: 'set' | 'reverse';
  resulting_state: DispositionResultingState;
  duplicate_set_id: string | null;
  canonical: { page_id: number; source_id: string; slug: string } | null;
  reverses_event_id: number | null;
  created_at: string;
}

export interface DispositionReceipt {
  operation_id: number;
  operation_uuid: string;
  kind: DispositionOperationKind;
  actor: DispositionActor;
  reason: string;
  idempotent_replay: boolean;
  noop: boolean;
  generation: number;
  events: DispositionEventReceipt[];
  projections: DispositionProjection[];
  affected_pages: Array<{ page_id: number; source_id: string; slug: string }>;
}

export class DispositionError extends Error {
  constructor(public readonly code: string, message: string) {
    super(message);
    this.name = 'DispositionError';
  }
}

export function assertActor(value: string): asserts value is DispositionActor {
  if (!(DISPOSITION_ACTORS as readonly string[]).includes(value)) {
    throw new DispositionError('permission_denied', 'Disposition actor is not an authorized durable fleet role.');
  }
}

export function normalizeReason(value: string): string {
  const reason = typeof value === 'string' ? value.trim() : '';
  if (reason.length < 1 || reason.length > 1000) {
    throw new DispositionError('invalid_params', 'reason must contain 1 to 1000 characters.');
  }
  return reason;
}

export function normalizeIdempotencyKey(value: string): string {
  const key = typeof value === 'string' ? value.trim() : '';
  if (key.length < 1 || key.length > 200) {
    throw new DispositionError('invalid_params', 'idempotency_key must contain 1 to 200 characters.');
  }
  return key;
}

export function normalizeMetadata(value: Record<string, unknown> | undefined): Record<string, unknown> {
  const metadata = value ?? {};
  if (!metadata || Array.isArray(metadata) || typeof metadata !== 'object') {
    throw new DispositionError('invalid_params', 'metadata must be an object.');
  }
  const encoded = JSON.stringify(metadata);
  if (encoded.length > 8192) {
    throw new DispositionError('invalid_params', 'metadata must serialize to at most 8192 bytes.');
  }
  return metadata;
}

export function normalizeDuplicateSetId(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const id = value.trim().toLowerCase();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(id)) {
    throw new DispositionError('invalid_params', 'duplicate_set_id must be a UUID.');
  }
  return id;
}

export function deterministicDuplicateSetId(idempotencyKey: string): string {
  const bytes = Buffer.from(createHash('sha256').update(`gbrain:page-disposition:${idempotencyKey}`).digest().subarray(0, 16));
  bytes[6] = (bytes[6]! & 0x0f) | 0x50;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function newOpaqueUuid(): string {
  return randomUUID();
}

function stableValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, entry]) => [key, stableValue(entry)]),
    );
  }
  return value;
}

export function requestHash(value: unknown): string {
  return createHash('sha256').update(JSON.stringify(stableValue(value))).digest('hex');
}

export function asIso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  const parsed = new Date(String(value));
  return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toISOString();
}
