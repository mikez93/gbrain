import type { BrainEngine } from '../engine.ts';
import type { SearchResult } from '../types.ts';

const MAX_BINDINGS_PER_PAGE = 25;

export interface FactPageBinding {
  fact_id: number;
  capture_page_slug: string;
  hermes_session_ref: string;
  matched_via: 'capture_page' | 'entity_fence';
}

interface PageRef {
  sourceId: string;
  slug: string;
}

export interface FactAuthorityCoordinate {
  fact_id: number;
  valid_from: string;
  valid_until: string | null;
  expired_at: string | null;
  superseded_by: number | null;
}

export interface FactAuthorityCompleteSummary {
  state: 'empty' | 'active_head' | 'no_active_terminal' | 'future_only' | 'future_and_terminal';
  matching_count: number;
  active_count: number;
  future_count: number;
  terminal_count: number;
  selected_active_fact: FactAuthorityCoordinate | null;
}

export interface FactAuthorityEvidence {
  version: 'f9-fact-authority-evidence-v2';
  availability: 'available' | 'unavailable';
  authority_evaluated_at: string | null;
  complete_summary: FactAuthorityCompleteSummary | null;
}

interface FactBindingRow {
  ref_source_id: string;
  ref_slug: string;
  fact_id: number | string;
  capture_page_slug: string;
  hermes_session_ref: string;
  matched_via: 'capture_page' | 'entity_fence';
}

interface FactAuthorityRow {
  ref_source_id: string;
  ref_slug: string;
  evaluated_at: unknown;
  matching_count: unknown;
  active_count: unknown;
  future_count: unknown;
  terminal_count: unknown;
  partition_error_count: unknown;
  selected_active_fact_id: unknown;
  selected_valid_from: unknown;
  selected_valid_until: unknown;
  selected_expired_at: unknown;
  selected_superseded_by: unknown;
}

function refKey(sourceId: string, slug: string): string {
  return `${sourceId}\u0000${slug}`;
}

function unavailableFactAuthority(): FactAuthorityEvidence {
  return {
    version: 'f9-fact-authority-evidence-v2',
    availability: 'unavailable',
    authority_evaluated_at: null,
    complete_summary: null,
  };
}

function safeCount(value: unknown): number | null {
  if (typeof value === 'string' && /^\d+$/.test(value)) value = Number(value);
  return Number.isSafeInteger(value) && (value as number) >= 0 ? value as number : null;
}

function safePositiveInt(value: unknown): number | null {
  const parsed = safeCount(value);
  return parsed !== null && parsed > 0 ? parsed : null;
}

function utcTimestamp(value: unknown): string | null {
  if (value instanceof Date && Number.isFinite(value.getTime())) return value.toISOString();
  if (typeof value !== 'string') return null;
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime())) return null;
  return parsed.toISOString();
}

/**
 * Load complete fact-state evidence for every requested page coordinate.
 * This is separate from the capped capture-lineage display above: authority
 * must account for every matching fact and therefore has no LIMIT.
 */
export async function loadFactAuthorityEvidence(
  engine: BrainEngine,
  refs: PageRef[],
  opts: { authorized?: boolean } = {},
): Promise<Map<string, FactAuthorityEvidence>> {
  const unique = [...new Map(
    refs
      .filter((ref) => ref.sourceId && ref.slug)
      .map((ref) => [refKey(ref.sourceId, ref.slug), ref]),
  ).values()];
  const unavailable = () => new Map(
    unique.map((ref) => [refKey(ref.sourceId, ref.slug), unavailableFactAuthority()]),
  );
  if (opts.authorized !== true || unique.length === 0) return new Map();
  if (typeof engine.executeRaw !== 'function') return unavailable();

  const params: unknown[] = [];
  const values = unique.map((ref) => {
    params.push(ref.sourceId, ref.slug);
    return `($${params.length - 1}::text, $${params.length}::text)`;
  }).join(', ');
  let rows: FactAuthorityRow[];
  try {
    rows = await engine.executeRaw<FactAuthorityRow>(
      `WITH refs(source_id, slug) AS (VALUES ${values}),
       clock AS (SELECT transaction_timestamp() AS evaluated_at),
       matched AS (
         SELECT r.source_id AS ref_source_id, r.slug AS ref_slug,
                f.id AS fact_id, f.valid_from, f.valid_until,
                f.expired_at, f.superseded_by, clock.evaluated_at,
                (f.id IS NOT NULL AND f.valid_from <= clock.evaluated_at
                 AND (f.valid_until IS NULL OR clock.evaluated_at < f.valid_until)
                 AND f.expired_at IS NULL AND f.superseded_by IS NULL) AS is_active,
                (f.id IS NOT NULL AND f.valid_from > clock.evaluated_at
                 AND f.expired_at IS NULL AND f.superseded_by IS NULL) AS is_future,
                (f.id IS NOT NULL AND (f.expired_at IS NOT NULL OR f.superseded_by IS NOT NULL
                 OR (f.valid_until IS NOT NULL AND f.valid_until <= clock.evaluated_at))) AS is_terminal,
                (f.id IS NOT NULL AND f.valid_until IS NOT NULL
                 AND f.valid_until < f.valid_from) AS has_inverted_interval
         FROM refs r CROSS JOIN clock
         LEFT JOIN facts f ON f.source_id = r.source_id
          AND (f.context = r.slug OR f.source_markdown_slug = r.slug)
          AND f.source = 'mcp:put_page'
       ), summary AS (
         SELECT ref_source_id, ref_slug, evaluated_at,
                count(fact_id) AS matching_count,
                count(*) FILTER (WHERE is_active) AS active_count,
                count(*) FILTER (WHERE is_future) AS future_count,
                count(*) FILTER (WHERE is_terminal) AS terminal_count,
                count(*) FILTER (WHERE fact_id IS NOT NULL AND (
                  has_inverted_interval OR
                  ((is_active::int + is_future::int + is_terminal::int) <> 1)
                )) AS partition_error_count,
                max(fact_id) FILTER (WHERE is_active) AS selected_active_fact_id
         FROM matched GROUP BY ref_source_id, ref_slug, evaluated_at
       )
       SELECT s.ref_source_id, s.ref_slug, s.evaluated_at,
              s.matching_count, s.active_count, s.future_count, s.terminal_count,
              s.partition_error_count, s.selected_active_fact_id,
              h.valid_from AS selected_valid_from, h.valid_until AS selected_valid_until,
              h.expired_at AS selected_expired_at, h.superseded_by AS selected_superseded_by
       FROM summary s
       LEFT JOIN matched h ON h.ref_source_id=s.ref_source_id AND h.ref_slug=s.ref_slug
        AND h.fact_id=s.selected_active_fact_id
       ORDER BY s.ref_source_id, s.ref_slug`,
      params,
    );
  } catch {
    return unavailable();
  }

  const out = new Map<string, FactAuthorityEvidence>();
  let sharedEvaluatedAt: string | null = null;
  for (const row of rows) {
    const key = refKey(row.ref_source_id, row.ref_slug);
    if (!unique.some((ref) => refKey(ref.sourceId, ref.slug) === key) || out.has(key)) return unavailable();
    const evaluatedAt = utcTimestamp(row.evaluated_at);
    const matching = safeCount(row.matching_count);
    const active = safeCount(row.active_count);
    const future = safeCount(row.future_count);
    const terminal = safeCount(row.terminal_count);
    const partitionErrors = safeCount(row.partition_error_count);
    if (
      evaluatedAt === null || matching === null || active === null || future === null
      || terminal === null || partitionErrors !== 0 || active > 1
      || active + future + terminal !== matching
    ) return unavailable();
    if (sharedEvaluatedAt !== null && sharedEvaluatedAt !== evaluatedAt) return unavailable();
    sharedEvaluatedAt = evaluatedAt;

    let state: FactAuthorityCompleteSummary['state'];
    if (active > 0) state = 'active_head';
    else if (matching === 0) state = 'empty';
    else if (terminal === matching) state = 'no_active_terminal';
    else if (future === matching) state = 'future_only';
    else if (future > 0 && terminal > 0) state = 'future_and_terminal';
    else return unavailable();

    let selected: FactAuthorityCoordinate | null = null;
    if (active > 0) {
      const factId = safePositiveInt(row.selected_active_fact_id);
      const validFrom = utcTimestamp(row.selected_valid_from);
      const validUntil = row.selected_valid_until == null ? null : utcTimestamp(row.selected_valid_until);
      const expiredAt = row.selected_expired_at == null ? null : utcTimestamp(row.selected_expired_at);
      const supersededBy = row.selected_superseded_by == null
        ? null
        : safePositiveInt(row.selected_superseded_by);
      if (
        factId === null || validFrom === null
        || (row.selected_valid_until != null && validUntil === null)
        || (row.selected_expired_at != null && expiredAt === null)
        || (row.selected_superseded_by != null && supersededBy === null)
        || Date.parse(validFrom) > Date.parse(evaluatedAt)
        || (validUntil !== null && Date.parse(evaluatedAt) >= Date.parse(validUntil))
        || expiredAt !== null || supersededBy !== null
      ) return unavailable();
      selected = {
        fact_id: factId,
        valid_from: validFrom,
        valid_until: validUntil,
        expired_at: expiredAt,
        superseded_by: supersededBy,
      };
    } else if (
      row.selected_active_fact_id != null || row.selected_valid_from != null
      || row.selected_valid_until != null || row.selected_expired_at != null
      || row.selected_superseded_by != null
    ) return unavailable();

    out.set(key, {
      version: 'f9-fact-authority-evidence-v2',
      availability: 'available',
      authority_evaluated_at: evaluatedAt,
      complete_summary: {
        state,
        matching_count: matching,
        active_count: active,
        future_count: future,
        terminal_count: terminal,
        selected_active_fact: selected,
      },
    });
  }
  if (out.size !== unique.length) return unavailable();
  return out;
}

export async function stampFactAuthorityEvidence(
  engine: BrainEngine,
  results: SearchResult[],
  opts: {
    authorized?: boolean;
    sourceAuthorized?: (sourceId: string) => boolean;
  } = {},
): Promise<void> {
  if (opts.authorized !== true || opts.sourceAuthorized === undefined) return;
  const eligible = results.filter((result) => opts.sourceAuthorized!(result.source_id ?? 'default'));
  const evidence = await loadFactAuthorityEvidence(
    engine,
    eligible.map((result) => ({ sourceId: result.source_id ?? 'default', slug: result.slug })),
    { authorized: true },
  );
  for (const result of eligible) {
    const found = evidence.get(refKey(result.source_id ?? 'default', result.slug));
    if (found) result.fact_authority_evidence = found;
  }
}

/**
 * Load the durable capture lineage attached to pages returned by search/read.
 *
 * `facts.context` is the originating capture page while
 * `facts.source_markdown_slug` is the entity fence that physically stores the
 * fact. They are deliberately separate coordinates; substituting the fence
 * slug for the capture slug loses the Hermes turn/session binding.
 */
export async function loadFactPageBindings(
  engine: BrainEngine,
  refs: PageRef[],
  opts: { authorized?: boolean } = {},
): Promise<Map<string, FactPageBinding[]>> {
  const unique = [...new Map(
    refs
      .filter((ref) => ref.sourceId && ref.slug)
      .map((ref) => [refKey(ref.sourceId, ref.slug), ref]),
  ).values()];
  const out = new Map<string, FactPageBinding[]>();
  // Some read-only embedders and test doubles implement only the page/search
  // surface. Bindings are additive metadata, so preserve the underlying read
  // contract when raw SQL is genuinely unavailable.
  if (
    opts.authorized !== true
    || unique.length === 0
    || typeof engine.executeRaw !== 'function'
  ) return out;

  const params: unknown[] = [];
  const values = unique.map((ref) => {
    params.push(ref.sourceId, ref.slug);
    return `($${params.length - 1}::text, $${params.length}::text)`;
  }).join(', ');
  let rows: FactBindingRow[];
  try {
    rows = await engine.executeRaw<FactBindingRow>(
      `WITH refs(source_id, slug) AS (VALUES ${values}),
     matched AS (
       SELECT
         r.source_id AS ref_source_id,
         r.slug AS ref_slug,
         f.id AS fact_id,
         f.context AS capture_page_slug,
         f.source_session AS hermes_session_ref,
         CASE WHEN f.context = r.slug THEN 'capture_page' ELSE 'entity_fence' END AS matched_via,
         ROW_NUMBER() OVER (
           PARTITION BY r.source_id, r.slug
           ORDER BY f.id DESC
         ) AS binding_rank
       FROM refs r
       JOIN facts f
         ON f.source_id = r.source_id
        AND (f.context = r.slug OR f.source_markdown_slug = r.slug)
       WHERE f.source = 'mcp:put_page'
         AND f.expired_at IS NULL
         AND NULLIF(BTRIM(f.context), '') IS NOT NULL
         AND NULLIF(BTRIM(f.source_session), '') IS NOT NULL
     )
     SELECT ref_source_id, ref_slug, fact_id, capture_page_slug,
            hermes_session_ref, matched_via
     FROM matched
     WHERE binding_rank <= ${MAX_BINDINGS_PER_PAGE}
     ORDER BY ref_source_id, ref_slug, fact_id DESC`,
      params,
    );
  } catch {
    // Binding coordinates are additive private metadata. A storage/query
    // failure must never leak them, but it also must not turn an otherwise
    // healthy authorized page/search result (including lexical fallback)
    // into an unclassified transport failure. Omit the additive field.
    return out;
  }

  for (const row of rows) {
    const factId = Number(row.fact_id);
    if (!Number.isSafeInteger(factId) || factId < 1) continue;
    const key = refKey(row.ref_source_id, row.ref_slug);
    const bindings = out.get(key) ?? [];
    bindings.push({
      fact_id: factId,
      capture_page_slug: row.capture_page_slug,
      hermes_session_ref: row.hermes_session_ref,
      matched_via: row.matched_via,
    });
    out.set(key, bindings);
  }
  return out;
}

export async function stampFactPageBindings(
  engine: BrainEngine,
  results: SearchResult[],
  opts: { authorized?: boolean } = {},
): Promise<void> {
  const bindings = await loadFactPageBindings(
    engine,
    results.map((result) => ({
      sourceId: result.source_id ?? 'default',
      slug: result.slug,
    })),
    opts,
  );
  for (const result of results) {
    const found = bindings.get(refKey(result.source_id ?? 'default', result.slug));
    if (found?.length) {
      (result as SearchResult & { fact_bindings?: FactPageBinding[] }).fact_bindings = found;
    }
  }
}

export function factPageBindingsFor(
  bindings: Map<string, FactPageBinding[]>,
  sourceId: string,
  slug: string,
): FactPageBinding[] {
  return bindings.get(refKey(sourceId, slug)) ?? [];
}
