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

interface FactBindingRow {
  ref_source_id: string;
  ref_slug: string;
  fact_id: number | string;
  capture_page_slug: string;
  hermes_session_ref: string;
  matched_via: 'capture_page' | 'entity_fence';
}

function refKey(sourceId: string, slug: string): string {
  return `${sourceId}\u0000${slug}`;
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
