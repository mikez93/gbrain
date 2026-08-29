import type { BrainEngine } from '../engine.ts';
import type { SearchResult } from '../types.ts';
import type { DispositionScope } from './model.ts';

export function dispositionVisibilityClause(
  pageAlias: string,
  scope: DispositionScope = 'competing',
): string {
  if (scope === 'curation') return '';
  return ` AND NOT EXISTS (
    SELECT 1 FROM page_dispositions visible_disposition
    WHERE visible_disposition.page_id = ${pageAlias}.id
      AND visible_disposition.state IN ('superseded', 'quarantined')
  )`;
}

export async function readDispositionGeneration(engine: BrainEngine): Promise<number> {
  try {
    const rows = await engine.executeRaw<{ generation: number }>(
      `SELECT generation FROM page_disposition_state WHERE id = 1`,
    );
    return Number(rows[0]?.generation ?? 0);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (/page_disposition_state|relation .* does not exist|no such table/i.test(message)) return 0;
    throw err;
  }
}

export async function pageCompetes(
  engine: BrainEngine,
  sourceId: string,
  slug: string,
  scope: DispositionScope = 'competing',
): Promise<boolean> {
  if (scope === 'curation') return true;
  try {
    const rows = await engine.executeRaw<{ state: string | null }>(
      `SELECT d.state
       FROM pages p
       LEFT JOIN page_dispositions d ON d.page_id = p.id
       WHERE p.source_id = $1 AND p.slug = $2 AND p.deleted_at IS NULL
       LIMIT 1`,
      [sourceId, slug],
    );
    return rows.length > 0 && (rows[0]!.state == null || rows[0]!.state === 'canonical');
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (/page_dispositions|relation .* does not exist|no such table/i.test(message)) return true;
    throw err;
  }
}

export async function stampPageDispositions(
  engine: BrainEngine,
  results: SearchResult[],
): Promise<void> {
  if (results.length === 0) return;
  const pageIds = Array.from(new Set(results.map(result => result.page_id).filter(Number.isFinite)));
  const byPage = new Map<number, SearchResult['disposition']>();
  try {
    const rows = await engine.executeRaw<Record<string, unknown>>(
      `SELECT p.id AS page_id, d.state, d.duplicate_set_id, d.last_event_id,
              cp.source_id AS canonical_source_id, cp.slug AS canonical_slug
       FROM pages p
       LEFT JOIN page_dispositions d ON d.page_id = p.id
       LEFT JOIN pages cp ON cp.id = d.canonical_page_id
       WHERE p.id = ANY($1::int[])`,
      [pageIds],
    );
    for (const row of rows) {
      const state = row.state == null
        ? 'undispositioned'
        : String(row.state) as 'canonical' | 'superseded' | 'quarantined';
      byPage.set(Number(row.page_id), {
        state,
        duplicate_set_id: row.duplicate_set_id == null ? null : String(row.duplicate_set_id),
        canonical: row.canonical_source_id == null ? null : {
          source_id: String(row.canonical_source_id),
          slug: String(row.canonical_slug),
        },
        last_event_id: row.last_event_id == null ? null : Number(row.last_event_id),
      });
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (!/page_dispositions|relation .* does not exist|no such table/i.test(message)) throw err;
  }
  for (const result of results) {
    result.disposition = byPage.get(result.page_id) ?? {
      state: 'undispositioned',
      duplicate_set_id: null,
      canonical: null,
      last_event_id: null,
    };
  }
}
