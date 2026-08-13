import {
  chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, renameSync, unlinkSync,
  realpathSync, writeFileSync,
} from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import type { BrainEngine, TakeKind } from './engine.ts';
import { parseMarkdown, serializeMarkdown } from './markdown.ts';
import { parseTakesFence, upsertTakeRow } from './takes-fence.ts';
import { withPageLock } from './page-lock.ts';
import { ensureGbrainHome } from './gbrain-home.ts';

/**
 * Caller scope for the proposal review surface. Mirrors `sourceScopeOpts`
 * precedence (federated `sourceIds` array > scalar `sourceId` > nothing) plus
 * the D4 takes-holder allow-list: an MCP token restricted to certain holders
 * must not see — or act on — proposals for other holders. An empty
 * `holdersAllowList` array matches nothing (fail-closed), same as the
 * engine's `holder = ANY($allowList)` behavior.
 */
export interface ProposalScope {
  sourceId?: string;
  sourceIds?: string[];
  holdersAllowList?: string[];
}

function assertProposalInScope(
  row: Record<string, unknown>,
  scope: ProposalScope,
  proposalId: number,
): void {
  const sourceOk =
    scope.sourceIds && scope.sourceIds.length > 0
      ? scope.sourceIds.includes(String(row.source_id))
      : scope.sourceId
        ? String(row.source_id) === scope.sourceId
        : true;
  if (!sourceOk) {
    throw new Error(`take proposal ${proposalId} is outside your source scope`);
  }
  if (scope.holdersAllowList && !scope.holdersAllowList.includes(String(row.holder))) {
    throw new Error(`take proposal ${proposalId} is outside your holder allow-list`);
  }
}

/**
 * Proposal acceptance/rejection changes canonical knowledge. Unlike reads,
 * those writes must always name exactly one source. A federated read grant is
 * deliberately insufficient: callers must hold scalar write authority for
 * the proposal's source, and a future caller that forgets to thread scope
 * fails closed instead of gaining whole-brain write access.
 */
function assertProposalWriteScope(
  row: Record<string, unknown>,
  scope: ProposalScope,
  proposalId: number,
): void {
  if (!scope.sourceId || (scope.sourceIds && scope.sourceIds.length > 0)) {
    throw new Error(`take proposal ${proposalId} write requires one explicit source scope`);
  }
  assertProposalInScope(row, { sourceId: scope.sourceId, holdersAllowList: scope.holdersAllowList }, proposalId);
}

const PROPOSAL_STATUSES = ['pending', 'accepted', 'rejected', 'superseded'] as const;

export interface TakeProposalRow {
  id: number;
  source_id: string;
  page_slug: string;
  status: 'pending' | 'accepted' | 'rejected' | 'superseded';
  claim_text: string;
  kind: TakeKind;
  holder: string;
  weight: number;
  domain?: string | null;
  dedup_against_fence_rows?: unknown;
  model_id: string;
  proposed_at: string;
  acted_at?: string | null;
  acted_by?: string | null;
  promoted_row_num?: number | null;
  canonical_page_slug?: string | null;
  review_note?: string | null;
  predicted_brier?: number | null;
  predicted_brier_bucket_n?: number | null;
  effective_date?: string | null;
  effective_date_source?: string | null;
}

export interface TakeProposalAcceptResult {
  ok: true;
  proposal_id: number;
  source_page_slug: string;
  page_slug: string;
  row_num: number;
  status: 'accepted';
  idempotent: boolean;
  since_date?: string;
}

export interface TakeProposalRejectResult {
  ok: true;
  proposal_id: number;
  status: 'rejected';
  idempotent: boolean;
  reason?: string;
}

function isoOrNull(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function dateOnlyOrUndefined(value: unknown, source: unknown): string | undefined {
  if (value === null || value === undefined) return undefined;
  if (source === 'fallback') return undefined;
  if (value instanceof Date) return value.toISOString().slice(0, 10);
  const raw = String(value);
  return /^\d{4}-\d{2}-\d{2}/.test(raw) ? raw.slice(0, 10) : undefined;
}

function numberOrNull(value: unknown): number | null {
  if (value === null || value === undefined) return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function mapProposalRow(row: Record<string, unknown>): TakeProposalRow {
  return {
    id: Number(row.id),
    source_id: String(row.source_id),
    page_slug: String(row.page_slug),
    status: row.status as TakeProposalRow['status'],
    claim_text: String(row.claim_text),
    kind: String(row.kind) as TakeKind,
    holder: String(row.holder),
    weight: Number(row.weight),
    domain: row.domain === undefined ? null : row.domain as string | null,
    dedup_against_fence_rows: row.dedup_against_fence_rows,
    model_id: String(row.model_id),
    proposed_at: isoOrNull(row.proposed_at) ?? '',
    acted_at: isoOrNull(row.acted_at),
    acted_by: row.acted_by === undefined ? null : row.acted_by as string | null,
    promoted_row_num: numberOrNull(row.promoted_row_num),
    canonical_page_slug: row.canonical_page_slug === undefined ? null : row.canonical_page_slug as string | null,
    review_note: row.review_note === undefined ? null : row.review_note as string | null,
    predicted_brier: numberOrNull(row.predicted_brier),
    predicted_brier_bucket_n: numberOrNull(row.predicted_brier_bucket_n),
    effective_date: isoOrNull(row.effective_date),
    effective_date_source: row.effective_date_source === undefined ? null : row.effective_date_source as string | null,
  };
}

const CURATION_PREFIX = 'gbrain-curated/takes';

/**
 * A proposal's source page slug can change when a generator inserts lines
 * above a section. The proposal content hash does not: propose-takes hashes
 * compiled_truth, not the generated filename/frontmatter. Key the durable
 * curation page on (source, content hash), so ordinary source edits cannot
 * orphan an accepted take.
 */
export function proposalCurationSlug(sourceId: string, contentHash: string): string {
  const identity = createHash('sha256')
    .update(sourceId)
    .update('\0')
    .update(contentHash)
    .digest('hex')
    .slice(0, 24);
  return `${CURATION_PREFIX}/${identity}`;
}

function proposalFenceSource(
  proposalId: number,
  sourceId: string,
  sourcePageSlug: string,
  contentHash: string,
): string {
  return `proposal:${proposalId}; source=${sourceId}; page=${sourcePageSlug}; content_sha256=${contentHash}`;
}

function curationFrontmatter(
  sourceId: string,
  sourcePageSlug: string,
  contentHash: string,
): Record<string, unknown> {
  return {
    gbrain_curated: true,
    curation_kind: 'reviewed-take-proposals',
    origin_source_id: sourceId,
    origin_page_slug_at_creation: sourcePageSlug,
    origin_content_sha256: contentHash,
  };
}

function initialCurationBody(): string {
  return [
    '# Reviewed knowledge',
    '',
    'This page contains claims explicitly promoted from the GBrain proposal queue.',
    'The cited source page and content hash remain the evidence provenance.',
    '',
  ].join('\n');
}

function assertCurationFrontmatter(
  frontmatter: Record<string, unknown>,
  sourceId: string,
  contentHash: string,
): void {
  if (
    frontmatter.gbrain_curated !== true
    || frontmatter.curation_kind !== 'reviewed-take-proposals'
    || frontmatter.origin_source_id !== sourceId
    || frontmatter.origin_content_sha256 !== contentHash
  ) {
    throw new Error('curation page identity/provenance does not match the proposal');
  }
}

function git(repoPath: string, args: string[]): string {
  return execFileSync('git', ['-C', repoPath, ...args], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 30_000,
    env: { ...process.env, GIT_TERMINAL_PROMPT: '0' },
  }).trimEnd();
}

function curationPath(repoPath: string, slug: string): { path: string; relativePath: string } {
  const path = join(repoPath, `${slug}.md`);
  const root = resolve(repoPath);
  const resolved = resolve(path);
  if (!resolved.startsWith(root + sep)) {
    throw new Error('curation page resolves outside the curation ledger');
  }
  const relativePath = relative(root, resolved);
  if (!relativePath || isAbsolute(relativePath) || relativePath.startsWith(`..${sep}`)) {
    throw new Error('curation page has an invalid ledger-relative path');
  }
  return { path: resolved, relativePath };
}

interface CurationLedgerPaths {
  worktree: string;
  mirror: string;
}

function assertSafeDirectory(path: string, label: string): string {
  const resolved = resolve(path);
  if (!existsSync(resolved)) {
    throw new Error(`${label} is unavailable or unsafe`);
  }
  const metadata = lstatSync(resolved);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error(`${label} is unavailable or unsafe`);
  }
  return realpathSync(resolved);
}

function gitMaybe(repoPath: string, args: string[]): string | null {
  try {
    return git(repoPath, args);
  } catch {
    return null;
  }
}

function initBareMirror(path: string): string {
  if (!existsSync(path)) {
    mkdirSync(path, { recursive: true, mode: 0o700 });
    execFileSync('git', ['init', '--bare', '--quiet', '--initial-branch=main', path], {
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 30_000,
      env: { ...process.env, GIT_TERMINAL_PROMPT: '0' },
    });
  }
  const mirror = assertSafeDirectory(path, 'brain curation mirror');
  const bare = gitMaybe(mirror, ['rev-parse', '--is-bare-repository']);
  if (bare !== 'true') throw new Error('brain curation mirror is not a bare Git repository');
  try { chmodSync(mirror, 0o700); } catch { /* best effort */ }
  return mirror;
}

function initLedgerWorktree(path: string, mirror: string): string {
  if (!existsSync(path)) {
    mkdirSync(path, { recursive: true, mode: 0o700 });
    execFileSync('git', ['init', '--quiet', '--initial-branch=main', path], {
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 30_000,
      env: { ...process.env, GIT_TERMINAL_PROMPT: '0' },
    });
  }
  const worktree = assertSafeDirectory(path, 'brain curation ledger');
  const gitDir = join(worktree, '.git');
  if (!existsSync(gitDir)) throw new Error('brain curation ledger is not a Git repository');
  const gitMetadata = lstatSync(gitDir);
  if (!gitMetadata.isDirectory() || gitMetadata.isSymbolicLink()) {
    throw new Error('brain curation ledger Git metadata is unavailable or unsafe');
  }
  const top = realpathSync(git(worktree, ['rev-parse', '--show-toplevel']));
  if (top !== worktree) throw new Error('brain curation ledger must be its own Git worktree');
  const branch = gitMaybe(worktree, ['symbolic-ref', '--short', 'HEAD']);
  if (branch !== 'main') throw new Error('brain curation ledger must remain on branch main');
  git(worktree, ['config', 'user.name', 'GBrain Curation']);
  git(worktree, ['config', 'user.email', 'gbrain-curation@localhost']);
  const origin = gitMaybe(worktree, ['remote', 'get-url', 'origin']);
  if (origin === null) git(worktree, ['remote', 'add', 'origin', mirror]);
  else if (resolve(worktree, origin) !== mirror && resolve(origin) !== mirror) {
    throw new Error('brain curation ledger origin does not match its private mirror');
  }
  try { chmodSync(worktree, 0o700); } catch { /* best effort */ }
  return worktree;
}

function syncLedger(worktree: string, mirror: string): void {
  const dirty = git(worktree, ['status', '--porcelain=v1', '--untracked-files=all']);
  if (dirty) throw new Error('brain curation ledger has unexpected uncommitted changes');

  git(worktree, ['fetch', '--quiet', 'origin']);
  const local = gitMaybe(worktree, ['rev-parse', '--verify', 'HEAD']);
  const remote = gitMaybe(mirror, ['rev-parse', '--verify', 'refs/heads/main']);
  if (local === null && remote === null) return;
  if (local === null && remote !== null) {
    git(worktree, ['checkout', '--quiet', '-B', 'main', remote]);
    return;
  }
  if (local !== null && remote === null) {
    git(worktree, ['push', '--quiet', 'origin', 'HEAD:refs/heads/main']);
    return;
  }
  if (local === remote) return;

  const base = gitMaybe(worktree, ['merge-base', local!, remote!]);
  if (base === local) {
    git(worktree, ['merge', '--quiet', '--ff-only', remote!]);
    return;
  }
  if (base === remote) {
    git(worktree, ['push', '--quiet', 'origin', 'HEAD:refs/heads/main']);
    return;
  }
  throw new Error('brain curation ledger diverged from its private mirror');
}

function resolveCurationLedger(explicitPath?: string): CurationLedgerPaths {
  const worktreePath = explicitPath
    ? resolve(explicitPath)
    : join(ensureGbrainHome(), 'curation-ledger');
  const mirrorPath = `${worktreePath}.git`;
  const mirror = initBareMirror(mirrorPath);
  const worktree = initLedgerWorktree(worktreePath, mirror);
  syncLedger(worktree, mirror);
  return { worktree, mirror };
}

function committedBody(repoPath: string, relativePath: string): string | null {
  try {
    return execFileSync('git', ['-C', repoPath, 'show', `HEAD:${relativePath}`], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 30_000,
      env: { ...process.env, GIT_TERMINAL_PROMPT: '0' },
    });
  } catch {
    return null;
  }
}

/**
 * Markdown is canonical. Commit the exact curation artifact before stamping
 * the derived DB index. If the DB step later fails, retrying accept repairs it
 * from this committed page. If Git cannot prove durability, restore the path
 * and leave the proposal pending.
 */
function commitCurationPage(
  repoPath: string,
  mirrorPath: string,
  path: string,
  relativePath: string,
  body: string,
  proposalId: number,
): void {
  const status = git(repoPath, ['status', '--porcelain=v1', '--', relativePath]);
  if (status) {
    throw new Error(`curation path is already dirty: ${relativePath}`);
  }
  if (committedBody(repoPath, relativePath) === body) {
    git(repoPath, ['push', '--quiet', 'origin', 'HEAD:refs/heads/main']);
    const local = git(repoPath, ['rev-parse', 'HEAD']);
    const mirrored = git(mirrorPath, ['rev-parse', 'refs/heads/main']);
    if (local !== mirrored) throw new Error('brain curation mirror did not retain the committed page');
    return;
  }

  const original = existsSync(path) ? readFileSync(path, 'utf8') : null;
  const tempPath = `${path}.tmp.${process.pid}.${randomBytes(4).toString('hex')}`;
  mkdirSync(dirname(path), { recursive: true });
  try {
    writeFileSync(tempPath, body, 'utf8');
    renameSync(tempPath, path);
    git(repoPath, ['add', '--', relativePath]);
    git(repoPath, ['commit', '-m', `gbrain: accept take proposal ${proposalId}`, '--', relativePath]);
    if (committedBody(repoPath, relativePath) !== body) {
      throw new Error('Git commit did not preserve the exact curation page');
    }
    git(repoPath, ['push', '--quiet', 'origin', 'HEAD:refs/heads/main']);
    const local = git(repoPath, ['rev-parse', 'HEAD']);
    const mirrored = git(mirrorPath, ['rev-parse', 'refs/heads/main']);
    if (local !== mirrored) throw new Error('brain curation mirror did not retain the committed page');
  } catch (error) {
    // A post-commit hook can fail after Git has already advanced HEAD. If the
    // exact canonical bytes are present there, durability succeeded; do not
    // manufacture a dirty rollback against the new commit.
    if (committedBody(repoPath, relativePath) === body) {
      throw new Error(`proposal ${proposalId} is committed locally but its private mirror is not current: ${error instanceof Error ? error.message : String(error)}`);
    }
    try { git(repoPath, ['reset', '--quiet', 'HEAD', '--', relativePath]); } catch { /* preserve original error */ }
    if (original === null) {
      try { if (existsSync(path)) unlinkSync(path); } catch { /* preserve original error */ }
    } else {
      writeFileSync(path, original, 'utf8');
    }
    throw new Error(`could not durably commit proposal ${proposalId}: ${error instanceof Error ? error.message : String(error)}`);
  } finally {
    try { if (existsSync(tempPath)) unlinkSync(tempPath); } catch { /* best effort */ }
  }
}

async function mirrorCanonicalCurationToDb(
  engine: BrainEngine,
  proposalId: number,
  target: ProposalTargetRow,
  opts: ProposalScope,
  actedBy: string,
  curationSlug: string,
  relativePath: string,
  canonicalMarkdown: string,
  rowNum: number,
  provenance: string,
): Promise<TakeProposalAcceptResult> {
  const canonical = parseMarkdown(canonicalMarkdown, relativePath, {
    validate: true,
    expectedSlug: curationSlug,
  });
  if (canonical.errors && canonical.errors.length > 0) {
    throw new Error(`committed curation page is invalid: ${canonical.errors.map(error => error.code).join(', ')}`);
  }
  assertCurationFrontmatter(canonical.frontmatter, target.source_id, target.content_hash);
  const canonicalTake = parseTakesFence(canonical.compiled_truth).takes.find(
    row => row.rowNum === rowNum && row.source === provenance,
  );
  if (!canonicalTake || canonicalTake.claim !== target.claim_text) {
    throw new Error(`committed curation page lost proposal ${proposalId}`);
  }

  return engine.transaction(async (tx) => {
    const lockedRows = await tx.executeRaw<Record<string, unknown>>(
      `SELECT id, source_id, page_slug, content_hash, claim_text, kind,
              holder, weight, status, promoted_row_num
         FROM take_proposals
        WHERE id = $1
        FOR UPDATE`,
      [proposalId],
    );
    const locked = lockedRows[0];
    if (!locked) throw new Error(`take proposal not found: ${proposalId}`);
    assertProposalWriteScope(locked, opts, proposalId);
    if (
      String(locked.source_id) !== target.source_id
      || String(locked.content_hash) !== target.content_hash
      || String(locked.claim_text) !== canonicalTake.claim
    ) {
      throw new Error(`take proposal ${proposalId} changed before its DB index was stamped`);
    }
    const promotedRowNum = numberOrNull(locked.promoted_row_num);
    const alreadyAccepted = locked.status === 'accepted' && promotedRowNum === rowNum;
    if (!alreadyAccepted && locked.status !== 'pending') {
      throw new Error(`take proposal ${proposalId} is ${locked.status}; only pending proposals can be accepted`);
    }
    if (locked.status === 'accepted' && promotedRowNum !== rowNum) {
      throw new Error(`take proposal ${proposalId} points at an unexpected canonical row`);
    }

    const page = await tx.putPage(curationSlug, {
      type: canonical.type,
      title: canonical.title,
      compiled_truth: canonical.compiled_truth,
      timeline: canonical.timeline,
      frontmatter: canonical.frontmatter,
    }, { sourceId: target.source_id });

    const duplicates = await tx.executeRaw<{
      page_slug: string;
      row_num: number;
      source: string | null;
    }>(
      `SELECT p.slug AS page_slug, t.row_num, t.source
         FROM takes t
         JOIN pages p ON p.id = t.page_id
        WHERE p.source_id = $1
          AND t.active = true
          AND lower(trim(t.claim)) = lower(trim($2))
          AND NOT (
            p.slug = $3
            AND t.row_num = $4
            AND t.source = $5
          )
        ORDER BY t.id
        LIMIT 1`,
      [target.source_id, canonicalTake.claim, curationSlug, rowNum, provenance],
    );
    const duplicate = duplicates[0];
    if (duplicate) {
      throw new Error(
        `take proposal ${proposalId} duplicates existing take ${duplicate.page_slug}#${duplicate.row_num}`,
      );
    }

    await tx.addTakesBatch([{
      page_id: page.id,
      row_num: rowNum,
      claim: canonicalTake.claim,
      kind: canonicalTake.kind,
      holder: canonicalTake.holder,
      weight: canonicalTake.weight,
      since_date: canonicalTake.sinceDate,
      source: provenance,
      active: true,
      superseded_by: null,
    }]);

    if (!alreadyAccepted) {
      const stamped = await tx.executeRaw<{ promoted_row_num: number }>(
        `UPDATE take_proposals
            SET status = 'accepted',
                acted_at = now(),
                acted_by = $2,
                promoted_row_num = $3,
                canonical_page_slug = $4,
                review_note = NULL
          WHERE id = $1 AND status = 'pending'
          RETURNING promoted_row_num`,
        [proposalId, actedBy, rowNum, curationSlug],
      );
      if (stamped.length === 0) {
        throw new Error(`take proposal ${proposalId} was not stamped accepted`);
      }
    }

    return {
      ok: true,
      proposal_id: proposalId,
      source_page_slug: target.page_slug,
      page_slug: curationSlug,
      row_num: rowNum,
      status: 'accepted',
      idempotent: alreadyAccepted,
      since_date: canonicalTake.sinceDate,
    } satisfies TakeProposalAcceptResult;
  });
}

interface ProposalTargetRow {
  page_slug: string;
  source_id: string;
  content_hash: string;
  claim_text: string;
  holder: string;
  status: string;
  promoted_row_num: number | null;
  effective_date: unknown;
  effective_date_source: unknown;
}

async function lookupProposalTarget(engine: BrainEngine, proposalId: number): Promise<ProposalTargetRow> {
  const rows = await engine.executeRaw<ProposalTargetRow>(
    `SELECT tp.page_slug, tp.source_id, tp.content_hash, tp.claim_text,
            tp.holder, tp.status,
            tp.promoted_row_num,
            p.effective_date, p.effective_date_source
       FROM take_proposals tp
       LEFT JOIN pages p ON p.slug = tp.page_slug AND p.source_id = tp.source_id
      WHERE tp.id = $1
      LIMIT 1`,
    [proposalId],
  );
  const row = rows[0];
  if (!row) throw new Error(`take proposal not found: ${proposalId}`);
  return row;
}

export async function listTakeProposals(
  engine: BrainEngine,
  opts: {
    limit?: number;
    offset?: number;
    status?: TakeProposalRow['status'];
  } & ProposalScope = {},
): Promise<TakeProposalRow[]> {
  const limit = Math.max(1, Math.min(500, Math.floor(opts.limit ?? 50)));
  const offset = Math.max(0, Math.floor(opts.offset ?? 0));
  const status = opts.status ?? 'pending';
  if (!PROPOSAL_STATUSES.includes(status)) {
    throw new Error(`invalid proposal status '${status}'. Expected: ${PROPOSAL_STATUSES.join(' | ')}`);
  }
  const params: unknown[] = [status];
  const where: string[] = ['tp.status = $1'];
  if (opts.sourceIds && opts.sourceIds.length > 0) {
    params.push(opts.sourceIds);
    where.push(`tp.source_id = ANY($${params.length}::text[])`);
  } else if (opts.sourceId) {
    params.push(opts.sourceId);
    where.push(`tp.source_id = $${params.length}`);
  }
  if (opts.holdersAllowList) {
    params.push(opts.holdersAllowList);
    where.push(`tp.holder = ANY($${params.length}::text[])`);
  }
  params.push(limit, offset);
  const rows = await engine.executeRaw(
    `SELECT
       tp.id, tp.source_id, tp.page_slug, tp.status, tp.claim_text,
       tp.kind, tp.holder, tp.weight, tp.domain, tp.dedup_against_fence_rows,
       tp.model_id, tp.proposed_at, tp.acted_at, tp.acted_by,
       tp.promoted_row_num, tp.canonical_page_slug, tp.review_note,
       tp.predicted_brier, tp.predicted_brier_bucket_n,
       p.effective_date, p.effective_date_source
     FROM take_proposals tp
     LEFT JOIN pages p ON p.slug = tp.page_slug AND p.source_id = tp.source_id
     WHERE ${where.join(' AND ')}
     ORDER BY
       CASE WHEN tp.predicted_brier IS NULL THEN 1 ELSE 0 END,
       tp.predicted_brier ASC NULLS LAST,
       tp.proposed_at DESC
     LIMIT $${params.length - 1} OFFSET $${params.length}`,
    params,
  );
  return rows.map((r) => mapProposalRow(r as Record<string, unknown>));
}

export async function acceptTakeProposal(
  engine: BrainEngine,
  proposalId: number,
  opts: { actedBy?: string; curationLedgerPath?: string } & ProposalScope = {},
): Promise<TakeProposalAcceptResult> {
  const target = await lookupProposalTarget(engine, proposalId);
  assertProposalWriteScope(target as unknown as Record<string, unknown>, opts, proposalId);
  if (!/^[a-f0-9]{64}$/i.test(target.content_hash)) {
    throw new Error(`take proposal ${proposalId} has an invalid content hash`);
  }
  const actedBy = opts.actedBy ?? 'gbrain-cli';
  const curationSlug = proposalCurationSlug(target.source_id, target.content_hash);
  const claimLock = `take-proposal-claim/${target.source_id}/${createHash('sha256')
    .update(target.claim_text.trim().toLowerCase())
    .digest('hex')}`;
  const provenance = proposalFenceSource(
    proposalId,
    target.source_id,
    target.page_slug,
    target.content_hash,
  );

  return withPageLock('take-proposal-curation-ledger', () =>
    withPageLock(claimLock, () => withPageLock(curationSlug, async () => {
    const ledger = resolveCurationLedger(opts.curationLedgerPath);
    const sourcePath = curationPath(ledger.worktree, curationSlug);
    const relativePath = relative(ledger.worktree, sourcePath.path);
    if (!relativePath || isAbsolute(relativePath) || relativePath.startsWith(`..${sep}`)) {
      throw new Error('curation page resolves outside the brain curation ledger');
    }
    const originalMarkdown = committedBody(ledger.worktree, relativePath);

    let frontmatter: Record<string, unknown>;
    let compiledTruth: string;
    let timeline = '';
    let pageType: ReturnType<typeof parseMarkdown>['type'] = 'concept';
    let title = `Reviewed knowledge — ${target.source_id}`;
    let tags: string[] = [];
    if (originalMarkdown === null) {
      frontmatter = curationFrontmatter(target.source_id, target.page_slug, target.content_hash);
      compiledTruth = initialCurationBody();
    } else {
      const parsed = parseMarkdown(originalMarkdown, relativePath, { validate: true, expectedSlug: curationSlug });
      if (parsed.errors && parsed.errors.length > 0) {
        throw new Error(`curation page is invalid: ${parsed.errors.map(error => error.code).join(', ')}`);
      }
      assertCurationFrontmatter(parsed.frontmatter, target.source_id, target.content_hash);
      frontmatter = parsed.frontmatter;
      compiledTruth = parsed.compiled_truth;
      timeline = parsed.timeline;
      pageType = parsed.type;
      title = parsed.title;
      tags = parsed.tags;
    }

    const proposalRows = await engine.executeRaw<Record<string, unknown>>(
      `SELECT claim_text, kind, holder, weight, status, promoted_row_num,
              source_id, page_slug, content_hash
         FROM take_proposals
        WHERE id = $1
        LIMIT 1`,
      [proposalId],
    );
    const proposal = proposalRows[0];
    if (!proposal) throw new Error(`take proposal not found: ${proposalId}`);
    assertProposalWriteScope(proposal, opts, proposalId);
    if (
      String(proposal.source_id) !== target.source_id
      || String(proposal.content_hash) !== target.content_hash
    ) {
      throw new Error(`take proposal ${proposalId} changed while acceptance was being prepared`);
    }
    if (proposal.status !== 'pending' && proposal.status !== 'accepted') {
      throw new Error(`take proposal ${proposalId} is ${proposal.status}; only pending proposals can be accepted`);
    }

    // Serialize same-claim acceptances with claimLock and reject before any
    // Git write. The repeat inside the DB transaction protects against
    // non-cooperating writers that bypass this helper.
    const preexistingDuplicates = await engine.executeRaw<{
      page_slug: string;
      row_num: number;
      source: string | null;
    }>(
      `SELECT p.slug AS page_slug, t.row_num, t.source
         FROM takes t
         JOIN pages p ON p.id = t.page_id
        WHERE p.source_id = $1
          AND t.active = true
          AND lower(trim(t.claim)) = lower(trim($2))
          AND NOT (p.slug = $3 AND t.source = $4)
        ORDER BY t.id
        LIMIT 1`,
      [target.source_id, proposal.claim_text, curationSlug, provenance],
    );
    const preexistingDuplicate = preexistingDuplicates[0];
    if (preexistingDuplicate) {
      throw new Error(
        `take proposal ${proposalId} duplicates existing take ${preexistingDuplicate.page_slug}#${preexistingDuplicate.row_num}`,
      );
    }

    const existingFenceRow = parseTakesFence(compiledTruth).takes.find(
      row => row.source === provenance,
    );
    let rowNum: number;
    if (existingFenceRow) {
      if (
        existingFenceRow.claim !== String(proposal.claim_text)
        || existingFenceRow.kind !== String(proposal.kind)
        || existingFenceRow.holder !== String(proposal.holder)
      ) {
        throw new Error(`curation page row for proposal ${proposalId} does not match the proposal`);
      }
      rowNum = existingFenceRow.rowNum;
    } else {
      const appended = upsertTakeRow(compiledTruth, {
        claim: String(proposal.claim_text),
        kind: String(proposal.kind),
        holder: String(proposal.holder),
        weight: Number(proposal.weight),
        source: provenance,
        sinceDate: dateOnlyOrUndefined(target.effective_date, target.effective_date_source),
        active: true,
      });
      compiledTruth = appended.body;
      rowNum = appended.rowNum;
    }

    const markdown = serializeMarkdown(frontmatter, compiledTruth, timeline, {
      type: pageType,
      title,
      tags,
    });
    commitCurationPage(
      ledger.worktree,
      ledger.mirror,
      sourcePath.path,
      relativePath,
      markdown,
      proposalId,
    );

    // Re-parse what Git actually committed. This is the canonical input to the
    // derived DB page/take rows; never index a pre-commit in-memory variant.
    const canonicalMarkdown = committedBody(ledger.worktree, relativePath);
    if (canonicalMarkdown === null) {
      throw new Error(`proposal ${proposalId} curation page is not committed`);
    }
    return mirrorCanonicalCurationToDb(
      engine,
      proposalId,
      target,
      opts,
      actedBy,
      curationSlug,
      relativePath,
      canonicalMarkdown,
      rowNum,
      provenance,
    );
    })));
}

export interface TakeProposalRepairResult {
  scanned: number;
  repaired: number;
  failed: Array<{ proposal_id: number; error: string }>;
}

/**
 * Rebuild derived DB pages/takes for accepted proposals from the private Git
 * ledger. Safe to run at startup or after recovery: no inference, no source
 * writes, and idempotent when the mirror is already current.
 */
export async function repairAcceptedTakeProposals(
  engine: BrainEngine,
  opts: { actedBy?: string; curationLedgerPath?: string } & ProposalScope,
): Promise<TakeProposalRepairResult> {
  if (!opts.sourceId || (opts.sourceIds && opts.sourceIds.length > 0)) {
    throw new Error('accepted proposal repair requires one explicit source scope');
  }
  const ledger = resolveCurationLedger(opts.curationLedgerPath);
  const rows = await engine.executeRaw<ProposalTargetRow & { id: number; canonical_page_slug: string }>(
    `SELECT tp.id, tp.page_slug, tp.source_id, tp.content_hash, tp.claim_text,
            tp.holder, tp.status, tp.promoted_row_num, tp.canonical_page_slug,
            p.effective_date, p.effective_date_source
       FROM take_proposals tp
       LEFT JOIN pages p ON p.slug = tp.page_slug AND p.source_id = tp.source_id
      WHERE tp.status = 'accepted'
        AND tp.source_id = $1
        AND tp.promoted_row_num IS NOT NULL
        AND tp.canonical_page_slug IS NOT NULL
      ORDER BY tp.id`,
    [opts.sourceId],
  );
  const result: TakeProposalRepairResult = { scanned: rows.length, repaired: 0, failed: [] };
  for (const row of rows) {
    const proposalId = Number(row.id);
    try {
      assertProposalWriteScope(row as unknown as Record<string, unknown>, opts, proposalId);
      const expectedSlug = proposalCurationSlug(row.source_id, row.content_hash);
      if (row.canonical_page_slug !== expectedSlug) {
        throw new Error(`proposal ${proposalId} canonical slug does not match its content identity`);
      }
      const sourcePath = curationPath(ledger.worktree, expectedSlug);
      const relativePath = relative(ledger.worktree, sourcePath.path);
      const canonicalMarkdown = committedBody(ledger.worktree, relativePath);
      if (canonicalMarkdown === null) {
        throw new Error(`proposal ${proposalId} is accepted but missing from the private curation ledger`);
      }
      await mirrorCanonicalCurationToDb(
        engine,
        proposalId,
        row,
        opts,
        opts.actedBy ?? 'gbrain-repair',
        expectedSlug,
        relativePath,
        canonicalMarkdown,
        Number(row.promoted_row_num),
        proposalFenceSource(proposalId, row.source_id, row.page_slug, row.content_hash),
      );
      result.repaired++;
    } catch (error) {
      result.failed.push({
        proposal_id: proposalId,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }
  return result;
}

export async function rejectTakeProposal(
  engine: BrainEngine,
  proposalId: number,
  opts: { actedBy?: string; reason?: string } & ProposalScope = {},
): Promise<TakeProposalRejectResult> {
  const actedBy = opts.actedBy ?? 'gbrain-cli';
  return engine.transaction(async (tx) => {
    const rows = await tx.executeRaw<Record<string, unknown>>(
      `SELECT id, source_id, holder, status, promoted_row_num
       FROM take_proposals WHERE id = $1
       FOR UPDATE`,
      [proposalId],
    );
    const row = rows[0];
    if (!row) throw new Error(`take proposal not found: ${proposalId}`);
    assertProposalWriteScope(row, opts, proposalId);
    if (row.status === 'rejected') {
      return { ok: true, proposal_id: proposalId, status: 'rejected', idempotent: true, reason: opts.reason };
    }
    if (row.status === 'accepted' || numberOrNull(row.promoted_row_num) !== null) {
      throw new Error(`take proposal ${proposalId} is already accepted and cannot be rejected`);
    }
    await tx.executeRaw(
      `UPDATE take_proposals
       SET status = 'rejected',
           acted_at = now(),
           acted_by = $2,
           review_note = $3
       WHERE id = $1`,
      [proposalId, actedBy, opts.reason ?? null],
    );
    return { ok: true, proposal_id: proposalId, status: 'rejected', idempotent: false, reason: opts.reason };
  });
}
