/**
 * Review-first take proposal lifecycle (#2269, takeover of PR #2418):
 * list / accept / reject over the shared operation registry, plus the
 * source-isolation + holder-allow-list repairs.
 *
 * Real PGLite engine (in-memory, no DATABASE_URL) so the SQL shapes
 * (FOR UPDATE OF, pg_advisory_xact_lock, ANY($::text[])) run for real.
 */
import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { PGLiteEngine } from '../src/core/pglite-engine.ts';
import type { BrainEngine } from '../src/core/engine.ts';
import { dispatchToolCall } from '../src/mcp/dispatch.ts';
import { operations } from '../src/core/operations.ts';
import { buildToolDefs } from '../src/mcp/tool-defs.ts';
import {
  acceptTakeProposal,
  listTakeProposals,
  proposalCurationSlug,
  rejectTakeProposal,
} from '../src/core/take-proposals.ts';

let engine: PGLiteEngine;
let brainDir: string;
const sourceDirs = new Map<string, string>();

function git(repo: string, ...args: string[]): string {
  return execFileSync('git', ['-C', repo, ...args], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trim();
}

function initSourceRepo(id: string): string {
  const repo = join(brainDir, id);
  mkdirSync(repo, { recursive: true });
  git(repo, 'init', '--quiet');
  git(repo, 'config', 'user.name', 'GBrain Test');
  git(repo, 'config', 'user.email', 'gbrain-test@localhost');
  writeFileSync(join(repo, 'README.md'), `# ${id}\n`, 'utf8');
  git(repo, 'add', '--', 'README.md');
  git(repo, 'commit', '--quiet', '-m', 'test source baseline');
  sourceDirs.set(id, repo);
  return repo;
}

function initNestedSourceRepo(id: string): { repo: string; sourceRoot: string } {
  const repo = join(brainDir, `${id}-parent`);
  const sourceRoot = join(repo, 'brain-pages');
  mkdirSync(sourceRoot, { recursive: true });
  git(repo, 'init', '--quiet');
  git(repo, 'config', 'user.name', 'GBrain Test');
  git(repo, 'config', 'user.email', 'gbrain-test@localhost');
  writeFileSync(join(repo, 'README.md'), `# ${id}\n`, 'utf8');
  git(repo, 'add', '--', 'README.md');
  git(repo, 'commit', '--quiet', '-m', 'test nested source baseline');
  sourceDirs.set(id, sourceRoot);
  return { repo, sourceRoot };
}

async function addSource(id: string, localPath: string): Promise<void> {
  await engine.executeRaw(
    `INSERT INTO sources (id, name, local_path, config, created_at)
     VALUES ($1, $1, $2, '{}'::jsonb, NOW()) ON CONFLICT (id) DO NOTHING`,
    [id, localPath],
  );
}

async function insertProposal(p: {
  source_id: string;
  page_slug: string;
  claim: string;
  holder?: string;
  kind?: string;
  weight?: number;
  content_hash?: string;
}): Promise<number> {
  const hash = p.content_hash ?? createHash('sha256')
    .update(`${p.source_id}\0${p.page_slug}\0${p.claim}\0${randomUUID()}`)
    .digest('hex');
  const rows = await engine.executeRaw<{ id: number }>(
    `INSERT INTO take_proposals
       (source_id, page_slug, content_hash, prompt_version, proposal_run_id,
        claim_text, kind, holder, weight, model_id)
     VALUES ($1, $2, $7, 'v1', 'run-test', $6, $3, $4, $5, 'test-model')
     RETURNING id`,
    [p.source_id, p.page_slug, p.kind ?? 'take', p.holder ?? 'garry', p.weight ?? 0.7, p.claim, hash],
  );
  return Number(rows[0].id);
}

function writePage(sourceId: string, slug: string, body = '# Page\n'): string {
  const repo = sourceDirs.get(sourceId);
  if (!repo) throw new Error(`test source is not initialized: ${sourceId}`);
  const path = join(repo, `${slug}.md`);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, body, 'utf-8');
  const relativePath = `${slug}.md`;
  git(repo, 'add', '--', relativePath);
  git(repo, 'commit', '--quiet', '-m', `test source page ${slug}`, '--', relativePath);
  return path;
}

beforeAll(async () => {
  brainDir = mkdtempSync(join(tmpdir(), 'gbrain-take-proposals-'));
  engine = new PGLiteEngine();
  await engine.connect({});
  await engine.initSchema();
  await addSource('tenant-a', initSourceRepo('tenant-a'));
  await addSource('tenant-b', initSourceRepo('tenant-b'));
  writePage('tenant-a', 'topics/a', '# A\n\nBody\n');
  writePage('tenant-b', 'topics/b', '# B\n\nBody\n');
  await engine.putPage('topics/a', { title: 'A', type: 'concept', compiled_truth: 'Body' }, { sourceId: 'tenant-a' });
  await engine.putPage('topics/b', { title: 'B', type: 'concept', compiled_truth: 'Body' }, { sourceId: 'tenant-b' });
  // Real content date on topics/a so accept threads since_date.
  await engine.executeRaw(
    `UPDATE pages SET effective_date = '2024-03-02', effective_date_source = 'frontmatter' WHERE slug = 'topics/a'`,
  );
}, 30000);

afterAll(async () => {
  await engine.disconnect();
  rmSync(brainDir, { recursive: true, force: true });
});

describe('listTakeProposals — scope isolation', () => {
  let idA: number;
  let idB: number;
  let idWorld: number;

  beforeAll(async () => {
    idA = await insertProposal({ source_id: 'tenant-a', page_slug: 'topics/a', claim: 'A will happen', holder: 'garry' });
    idB = await insertProposal({ source_id: 'tenant-b', page_slug: 'topics/b', claim: 'B will happen', holder: 'garry' });
    idWorld = await insertProposal({ source_id: 'tenant-a', page_slug: 'topics/a', claim: 'Public claim', holder: 'world' });
  });

  test('unscoped (trusted local) sees all pending proposals', async () => {
    const rows = await listTakeProposals(engine);
    const ids = rows.map(r => r.id);
    expect(ids).toContain(idA);
    expect(ids).toContain(idB);
    expect(ids).toContain(idWorld);
  });

  test('scalar sourceId filters to that source', async () => {
    const rows = await listTakeProposals(engine, { sourceId: 'tenant-b' });
    expect(rows.map(r => r.id)).toEqual([idB]);
  });

  test('federated sourceIds array filters to the grant', async () => {
    const rows = await listTakeProposals(engine, { sourceIds: ['tenant-a'] });
    const ids = rows.map(r => r.id).sort();
    expect(ids).toEqual([idA, idWorld].sort());
  });

  test('holdersAllowList hides other holders; empty list matches nothing', async () => {
    const world = await listTakeProposals(engine, { holdersAllowList: ['world'] });
    expect(world.map(r => r.id)).toEqual([idWorld]);
    expect(await listTakeProposals(engine, { holdersAllowList: [] })).toEqual([]);
  });

  test('invalid status is rejected', async () => {
    await expect(listTakeProposals(engine, { status: 'garbage' as never })).rejects.toThrow('invalid proposal status');
  });

  test('takes_propose_list op threads source scope + holder allow-list (remote)', async () => {
    const result = await dispatchToolCall(engine, 'takes_propose_list', {}, {
      remote: true,
      sourceId: 'tenant-a',
      takesHoldersAllowList: ['world'],
    });
    expect(result.isError).toBeFalsy();
    const rows = JSON.parse(result.content[0].text) as Array<{ id: number; holder: string; source_id: string }>;
    expect(rows.map(r => r.id)).toEqual([idWorld]);
  });

  test('list surfaces page effective-date metadata', async () => {
    const rows = await listTakeProposals(engine, { sourceIds: ['tenant-a'] });
    const a = rows.find(r => r.id === idA)!;
    expect(a.effective_date).toContain('2024-03-02');
    expect(a.effective_date_source).toBe('frontmatter');
  });
});

describe('acceptTakeProposal', () => {
  test('promotes into a durable curation page, mirrors DB, stamps proposal; idempotent re-accept', async () => {
    const sourcePagePath = join(sourceDirs.get('tenant-a')!, 'topics/a.md');
    const id = await insertProposal({ source_id: 'tenant-a', page_slug: 'topics/a', claim: 'Promote me', holder: 'garry' });

    const result = await acceptTakeProposal(engine, id, { actedBy: 'test' });
    expect(result).toMatchObject({
      ok: true,
      proposal_id: id,
      source_page_slug: 'topics/a',
      status: 'accepted',
      idempotent: false,
      since_date: '2024-03-02',
    });
    expect(result.page_slug).toStartWith('gbrain-curated/takes/');

    const curationPath = join(sourceDirs.get('tenant-a')!, `${result.page_slug}.md`);
    const body = readFileSync(curationPath, 'utf-8');
    expect(body).toContain('Promote me');
    expect(body).toContain(`proposal:${id}`);
    expect(body).toContain('origin_source_id: tenant-a');
    expect(readFileSync(sourcePagePath, 'utf8')).not.toContain('Promote me');
    expect(git(sourceDirs.get('tenant-a')!, 'show', `HEAD:${result.page_slug}.md`)).toContain('Promote me');

    const takes = await engine.listTakes({ page_slug: result.page_slug, sourceId: 'tenant-a' });
    const promoted = takes.find(t => t.claim === 'Promote me')!;
    expect(promoted).toBeDefined();
    expect(promoted.row_num).toBe(result.row_num);
    expect(promoted.since_date).toContain('2024-03-02');

    const [stamped] = await engine.executeRaw<{
      status: string;
      acted_by: string;
      promoted_row_num: number;
      canonical_page_slug: string;
    }>(
      `SELECT status, acted_by, promoted_row_num, canonical_page_slug
         FROM take_proposals WHERE id = $1`, [id],
    );
    expect(stamped).toMatchObject({
      status: 'accepted',
      acted_by: 'test',
      canonical_page_slug: result.page_slug,
    });
    expect(Number(stamped.promoted_row_num)).toBe(result.row_num);

    const again = await acceptTakeProposal(engine, id, { actedBy: 'test' });
    expect(again).toMatchObject({ ok: true, idempotent: true, row_num: result.row_num });
  });

  test('refuses out-of-scope source and out-of-allow-list holder', async () => {
    const id = await insertProposal({ source_id: 'tenant-a', page_slug: 'topics/a', claim: 'Scoped claim', holder: 'garry' });
    await expect(acceptTakeProposal(engine, id, { sourceIds: ['tenant-b'] })).rejects.toThrow('outside your source scope');
    await expect(acceptTakeProposal(engine, id, { sourceId: 'tenant-b' })).rejects.toThrow('outside your source scope');
    await expect(acceptTakeProposal(engine, id, { holdersAllowList: ['world'] })).rejects.toThrow('outside your holder allow-list');
    const [row] = await engine.executeRaw<{ status: string }>(`SELECT status FROM take_proposals WHERE id = $1`, [id]);
    expect(row.status).toBe('pending');
  });

  test('refuses a duplicate of an existing active take', async () => {
    const id = await insertProposal({ source_id: 'tenant-a', page_slug: 'topics/a', claim: '  PROMOTE ME  ', holder: 'garry' });
    await expect(acceptTakeProposal(engine, id)).rejects.toThrow('duplicates existing take');
  });

  test('a DB mirror failure leaves canonical Git knowledge recoverable on retry', async () => {
    writePage('tenant-a', 'topics/a-rollback', '# Rollback\n');
    await engine.putPage('topics/a-rollback', { title: 'R', type: 'concept', compiled_truth: 'Body' }, { sourceId: 'tenant-a' });
    const id = await insertProposal({ source_id: 'tenant-a', page_slug: 'topics/a-rollback', claim: 'Should not persist', holder: 'garry' });
    const [{ content_hash: contentHash }] = await engine.executeRaw<{ content_hash: string }>(
      `SELECT content_hash FROM take_proposals WHERE id = $1`, [id],
    );
    const curationSlug = proposalCurationSlug('tenant-a', contentHash);
    const curationPath = join(sourceDirs.get('tenant-a')!, `${curationSlug}.md`);

    // Wrap the real engine: same transaction machinery, injected batch failure.
    const failing = Object.create(engine) as BrainEngine;
    failing.transaction = <T>(fn: (tx: BrainEngine) => Promise<T>) =>
      engine.transaction((tx) => {
        const failingTx = Object.create(tx) as BrainEngine;
        failingTx.addTakesBatch = async () => { throw new Error('injected addTakesBatch failure'); };
        return fn(failingTx);
      });

    await expect(acceptTakeProposal(failing, id)).rejects.toThrow('injected addTakesBatch failure');
    expect(readFileSync(curationPath, 'utf-8')).toContain('Should not persist');
    expect(git(sourceDirs.get('tenant-a')!, 'show', `HEAD:${curationSlug}.md`)).toContain('Should not persist');
    const [row] = await engine.executeRaw<{ status: string; promoted_row_num: number | null }>(
      `SELECT status, promoted_row_num FROM take_proposals WHERE id = $1`, [id],
    );
    expect(row.status).toBe('pending');
    expect(row.promoted_row_num).toBeNull();

    const repaired = await acceptTakeProposal(engine, id, { actedBy: 'repair-test' });
    expect(repaired).toMatchObject({ page_slug: curationSlug, idempotent: false, status: 'accepted' });
    expect((await engine.listTakes({ page_slug: curationSlug, sourceId: 'tenant-a' })).map(t => t.claim))
      .toContain('Should not persist');
  });

  test('accept without a real content date leaves since_date unset', async () => {
    const id = await insertProposal({ source_id: 'tenant-b', page_slug: 'topics/b', claim: 'No date here', holder: 'garry' });
    const result = await acceptTakeProposal(engine, id);
    expect(result.since_date).toBeUndefined();
  });

  test('accepted knowledge survives a managed-page identity shift after an edit above its section', async () => {
    const contentHash = createHash('sha256').update('stable section body').digest('hex');
    const oldSlug = 'managed/hash-before-memory-1';
    const newSlug = 'managed/hash-after-memory-1';
    writePage('tenant-a', oldSlug, '# Prior heading\n\nStable section body\n');
    await engine.putPage(oldSlug, {
      title: 'Stable section', type: 'concept', compiled_truth: 'stable section body',
    }, { sourceId: 'tenant-a' });
    const id = await insertProposal({
      source_id: 'tenant-a', page_slug: oldSlug, claim: 'Durable across regeneration',
      holder: 'garry', content_hash: contentHash,
    });
    const accepted = await acceptTakeProposal(engine, id, { actedBy: 'test' });
    const canonicalBefore = git(
      sourceDirs.get('tenant-a')!, 'show', `HEAD:${accepted.page_slug}.md`,
    );

    // Simulate the real failure mechanism: an insertion above the section
    // changes start_line, so the generator replaces the old hashed filename.
    const repo = sourceDirs.get('tenant-a')!;
    rmSync(join(repo, `${oldSlug}.md`));
    const newPath = join(repo, `${newSlug}.md`);
    mkdirSync(dirname(newPath), { recursive: true });
    writeFileSync(newPath, '# Inserted heading\n\n# Prior heading\n\nStable section body\n', 'utf8');
    git(repo, 'add', '-A', '--', 'managed');
    git(repo, 'commit', '--quiet', '-m', 'regenerate after line insertion', '--', 'managed');
    await engine.deletePage(oldSlug, { sourceId: 'tenant-a' });
    await engine.putPage(newSlug, {
      title: 'Stable section', type: 'concept', compiled_truth: 'stable section body',
    }, { sourceId: 'tenant-a' });

    expect(git(repo, 'show', `HEAD:${accepted.page_slug}.md`)).toBe(canonicalBefore);
    const takes = await engine.listTakes({ page_slug: accepted.page_slug, sourceId: 'tenant-a' });
    expect(takes.map(t => t.claim)).toContain('Durable across regeneration');
    const [proposal] = await engine.executeRaw<{ status: string; promoted_row_num: number }>(
      `SELECT status, promoted_row_num FROM take_proposals WHERE id = $1`, [id],
    );
    expect(proposal.status).toBe('accepted');
    expect(Number(proposal.promoted_row_num)).toBe(accepted.row_num);
  });

  test('commits correctly when a source local_path is nested under its Git worktree', async () => {
    const sourceId = 'tenant-nested';
    const { repo, sourceRoot } = initNestedSourceRepo(sourceId);
    await addSource(sourceId, sourceRoot);
    writePage(sourceId, 'topics/nested', '# Nested\n\nBody\n');
    await engine.putPage('topics/nested', {
      title: 'Nested', type: 'concept', compiled_truth: 'Body',
    }, { sourceId });
    const id = await insertProposal({
      source_id: sourceId,
      page_slug: 'topics/nested',
      claim: 'Nested source roots are supported',
    });

    const result = await acceptTakeProposal(engine, id);
    const repoRelativePath = `brain-pages/${result.page_slug}.md`;
    expect(git(repo, 'show', `HEAD:${repoRelativePath}`)).toContain('Nested source roots are supported');
    expect(readFileSync(join(sourceRoot, `${result.page_slug}.md`), 'utf8'))
      .toContain('Nested source roots are supported');
  });
});

describe('rejectTakeProposal', () => {
  test('stamps pending → rejected; idempotent; refuses accepted; enforces scope', async () => {
    const id = await insertProposal({ source_id: 'tenant-a', page_slug: 'topics/a', claim: 'Reject me', holder: 'garry' });

    await expect(rejectTakeProposal(engine, id, { sourceId: 'tenant-b' })).rejects.toThrow('outside your source scope');
    await expect(rejectTakeProposal(engine, id, { holdersAllowList: ['world'] })).rejects.toThrow('outside your holder allow-list');

    const first = await rejectTakeProposal(engine, id, { actedBy: 'reviewer', reason: 'not supported' });
    expect(first).toEqual({ ok: true, proposal_id: id, status: 'rejected', idempotent: false, reason: 'not supported' });
    const [row] = await engine.executeRaw<{ status: string; acted_by: string; review_note: string }>(
      `SELECT status, acted_by, review_note FROM take_proposals WHERE id = $1`, [id],
    );
    expect(row).toMatchObject({
      status: 'rejected',
      acted_by: 'reviewer',
      review_note: 'not supported',
    });

    const second = await rejectTakeProposal(engine, id, { actedBy: 'reviewer' });
    expect(second.idempotent).toBe(true);

    const acceptedId = await insertProposal({ source_id: 'tenant-a', page_slug: 'topics/a', claim: 'Accepted already', holder: 'garry' });
    await acceptTakeProposal(engine, acceptedId);
    await expect(rejectTakeProposal(engine, acceptedId)).rejects.toThrow('already accepted');
  });
});

describe('take proposal MCP operation schema', () => {
  test('exposes list/accept/reject through the shared operation registry with correct scopes', () => {
    const byName = Object.fromEntries(operations.map((op) => [op.name, op]));
    expect(byName.takes_propose_list?.scope).toBe('read');
    expect(byName.takes_propose_accept?.scope).toBe('write');
    expect(byName.takes_propose_reject?.scope).toBe('write');
    expect(byName.takes_propose_accept.params.proposal_id.required).toBe(true);
    expect(byName.takes_propose_reject.params.proposal_id.required).toBe(true);

    const defs = Object.fromEntries(buildToolDefs(operations).map((def) => [def.name, def]));
    expect(defs.takes_propose_accept.inputSchema.required).toEqual(['proposal_id']);
    expect(defs.takes_propose_reject.inputSchema.required).toEqual(['proposal_id']);
    expect(Object.keys(defs.takes_propose_list.inputSchema.properties)).toEqual(['limit', 'offset', 'status']);
  });

  test('federated read grants never widen scalar proposal-write authority', async () => {
    const id = await insertProposal({
      source_id: 'tenant-b',
      page_slug: 'topics/b',
      claim: 'Neighboring source must stay pending',
      holder: 'garry',
    });
    const result = await dispatchToolCall(engine, 'takes_propose_accept', { proposal_id: id }, {
      remote: true,
      sourceId: 'tenant-a',
      auth: {
        token: 'test-token',
        clientId: 'reviewer',
        scopes: ['write'],
        allowedSources: ['tenant-a', 'tenant-b'],
      },
    });
    expect(result.isError).toBe(true);
    expect(result.content[0]?.text).toContain('outside your source scope');
    const [proposal] = await engine.executeRaw<{ status: string }>(
      `SELECT status FROM take_proposals WHERE id = $1`,
      [id],
    );
    expect(proposal.status).toBe('pending');
  });
});
