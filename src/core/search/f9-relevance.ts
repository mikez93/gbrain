import type { SearchResult } from '../types.ts';

const STOPWORDS = new Set([
  'a', 'an', 'and', 'are', 'as', 'at', 'be', 'by', 'do', 'does', 'for', 'from',
  'how', 'i', 'in', 'is', 'it', 'me', 'my', 'of', 'on', 'or', 'our', 'the',
  'to', 'was', 'we', 'what', 'when', 'where', 'which', 'who', 'with',
]);

export interface F9RetrievalEvidence {
  version: 'f9-item-evidence-v1';
  query_token_count: number;
  matched_distinct_token_count: number;
  coverage_bps: number;
  exact_title_match: boolean;
  exact_chunk_phrase: boolean;
}

function isLetterOrNumber(value: string): boolean {
  return /[\p{L}\p{N}]/u.test(value);
}

/** V10's provider-free NFKC token contract, capped by the router query limit. */
export function f9Tokens(value: string): string[] {
  const raw: string[] = [];
  let token = '';
  for (const char of value.normalize('NFKC').toLowerCase()) {
    if (isLetterOrNumber(char)) token += char;
    else if (token) {
      raw.push(token);
      token = '';
    }
  }
  if (token) raw.push(token);

  const seen = new Set<string>();
  const tokens: string[] = [];
  for (const candidate of raw) {
    if (Array.from(candidate).length <= 1 || STOPWORDS.has(candidate) || seen.has(candidate)) continue;
    seen.add(candidate);
    tokens.push(candidate);
  }
  return tokens.slice(0, 1024);
}

function containsSequence(haystack: string[], needle: string[]): boolean {
  if (needle.length === 0 || needle.length > haystack.length) return false;
  for (let start = 0; start <= haystack.length - needle.length; start += 1) {
    if (needle.every((value, offset) => haystack[start + offset] === value)) return true;
  }
  return false;
}

export function deriveF9RetrievalEvidence(
  query: string,
  title: string | null | undefined,
  matchedChunk: string | null | undefined,
): F9RetrievalEvidence {
  const queryTokens = f9Tokens(query);
  const titleTokens = f9Tokens(title ?? '');
  const chunkTokens = f9Tokens(matchedChunk ?? '');
  const matchedTokens = new Set([...titleTokens, ...chunkTokens]);
  const matched = queryTokens.filter((value) => matchedTokens.has(value)).length;
  return {
    version: 'f9-item-evidence-v1',
    query_token_count: queryTokens.length,
    matched_distinct_token_count: matched,
    coverage_bps: queryTokens.length === 0 ? 0 : Math.floor((10000 * matched) / queryTokens.length),
    exact_title_match: queryTokens.length > 0
      && queryTokens.length === titleTokens.length
      && queryTokens.every((value, index) => titleTokens[index] === value),
    exact_chunk_phrase: queryTokens.length >= 2 && containsSequence(chunkTokens, queryTokens),
  };
}

export function stampF9RetrievalEvidence(query: string, results: SearchResult[]): void {
  for (const result of results) {
    result.retrieval_evidence = deriveF9RetrievalEvidence(query, result.title, result.chunk_text);
  }
}
