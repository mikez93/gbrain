import { describe, expect, test } from 'bun:test';
import { deriveF9RetrievalEvidence, f9Tokens } from '../src/core/search/f9-relevance.ts';

describe('F9 deterministic retrieval evidence', () => {
  test('normalization is stable across compatibility Unicode and stopwords', () => {
    expect(f9Tokens('ＣＵＲＲＥＮＴ　status')).toEqual(['current', 'status']);
    expect(f9Tokens('Café café')).toEqual(['café']);
    expect(f9Tokens('the AND current')).toEqual(['current']);
  });

  test('one accidental token cannot satisfy a multi-token nonsense query', () => {
    expect(deriveF9RetrievalEvidence(
      'violet submarine payroll marmalade 7319',
      'Payroll policy',
      'ordinary unrelated prose',
    )).toMatchObject({
      query_token_count: 5,
      matched_distinct_token_count: 1,
      coverage_bps: 2000,
      exact_title_match: false,
      exact_chunk_phrase: false,
    });
  });

  test('two-token fifty-percent boundary is represented exactly', () => {
    expect(deriveF9RetrievalEvidence(
      'current payroll schedule policy',
      'Payroll schedule',
      '',
    )).toMatchObject({
      query_token_count: 4,
      matched_distinct_token_count: 2,
      coverage_bps: 5000,
    });
  });

  test('exact title and exact chunk phrase are positive signals', () => {
    expect(deriveF9RetrievalEvidence('Trophy payroll', 'Trophy payroll', '')).toMatchObject({
      exact_title_match: true,
      exact_chunk_phrase: false,
    });
    expect(deriveF9RetrievalEvidence('payroll schedule', 'Policy', 'Current payroll schedule applies.'))
      .toMatchObject({ exact_title_match: false, exact_chunk_phrase: true });
  });

  test('zero normalized query never exact-matches empty text', () => {
    expect(deriveF9RetrievalEvidence('the and I', '', '')).toEqual({
      version: 'f9-item-evidence-v1',
      query_token_count: 0,
      matched_distinct_token_count: 0,
      coverage_bps: 0,
      exact_title_match: false,
      exact_chunk_phrase: false,
    });
  });
});
