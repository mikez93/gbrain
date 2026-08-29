/** Positive, response-local proof of what the cross-encoder did. */
export interface RerankProof {
  applied: boolean;
  provider: string | null;
  model: string | null;
  candidate_pool_requested: number;
  candidates_in: number;
  candidates_out: number;
}

interface RerankProofOpts {
  enabled: boolean;
  topNIn: number;
  model?: string;
}

export function buildRerankProof(
  candidates: unknown[],
  reranked: Array<{ rerank_score?: number }>,
  opts: RerankProofOpts,
): RerankProof {
  const candidatesIn = opts.enabled
    ? Math.min(candidates.length, Math.max(0, opts.topNIn))
    : 0;
  const candidatesOut = opts.enabled
    ? reranked.filter((item) => Number.isFinite(item.rerank_score)).length
    : 0;
  const model = typeof opts.model === 'string' ? opts.model : null;
  const providerSeparator = model?.search(/[:/]/) ?? -1;
  const provider = model && providerSeparator > 0
    ? model.slice(0, providerSeparator)
    : null;
  return {
    applied: candidatesIn > 0 && candidatesOut === candidatesIn,
    provider,
    model,
    candidate_pool_requested: Math.max(0, opts.topNIn),
    candidates_in: candidatesIn,
    candidates_out: candidatesOut,
  };
}
