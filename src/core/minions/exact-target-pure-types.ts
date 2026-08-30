/**
 * Data-only types for the exact-target lane.
 *
 * This module deliberately has no runtime imports. Later implementation orders
 * may build pure validators and reducers on these transport representations
 * without pulling the queue, an engine, or provider packages into the test
 * boundary.
 */

declare const exactTargetBrand: unique symbol;

export type ExactTargetInt8Text = string & {
  readonly [exactTargetBrand]: 'int8-decimal-text';
};

export type ExactTargetTimestampText = string & {
  readonly [exactTargetBrand]: 'utc-six-microsecond-text';
};

export type ExactTargetJsonText = string & {
  readonly [exactTargetBrand]: 'postgres-jsonb-text';
};

export type ExactTargetInt4 = number & {
  readonly [exactTargetBrand]: 'signed-int4';
};

export type ExactTargetClaimOutcome =
  | 'NOT_NEEDED'
  | 'RECOVERED'
  | 'NOT_COMMITTED'
  | 'UNKNOWN_OR_FOREIGN'
  | 'READBACK_FAILED';

export type ExactTargetReadbackObservability =
  | 'NOT_APPLICABLE'
  | 'TRUSTED'
  | 'UNTRUSTED';

export interface ExactTargetClaimAccounting {
  readonly total_update_count: 1;
  readonly select_attempt_count: 0 | 1;
  readonly successful_select_count: 0 | 1;
  readonly rows_returned: 0 | 1 | null;
  readonly rows_returned_observability: ExactTargetReadbackObservability;
}

export type ExactTargetTransportScalar =
  | string
  | number
  | boolean
  | null;

export type ExactTargetTransportRecord = Readonly<
  Record<string, ExactTargetTransportScalar>
>;
