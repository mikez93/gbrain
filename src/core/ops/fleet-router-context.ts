import type { OperationContext } from './contract.ts';
import { hasScope } from '../scope.ts';

/**
 * Operator-provisioned fleet routers are remote transports but trusted owner
 * readers. Their source/page scope still comes exclusively from server-side
 * OAuth grants; this predicate never widens that scope.
 */
export function isFleetRouterContext(ctx: OperationContext): boolean {
  const auth = ctx.auth;
  return ctx.remote === true
    && auth !== undefined
    && hasScope(auth.scopes, 'read')
    // F4b owner contract: client_name, surface, and surface_set_by are
    // classification/presentation metadata, never authorization. All three
    // dedicated row fields must survive token projection; a legacy or
    // degraded projection therefore fails closed.
    && auth.fleetGrant === 'fleet_router'
    && auth.fleetGrantVersion === 1
    && auth.fleetGrantSetBy === 'operator'
    && typeof auth.fleetGrantSetAt === 'string'
    && Number.isFinite(Date.parse(auth.fleetGrantSetAt));
}

/** Capture/session provenance is private metadata even for a world fact. */
export function canReadFactBindings(ctx: OperationContext): boolean {
  return ctx.remote === false || isFleetRouterContext(ctx);
}
