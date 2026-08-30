import type { OperationContext } from './contract.ts';

/**
 * Operator-provisioned fleet routers are remote transports but trusted owner
 * readers. Their source/page scope still comes exclusively from server-side
 * OAuth grants; this predicate never widens that scope.
 */
export function isFleetRouterContext(ctx: OperationContext): boolean {
  return ctx.remote === true
    && ctx.auth?.scopes.includes('read') === true
    // F4b owner contract: client_name, surface, and surface_set_by are
    // classification/presentation metadata, never authorization. All three
    // dedicated row fields must survive token projection; a legacy or
    // degraded projection therefore fails closed.
    && ctx.auth.fleetGrant === 'fleet_router'
    && ctx.auth.fleetGrantVersion === 1
    && ctx.auth.fleetGrantSetBy === 'operator'
    && typeof ctx.auth.fleetGrantSetAt === 'string'
    && Number.isFinite(Date.parse(ctx.auth.fleetGrantSetAt));
}

/** Capture/session provenance is private metadata even for a world fact. */
export function canReadFactBindings(ctx: OperationContext): boolean {
  return ctx.remote === false || isFleetRouterContext(ctx);
}
