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

/**
 * Fact authority is source-scoped as well as role-scoped. A remote fleet
 * router must prove the result source through either its nonempty federated
 * read grant or the exact server-assigned scalar source.
 */
export function canReadFactAuthority(ctx: OperationContext, sourceId: string): boolean {
  if (ctx.remote === false) return true;
  if (!isFleetRouterContext(ctx)) return false;
  const allowed = ctx.auth?.allowedSources;
  if (allowed && allowed.length > 0) return allowed.includes(sourceId);
  return typeof ctx.sourceId === 'string' && ctx.sourceId === sourceId;
}
