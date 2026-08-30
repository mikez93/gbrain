import type { OperationContext } from './contract.ts';

const FLEET_ROUTER_CLIENT_NAME =
  /^brain-router-[a-z][a-z0-9_-]{0,63}-[0-9a-f]{12}$/;

/**
 * Operator-provisioned fleet routers are remote transports but trusted owner
 * readers. Their source/page scope still comes exclusively from server-side
 * OAuth grants; this predicate never widens that scope.
 */
export function isFleetRouterContext(ctx: OperationContext): boolean {
  return ctx.remote === true
    && typeof ctx.auth?.clientName === 'string'
    && FLEET_ROUTER_CLIENT_NAME.test(ctx.auth.clientName)
    && ctx.auth.scopes.includes('read')
    // DCR persists caller-supplied client_name, so the name shape is only a
    // routing convention, never proof of operator provisioning. The OAuth
    // projection must also carry the operator-only persistence marker. A
    // missing/degraded projection therefore fails closed.
    && ctx.auth.surfaceSetBy === 'operator';
}

/** Capture/session provenance is private metadata even for a world fact. */
export function canReadFactBindings(ctx: OperationContext): boolean {
  return ctx.remote === false || isFleetRouterContext(ctx);
}
