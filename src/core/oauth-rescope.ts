export interface RescopedClient {
  clientId: string;
  clientName: string;
  scopes: string;
  sourceId: string;
  federatedRead: string[];
  boundSlugPrefixes?: string[] | null;
  surface?: string | null;
  surfaceOld?: string | null;
  fleetGrant: 'ordinary_remote' | 'fleet_router';
  fleetGrantOld: 'ordinary_remote' | 'fleet_router' | null;
  fleetGrantVersion: 0 | 1;
  fleetGrantSetBy: 'operator' | null;
  fleetGrantSetAt: string | null;
  fleetGrantEventId: number | null;
}

export function normalizeFleetGrantSetAt(value: unknown): string | null {
  if (value == null) return null;
  return value instanceof Date
    ? value.toISOString()
    : new Date(String(value)).toISOString();
}
