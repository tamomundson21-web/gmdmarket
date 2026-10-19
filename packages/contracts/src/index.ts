export const BRAND = {
  name: 'GMD Market',
  legalName: 'Global Menkul Değerler',
} as const;

export type HealthResponse = {
  status: 'ok' | 'degraded';
  service: string;
};

export type VersionResponse = {
  name: string;
  legalName: string;
  version: string;
};