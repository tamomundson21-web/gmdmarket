import { Type } from '@sinclair/typebox';

export const ErrorResponseSchema = Type.Object(
  {
    error: Type.String(),
    message: Type.String(),
    code: Type.Optional(Type.String()),
  },
  { additionalProperties: false },
);

export const HealthResponseSchema = Type.Object(
  {
    status: Type.String(),
    service: Type.String(),
  },
  { additionalProperties: false },
);

export const VersionResponseSchema = Type.Object(
  {
    name: Type.String(),
    legalName: Type.String(),
    version: Type.String(),
  },
  { additionalProperties: false },
);

export type ErrorResponse = typeof ErrorResponseSchema.static;
export type HealthResponse = typeof HealthResponseSchema.static;
export type VersionResponse = typeof VersionResponseSchema.static;
