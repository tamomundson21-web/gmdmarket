import { Type } from '@sinclair/typebox';

export const EnvelopeSchema = Type.Object(
  {
    envelope_id: Type.String({ format: 'uuid' }),
    command_key: Type.String(),
    installation_id: Type.String({ format: 'uuid' }),
    target_user_id: Type.Union([Type.String({ format: 'uuid' }), Type.Null()]),
    actor_id: Type.Union([Type.String({ format: 'uuid' }), Type.Null()]),
    action: Type.String(),
    operation_generation: Type.String(),
    key_id: Type.String(),
    issued_at: Type.String({ format: 'date-time' }),
    accept_until: Type.String({ format: 'date-time' }),
    fingerprint: Type.String(),
  },
  { additionalProperties: false },
);

export const RegistrationRequestSchema = Type.Object(
  {
    email: Type.String(),
    password: Type.String({ minLength: 8, maxLength: 128 }),
    tc_kimlik: Type.String({ minLength: 11, maxLength: 11 }),
    invite_code: Type.Optional(Type.String()),
    command_key: Type.String(),
    envelope: EnvelopeSchema,
  },
  { additionalProperties: false },
);

export const RegistrationResponseSchema = Type.Object(
  {
    result: Type.String(),
    result_ref: Type.String(),
    status: Type.String(),
  },
  { additionalProperties: false },
);

export const AdminCustomerRequestSchema = Type.Object(
  {
    email: Type.String(),
    password: Type.String({ minLength: 8, maxLength: 128 }),
    tc_kimlik: Type.String({ minLength: 11, maxLength: 11 }),
    command_key: Type.String(),
    envelope: EnvelopeSchema,
  },
  { additionalProperties: false },
);

export const DecisionRequestSchema = Type.Object(
  {
    decision: Type.String(),
    desk_id: Type.Optional(Type.String({ format: 'uuid' })),
    expected_registration_version: Type.String(),
    command_key: Type.String(),
    envelope: EnvelopeSchema,
  },
  { additionalProperties: false },
);

export const DecisionResponseSchema = Type.Object(
  {
    result: Type.String(),
    result_ref: Type.String(),
    status: Type.String(),
  },
  { additionalProperties: false },
);
