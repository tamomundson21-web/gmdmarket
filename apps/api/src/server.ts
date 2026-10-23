import Fastify from 'fastify';
import cookie from '@fastify/cookie';
import type { FastifyReply } from 'fastify';
import { Type } from '@sinclair/typebox';
import {
  ErrorResponseSchema,
  HealthResponseSchema,
  VersionResponseSchema,
} from './schemas/common.js';
import {
  AdminCustomerRequestSchema,
  DecisionRequestSchema,
  DecisionResponseSchema,
  RegistrationRequestSchema,
  RegistrationResponseSchema,
} from './schemas/registration.js';
import { closeDb, getDb } from './db/index.js';
import { createEnvelope, isEnvelopeExpired, setFingerprintKey } from './auth/envelope.js';
import { hashPassword } from './auth/password.js';
import { encryptTc, setTcKey } from './auth/tc.js';
import { authRoutes } from './routes/auth.js';
import { adminRoutes } from './routes/admin.js';
import { randomBytes, randomUUID } from 'node:crypto';

const PORT = Number(process.env.API_PORT ?? 3001);
const HOST = process.env.API_HOST ?? '0.0.0.0';

setFingerprintKey(Buffer.from(process.env.F1_FINGERPRINT_KEY ?? 'dev-only-key-change-in-prod', 'utf8'));
setTcKey(Buffer.from(process.env.F1_TC_KEY ?? 'dev-tc-key-32-bytes-change-me!!', 'utf8'));

const app = Fastify({
  logger: { level: process.env.LOG_LEVEL ?? 'info' },
});

await app.register(cookie, { secret: process.env.F1_COOKIE_SECRET ?? 'dev-cookie-secret-change-me' });

app.get('/health', { schema: { response: { 200: HealthResponseSchema } } }, async () => ({
  status: 'ok',
  service: 'gmd-api',
}));

app.get(
  '/health/ready',
  {
    schema: {
      response: {
        200: Type.Object(
          { status: Type.String(), database: Type.String() },
          { additionalProperties: false },
        ),
        default: ErrorResponseSchema,
      },
    },
  },
  async (_req, reply) => {
    try {
      const result = await getDb()
        .selectFrom('health_probe')
        .select((eb) => eb.fn.countAll<number>().as('c'))
        .executeTakeFirstOrThrow();
      return { status: 'ok', database: `postgres ok (${result.c} satir)` };
    } catch (err) {
      app.log.error({ err }, 'database kontrolu basarisiz');
      return (reply as FastifyReply).code(503).send({
        error: 'service_unavailable',
        message: 'veritabani erisilemiyor',
      });
    }
  },
);

app.get(
  '/api/version',
  {
    schema: {
      response: { 200: VersionResponseSchema, default: ErrorResponseSchema },
    },
  },
  async () => ({
    name: 'GMD Market',
    legalName: 'Global Menkul Değerler',
    version: '0.1.0',
  }),
);

app.post(
  '/v1/f1/envelopes',
  {
    schema: {
      body: Type.Object(
        {
          action: Type.String(),
          command_key: Type.String(),
          installation_id: Type.String({ format: 'uuid' }),
          target_user_id: Type.Optional(Type.String({ format: 'uuid' })),
          actor_id: Type.Optional(Type.String({ format: 'uuid' })),
        },
        { additionalProperties: false },
      ),
      response: { 200: Type.Object({ envelope: Type.String() }) },
    },
  },
  async (req, reply) => {
    const { action, command_key, installation_id, target_user_id, actor_id } = req.body as {
      action: string;
      command_key: string;
      installation_id: string;
      target_user_id?: string;
      actor_id?: string;
    };

    const envelope = createEnvelope({
      action,
      commandKey: command_key,
      installationId: installation_id,
      targetUserId: target_user_id ?? null,
      actorId: actor_id ?? null,
      operationGeneration: 1n,
      keyId: process.env.F1_FINGERPRINT_KEY_ID ?? 'v1',
    });

    return reply.send({
      envelope: JSON.stringify({
        envelope_id: envelope.envelopeId,
        command_key: envelope.commandKey,
        installation_id: envelope.installationId,
        target_user_id: envelope.targetUserId,
        actor_id: envelope.actorId,
        action: envelope.action,
        operation_generation: envelope.operationGeneration.toString(),
        key_id: envelope.keyId,
        issued_at: envelope.issuedAt.toISOString(),
        accept_until: envelope.acceptUntil.toISOString(),
        fingerprint: envelope.fingerprint.toString('hex'),
      }),
    });
  },
);

app.post(
  '/v1/registrations',
  {
    schema: {
      body: RegistrationRequestSchema,
      response: { 200: RegistrationResponseSchema, default: ErrorResponseSchema },
    },
  },
  async (req, reply) => {
    const { email, password, tc_kimlik, invite_code, command_key, envelope } = req.body as {
      email: string;
      password: string;
      tc_kimlik: string;
      invite_code?: string;
      command_key: string;
      envelope: {
        envelope_id: string;
        command_key: string;
        installation_id: string;
        target_user_id?: string;
        actor_id?: string;
        action: string;
        operation_generation: string;
        key_id: string;
        issued_at: string;
        accept_until: string;
        fingerprint: string;
      };
    };

    if (isEnvelopeExpired({ acceptUntil: new Date(envelope.accept_until) })) {
      return reply.code(409).send({ error: 'envelope_expired', message: 'zarf suresi doldu' });
    }

    const db = getDb();
    const resultRef = randomUUID();
    const now = new Date();

    const prior = await db
      .selectFrom('f1_command_results')
      .select(['outcome', 'result_ref'])
      .where('installation_id', '=', envelope.installation_id)
      .where('command_key', '=', command_key)
      .executeTakeFirst();

    if (prior) {
      const priorStatus =
        prior.outcome === 'rejected' ? 'rejected' : prior.outcome === 'applied' ? 'approved' : 'pending';
      return reply.send({
        result: prior.outcome,
        result_ref: prior.result_ref ?? resultRef,
        status: priorStatus,
      });
    }

    try {
      const outcome = await db.transaction().execute(async (trx): Promise<{
        outcome: 'applied' | 'no_op' | 'rejected';
        status: 'pending' | 'approved' | 'rejected';
      }> => {
        const existing = await trx
          .selectFrom('users')
          .select('id')
          .where('email_key', '=', email.toLowerCase())
          .executeTakeFirst();

        if (existing) {
          await trx
            .insertInto('f1_command_results')
            .values({
              id: randomUUID(),
              installation_id: envelope.installation_id,
              actor_id: envelope.actor_id ?? null,
              command_key,
              action: 'registration',
              target_user_id: null,
              request_fingerprint: Buffer.from(envelope.fingerprint, 'hex'),
              fingerprint_key_id: envelope.key_id,
              operation_generation: '1',
              accept_until: new Date(envelope.accept_until),
              outcome: 'rejected',
              result_ref: resultRef,
              committed_at: now,
              created_at: now,
            })
            .execute();
          return { outcome: 'rejected', status: 'rejected' };
        }

        const passwordHash = await hashPassword(password);

        const user = await trx
          .insertInto('users')
          .values({
            id: randomUUID(),
            email,
            email_key: email.toLowerCase(),
            password_hash: passwordHash,
            role: 'user',
            status: 'active',
            profile_version: 1,
            credential_version: 1,
            authorization_version: 1,
            auth_generation: 1,
            customer_trading_enabled: true,
            created_at: now,
          })
          .returning('id')
          .executeTakeFirstOrThrow();

        let origin: 'self_without_invite' | 'self_with_invite' = 'self_without_invite';
        let initialAccountId: string | null = null;
        let registrationStatus: 'pending' | 'approved' = 'pending';

        if (invite_code) {
          const invite = await trx
            .selectFrom('desk_invites')
            .select(['id', 'desk_id', 'max_uses', 'used_count', 'expires_at', 'active'])
            .where('code_hash', '=', Buffer.from(invite_code, 'utf8'))
            .executeTakeFirst();

          if (invite && invite.active && new Date() < new Date(invite.expires_at) && invite.used_count < invite.max_uses) {
            origin = 'self_with_invite';
            registrationStatus = 'approved';

            const account = await trx
              .insertInto('accounts')
              .values({
                id: randomUUID(),
                user_id: user.id,
                desk_id: invite.desk_id,
                currency: 'USD',
                balance: '0',
                last_publication_seq: 0,
                last_operation_seq: 0,
                state_version: 1,
                status: 'active',
                created_at: now,
              })
              .returning('id')
              .executeTakeFirstOrThrow();

            initialAccountId = account.id;

            await trx
              .updateTable('desk_invites')
              .set({ used_count: invite.used_count + 1 })
              .where('id', '=', invite.id)
              .execute();
          }
        }

        if (tc_kimlik && /^\d{11}$/.test(tc_kimlik)) {
          const tc = encryptTc(tc_kimlik);
          await trx
            .insertInto('tc_identity_vault')
            .values({
              id: randomUUID(),
              user_id: user.id,
              tc_ciphertext: tc.ciphertext,
              tc_nonce: tc.nonce,
              tc_auth_tag: tc.tag,
              tc_key_id: tc.keyId,
              tc_crypto_version: tc.cryptoVersion,
              created_at: now,
            })
            .execute();
        }

        await trx
          .insertInto('registration_queue')
          .values({
            id: randomUUID(),
            user_id: user.id,
            origin,
            version: 1,
            requested_at: now,
            status: registrationStatus,
            initial_account_id: initialAccountId,
            reviewed_at: registrationStatus === 'approved' ? now : null,
          })
          .execute();

        await trx
          .insertInto('f1_command_results')
          .values({
            id: randomUUID(),
            installation_id: envelope.installation_id,
            actor_id: envelope.actor_id ?? null,
            command_key,
            action: 'registration',
            target_user_id: user.id,
            request_fingerprint: Buffer.from(envelope.fingerprint, 'hex'),
            fingerprint_key_id: envelope.key_id,
            operation_generation: '1',
            accept_until: new Date(envelope.accept_until),
            outcome: registrationStatus === 'approved' ? 'applied' : 'no_op',
            result_ref: resultRef,
            committed_at: now,
            created_at: now,
          })
          .execute();

        return {
          outcome: registrationStatus === 'approved' ? 'applied' : 'no_op',
          status: registrationStatus,
        };
      });

      return reply.send({
        result: outcome.outcome,
        result_ref: resultRef,
        status: outcome.status,
      });
    } catch (err) {
      app.log.error({ err }, 'kayit basarisiz');
      return reply.code(500).send({ error: 'internal_error', message: 'kayit tamamlanamadi' });
    }
  },
);

await app.register(authRoutes, { prefix: '' });
await app.register(adminRoutes, { prefix: '' });

async function main(): Promise<void> {
  try {
    await app.listen({ port: PORT, host: HOST });
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
}

for (const sig of ['SIGINT', 'SIGTERM'] as const) {
  process.on(sig, () => {
    void app.close().then(closeDb).then(() => process.exit(0));
  });
}

void main();
