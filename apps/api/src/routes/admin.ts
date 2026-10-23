import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import '@fastify/cookie';
import { Type } from '@sinclair/typebox';
import { getDb } from '../db/index.js';
import { hashPassword } from '../auth/password.js';
import { normalizeEmailKey, isValidTcKimlik } from '../auth/input.js';
import { decryptTc, encryptTc } from '../auth/tc.js';
import { revokeAllUserAccess } from '../auth/session.js';
import { allowedOrigin } from '../auth/csrf.js';

type AdminActor = { id: string; role: 'master' | 'sub_admin'; deskId: string | null };

async function getAdminActor(req: FastifyRequest): Promise<AdminActor | null> {
  const jar = req.cookies as Record<string, string | undefined>;
  const activeCookie = Object.keys(jar)
    .filter((k) => k.startsWith('__Host-tp-a-'))
    .map((k) => ({ name: k, value: jar[k]! }))
    .at(0);
  if (!activeCookie) return null;

  const db = getDb();
  const { validateSession } = await import('../auth/session.js');
  const session = await validateSession(db, activeCookie.value);
  if (!session) return null;
  if (session.role !== 'master' && session.role !== 'sub_admin') return null;

  return { id: session.user_id, role: session.role, deskId: session.desk_id };
}

function isAuthorized(actor: AdminActor, targetDeskId: string | null): boolean {
  if (actor.role === 'master') return true;
  return targetDeskId !== null && targetDeskId === actor.deskId;
}

export async function adminRoutes(app: FastifyInstance): Promise<void> {
  const db = getDb();

  app.post(
    '/v1/admin/customers',
    {
      schema: {
        body: Type.Object(
          {
            email: Type.String(),
            password: Type.String({ minLength: 8, maxLength: 128 }),
            tc_kimlik: Type.String({ minLength: 11, maxLength: 11 }),
            command_key: Type.String(),
          },
          { additionalProperties: false },
        ),
        response: {
          200: Type.Object(
            { result: Type.String(), result_ref: Type.String(), user_id: Type.String() },
            { additionalProperties: false },
          ),
          default: Type.Object({ error: Type.String(), message: Type.String() }),
        },
      },
    },
    async (req, reply) => {
      if (!allowedOrigin(req.headers.origin)) {
        return (reply as FastifyReply).code(403).send({ error: 'forbidden', message: 'origin izinli degil' });
      }

      const actor = await getAdminActor(req);
      if (!actor) {
        return (reply as FastifyReply).code(401).send({ error: 'unauthenticated', message: 'oturum yok' });
      }
      if (actor.role !== 'sub_admin' || !actor.deskId) {
        return (reply as FastifyReply).code(403).send({ error: 'forbidden', message: 'yetki yok' });
      }

      const { email, password, tc_kimlik, command_key } = req.body as {
        email: string;
        password: string;
        tc_kimlik: string;
        command_key: string;
      };

      if (!isValidTcKimlik(tc_kimlik)) {
        return (reply as FastifyReply).code(400).send({ error: 'invalid_request', message: 'tc gecersiz' });
      }

      const key = normalizeEmailKey(email);
      const existing = await db
        .selectFrom('users')
        .select('id')
        .where('email_key', '=', key)
        .executeTakeFirst();
      if (existing) {
        return (reply as FastifyReply).code(409).send({ error: 'conflict', message: 'email kayitli' });
      }

      const resultRef = crypto.randomUUID();
      const now = new Date();
      const passwordHash = await hashPassword(password);

      const userId = await db.transaction().execute(async (trx) => {
        const user = await trx
          .insertInto('users')
          .values({
            id: crypto.randomUUID(),
            email,
            email_key: key,
            password_hash: passwordHash,
            role: 'user',
            status: 'active',
            desk_id: actor.deskId!,
            profile_version: 1,
            credential_version: 1,
            authorization_version: 1,
            auth_generation: 1,
            customer_trading_enabled: true,
            created_by: actor.id,
            created_at: now,
          })
          .returning('id')
          .executeTakeFirstOrThrow();

        const account = await trx
          .insertInto('accounts')
          .values({
            id: crypto.randomUUID(),
            user_id: user.id,
            desk_id: actor.deskId!,
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

        await trx
          .insertInto('registration_queue')
          .values({
            id: crypto.randomUUID(),
            user_id: user.id,
            origin: 'sub_admin_created',
            version: 1,
            requested_at: now,
            status: 'approved',
            reviewed_by: actor.id,
            reviewed_at: now,
            initial_account_id: account.id,
          })
          .execute();

        const tc = encryptTc(tc_kimlik);
        await trx
          .insertInto('tc_identity_vault')
          .values({
            id: crypto.randomUUID(),
            user_id: user.id,
            tc_ciphertext: tc.ciphertext,
            tc_nonce: tc.nonce,
            tc_auth_tag: tc.tag,
            tc_key_id: tc.keyId,
            tc_crypto_version: tc.cryptoVersion,
            created_at: now,
          })
          .execute();

        return user.id;
      });

      return reply.send({ result: 'applied', result_ref: resultRef, user_id: userId });
    },
  );

  app.post(
    '/v1/admin/registrations/:user_id/decision',
    {
      schema: {
        params: Type.Object({ user_id: Type.String({ format: 'uuid' }) }),
        body: Type.Object(
          {
            decision: Type.Union([Type.Literal('approved'), Type.Literal('rejected')]),
            desk_id: Type.Optional(Type.String({ format: 'uuid' })),
            expected_registration_version: Type.String(),
            command_key: Type.String(),
          },
          { additionalProperties: false },
        ),
        response: {
          200: Type.Object(
            { result: Type.String(), result_ref: Type.String(), status: Type.String() },
            { additionalProperties: false },
          ),
          default: Type.Object({ error: Type.String(), message: Type.String() }),
        },
      },
    },
    async (req, reply) => {
      if (!allowedOrigin(req.headers.origin)) {
        return (reply as FastifyReply).code(403).send({ error: 'forbidden', message: 'origin izinli degil' });
      }

      const actor = await getAdminActor(req);
      if (!actor || actor.role !== 'master') {
        return (reply as FastifyReply).code(403).send({ error: 'forbidden', message: 'yetki yok' });
      }

      const { user_id } = req.params as { user_id: string };
      const { decision, desk_id, expected_registration_version, command_key } = req.body as {
        decision: 'approved' | 'rejected';
        desk_id?: string;
        expected_registration_version: string;
        command_key: string;
      };

      const resultRef = crypto.randomUUID();
      const now = new Date();

      const outcome = await db.transaction().execute(async (trx) => {
        const reg = await trx
          .selectFrom('registration_queue')
          .select(['id', 'user_id', 'version', 'status', 'initial_account_id'])
          .where('user_id', '=', user_id)
          .forUpdate()
          .executeTakeFirst();

        if (!reg) return { error: 'not_found' as const };
        if (reg.status !== 'pending') return { error: 'conflict' as const };
        if (Number(reg.version) !== Number(expected_registration_version)) {
          return { error: 'version_conflict' as const };
        }

        if (decision === 'rejected') {
          await trx
            .updateTable('registration_queue')
            .set({ status: 'rejected', reviewed_by: actor.id, reviewed_at: now, version: (eb) => eb('version', '+', 1) })
            .where('id', '=', reg.id)
            .execute();
          return { result: 'applied' as const, status: 'rejected' as const };
        }

        if (!desk_id) return { error: 'invalid_request' as const };

        const desk = await trx
          .selectFrom('desks')
          .select(['id', 'status'])
          .where('id', '=', desk_id)
          .executeTakeFirst();
        if (!desk || desk.status !== 'active') return { error: 'invalid_request' as const };

        const user = await trx
          .selectFrom('users')
          .select(['id'])
          .where('id', '=', reg.user_id)
          .executeTakeFirst();
        if (!user) return { error: 'not_found' as const };

        const account = await trx
          .insertInto('accounts')
          .values({
            id: crypto.randomUUID(),
            user_id: reg.user_id,
            desk_id: desk_id!,
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

        await trx
          .updateTable('users')
          .set({ desk_id, authorization_version: (eb) => eb('authorization_version', '+', 1) })
          .where('id', '=', reg.user_id)
          .execute();

        await trx
          .updateTable('registration_queue')
          .set({
            status: 'approved',
            reviewed_by: actor.id,
            reviewed_at: now,
            initial_account_id: account.id,
            version: (eb) => eb('version', '+', 1),
          })
          .where('id', '=', reg.id)
          .execute();

        return { result: 'applied' as const, status: 'approved' as const };
      });

      if ('error' in outcome) {
        const code = outcome.error === 'version_conflict' ? 409 : 400;
        return (reply as FastifyReply).code(code).send({ error: outcome.error, message: 'karar uygulanamadi' });
      }

      return reply.send({ result: outcome.result, result_ref: resultRef, status: outcome.status });
    },
  );

  app.patch(
    '/v1/admin/customers/:user_id/email',
    {
      schema: {
        params: Type.Object({ user_id: Type.String({ format: 'uuid' }) }),
        body: Type.Object(
          {
            email: Type.String(),
            expected_profile_version: Type.String(),
            command_key: Type.String(),
          },
          { additionalProperties: false },
        ),
        response: {
          200: Type.Object(
            { result: Type.String(), result_ref: Type.String() },
            { additionalProperties: false },
          ),
          default: Type.Object({ error: Type.String(), message: Type.String() }),
        },
      },
    },
    async (req, reply) => {
      if (!allowedOrigin(req.headers.origin)) {
        return (reply as FastifyReply).code(403).send({ error: 'forbidden', message: 'origin izinli degil' });
      }

      const actor = await getAdminActor(req);
      if (!actor) return (reply as FastifyReply).code(401).send({ error: 'unauthenticated', message: 'oturum yok' });

      const { user_id } = req.params as { user_id: string };
      const { email, expected_profile_version, command_key } = req.body as {
        email: string;
        expected_profile_version: string;
        command_key: string;
      };

      const resultRef = crypto.randomUUID();
      const now = new Date();
      const key = normalizeEmailKey(email);

      const outcome = await db.transaction().execute(async (trx) => {
        const target = await trx
          .selectFrom('users')
          .select(['id', 'desk_id', 'email_key', 'profile_version', 'credential_version'])
          .where('id', '=', user_id)
          .where('role', '=', 'user')
          .forUpdate()
          .executeTakeFirst();

        if (!target) return { error: 'not_found' as const };
        if (!isAuthorized(actor, target.desk_id)) return { error: 'forbidden' as const };
        if (Number(target.profile_version) !== Number(expected_profile_version)) {
          return { error: 'version_conflict' as const };
        }
        if (target.email_key === key) return { result: 'no_op' as const };

        const clash = await trx
          .selectFrom('users')
          .select('id')
          .where('email_key', '=', key)
          .where('id', '!=', target.id)
          .executeTakeFirst();
        if (clash) return { error: 'conflict' as const };

        await trx
          .updateTable('users')
          .set({
            email,
            email_key: key,
            profile_version: (eb) => eb('profile_version', '+', 1),
            credential_version: (eb) => eb('credential_version', '+', 1),
          })
          .where('id', '=', target.id)
          .execute();

        await revokeAllUserAccess(trx, target.id, now);

        return { result: 'applied' as const };
      });

      if ('error' in outcome) {
        return (reply as FastifyReply).code(409).send({ error: outcome.error, message: 'degisiklik uygulanamadi' });
      }

      return reply.send({ result: outcome.result, result_ref: resultRef });
    },
  );

  app.get(
    '/v1/admin/customers/:user_id/identity',
    {
      schema: {
        params: Type.Object({ user_id: Type.String({ format: 'uuid' }) }),
        response: {
          200: Type.Object(
            { user_id: Type.String(), tc_kimlik: Type.String() },
            { additionalProperties: false },
          ),
          default: Type.Object({ error: Type.String(), message: Type.String() }),
        },
      },
    },
    async (req, reply) => {
      const actor = await getAdminActor(req);
      if (!actor || actor.role !== 'master') {
        return (reply as FastifyReply).code(403).send({ error: 'forbidden', message: 'yetki yok' });
      }

      const { user_id } = req.params as { user_id: string };

      const vault = await db
        .selectFrom('tc_identity_vault')
        .select(['tc_ciphertext', 'tc_nonce', 'tc_auth_tag', 'tc_key_id', 'tc_crypto_version'])
        .where('user_id', '=', user_id)
        .executeTakeFirst();

      if (!vault) {
        return (reply as FastifyReply).code(404).send({ error: 'not_found', message: 'kimlik yok' });
      }

      try {
        const tc = decryptTc({
          ciphertext: vault.tc_ciphertext,
          nonce: vault.tc_nonce,
          tag: vault.tc_auth_tag,
          keyId: vault.tc_key_id,
          cryptoVersion: vault.tc_crypto_version,
        });
        return reply.send({ user_id, tc_kimlik: tc });
      } catch {
        return (reply as FastifyReply).code(500).send({ error: 'error', message: 'cozum basarisiz' });
      }
    },
  );
}
