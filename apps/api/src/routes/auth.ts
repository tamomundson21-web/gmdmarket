import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import '@fastify/cookie';
import { Type } from '@sinclair/typebox';
import { getDb } from '../db/index.js';
import { verifyPassword } from '../auth/password.js';
import { normalizeEmailKey } from '../auth/input.js';
import { tokenHash, tokenEquals } from '../auth/token.js';
import {
  consumeResetToken,
  createResetToken,
  login,
  revokeFamily,
  revokeAllUserAccess,
  validateSession,
} from '../auth/session.js';
import { hashPassword } from '../auth/password.js';
import { allowedOrigin, generateCsrf, verifyCsrf } from '../auth/csrf.js';

const ACTIVE_COOKIE = (id: string) => `__Host-tp-a-${id}`;
const REMEMBER_COOKIE = (id: string) => `__Host-tp-r-${id}`;
const CSRF_COOKIE = '__Host-tp-c';

function readCookie(req: FastifyRequest, name: string): string | undefined {
  const jar = req.cookies as Record<string, string | undefined>;
  return jar[name];
}

function setAuthCookies(
  reply: FastifyReply,
  opts: {
    activeId?: string | undefined;
    activeToken?: string | undefined;
    rememberId?: string | undefined;
    rememberToken?: string | undefined;
    maxAge?: number | undefined;
  },
) {
  if (opts.activeId && opts.activeToken) {
    reply.setCookie(ACTIVE_COOKIE(opts.activeId), opts.activeToken, {
      path: '/',
      secure: true,
      httpOnly: true,
      sameSite: 'strict',
      maxAge: opts.maxAge ?? 1800,
    });
  }
  if (opts.rememberId && opts.rememberToken) {
    reply.setCookie(REMEMBER_COOKIE(opts.rememberId), opts.rememberToken, {
      path: '/',
      secure: true,
      httpOnly: true,
      sameSite: 'strict',
      maxAge: 30 * 24 * 60 * 60,
    });
  }
}

function requireCsrf(req: FastifyRequest): boolean {
  if (!allowedOrigin(req.headers.origin)) return false;
  return verifyCsrf(readCookie(req, CSRF_COOKIE), req.headers['x-tp-csrf'] as string | undefined);
}

export async function authRoutes(app: FastifyInstance): Promise<void> {
  const db = getDb();

  app.post(
    '/v1/auth/csrf',
    {
      schema: {
        response: { 200: Type.Object({ csrf_token: Type.String() }) },
      },
    },
    async (req, reply) => {
      if (!allowedOrigin(req.headers.origin)) {
        return (reply as FastifyReply).code(403).send({ error: 'forbidden', message: 'origin izinli degil' });
      }
      const csrf = generateCsrf();
      reply.setCookie(CSRF_COOKIE, csrf.cookie, {
        path: '/',
        secure: true,
        httpOnly: false,
        sameSite: 'strict',
        maxAge: 60 * 60,
      });
      return reply.send({ csrf_token: csrf.token });
    },
  );

  app.post(
    '/v1/auth/login',
    {
      schema: {
        body: Type.Object(
          {
            email: Type.String(),
            password: Type.String({ minLength: 8, maxLength: 128 }),
            remember_me: Type.Optional(Type.Boolean()),
          },
          { additionalProperties: false },
        ),
        response: {
          200: Type.Object(
            { role: Type.String(), status: Type.String() },
            { additionalProperties: false },
          ),
          default: Type.Object({ error: Type.String(), message: Type.String() }),
        },
      },
    },
    async (req, reply) => {
      const { email, password, remember_me } = req.body as {
        email: string;
        password: string;
        remember_me?: boolean;
      };

      const key = normalizeEmailKey(email);
      const user = await db
        .selectFrom('users')
        .select(['id', 'role', 'status', 'password_hash'])
        .where('email_key', '=', key)
        .executeTakeFirst();

      let passwordOk = false;
      if (user) {
        passwordOk = await verifyPassword(user.password_hash, password);
      }

      if (!user || !passwordOk) {
        return (reply as FastifyReply).code(401).send({ error: 'invalid_credentials', message: 'giris basarisiz' });
      }

      const result = await login(db, { id: user.id, role: user.role, status: user.status }, true, remember_me ?? false);

      if (!result.ok) {
        return (reply as FastifyReply).code(403).send({ error: result.reason, message: 'giris basarisiz' });
      }

      setAuthCookies(reply, {
        activeId: result.sessionToken,
        activeToken: result.sessionToken,
        rememberId: result.rememberToken,
        rememberToken: result.rememberToken,
      });

      return reply.send({ role: user.role, status: user.status });
    },
  );

  app.post(
    '/v1/auth/remember',
    {
      schema: {
        response: {
          200: Type.Object({ role: Type.String() }),
          default: Type.Object({ error: Type.String(), message: Type.String() }),
        },
      },
    },
    async (req, reply) => {
      if (!requireCsrf(req)) {
        return (reply as FastifyReply).code(403).send({ error: 'csrf_invalid', message: 'csrf gecersiz' });
      }

      const jar = req.cookies as Record<string, string | undefined>;
      const rememberCookie = Object.keys(jar)
        .filter((k) => k.startsWith('__Host-tp-r-'))
        .map((k) => ({ name: k, value: jar[k]! }))
        .at(0);

      if (!rememberCookie) {
        return (reply as FastifyReply).code(401).send({ error: 'unauthenticated', message: 'hatirlama yok' });
      }

      const hash = tokenHash('remember', rememberCookie.value);
      const grant = await db
        .selectFrom('remembered_browser_grants as g')
        .innerJoin('auth_session_families as f', 'f.id', 'g.session_family_id')
        .innerJoin('users as u', 'u.id', 'g.user_id')
        .select([
          'g.id',
          'g.user_id',
          'g.session_family_id',
          'g.secret_hash',
          'g.revoked_at',
          'g.expires_at',
          'g.credential_version',
          'g.auth_generation',
          'f.revoked_at as family_revoked_at',
          'u.role',
          'u.status',
          'u.credential_version as user_credential_version',
          'u.auth_generation as user_auth_generation',
        ])
        .where('g.secret_hash', '=', hash)
        .executeTakeFirst();

      if (
        !grant ||
        grant.revoked_at ||
        grant.family_revoked_at ||
        grant.expires_at.getTime() <= Date.now() ||
        grant.credential_version !== grant.user_credential_version ||
        grant.auth_generation !== grant.user_auth_generation ||
        grant.status !== 'active' ||
        !tokenEquals(grant.secret_hash, hash)
      ) {
        return (reply as FastifyReply).code(401).send({ error: 'unauthenticated', message: 'hatirlama gecersiz' });
      }

      const { generateToken } = await import('../auth/token.js');
      const session = generateToken('active');

      await db
        .insertInto('auth_sessions')
        .values({
          id: crypto.randomUUID(),
          user_id: grant.user_id,
          session_family_id: grant.session_family_id,
          token_hash: session.hash,
          created_at: new Date(),
          last_user_activity_at: new Date(),
          idle_expires_at: new Date(Date.now() + 30 * 60 * 1000),
          credential_version: grant.user_credential_version,
          authorization_version: 1,
          auth_generation: grant.user_auth_generation,
        })
        .execute();

      setAuthCookies(reply, {
        activeId: session.raw,
        activeToken: session.raw,
      });

      return reply.send({ role: grant.role });
    },
  );

  app.post(
    '/v1/auth/logout',
    {
      schema: {
        response: { 200: Type.Object({ ok: Type.Boolean() }) },
      },
    },
    async (req, reply) => {
      const jar = req.cookies as Record<string, string | undefined>;
      const activeCookie = Object.keys(jar)
        .filter((k) => k.startsWith('__Host-tp-a-'))
        .map((k) => ({ name: k, value: jar[k]! }))
        .at(0);

      if (!activeCookie) {
        return reply.send({ ok: true });
      }

      const hash = tokenHash('active', activeCookie.value);
      const session = await db
        .selectFrom('auth_sessions')
        .select('session_family_id')
        .where('token_hash', '=', hash)
        .where('revoked_at', 'is', null)
        .executeTakeFirst();

      if (session) {
        await revokeFamily(db, session.session_family_id, new Date());
      }

      reply.clearCookie(activeCookie.name, { path: '/' });
      return reply.send({ ok: true });
    },
  );

  app.post(
    '/v1/auth/password',
    {
      schema: {
        body: Type.Object(
          {
            current_password: Type.String({ minLength: 8, maxLength: 128 }),
            new_password: Type.String({ minLength: 8, maxLength: 128 }),
          },
          { additionalProperties: false },
        ),
        response: {
          200: Type.Object({ ok: Type.Boolean() }),
          default: Type.Object({ error: Type.String(), message: Type.String() }),
        },
      },
    },
    async (req, reply) => {
      if (!requireCsrf(req)) {
        return (reply as FastifyReply).code(403).send({ error: 'csrf_invalid', message: 'csrf gecersiz' });
      }

      const jar = req.cookies as Record<string, string | undefined>;
      const activeCookie = Object.keys(jar)
        .filter((k) => k.startsWith('__Host-tp-a-'))
        .map((k) => ({ name: k, value: jar[k]! }))
        .at(0);

      if (!activeCookie) {
        return (reply as FastifyReply).code(401).send({ error: 'unauthenticated', message: 'oturum yok' });
      }

      const session = await validateSession(db, activeCookie.value);
      if (!session) {
        return (reply as FastifyReply).code(401).send({ error: 'unauthenticated', message: 'oturum gecersiz' });
      }

      const { current_password, new_password } = req.body as {
        current_password: string;
        new_password: string;
      };

      const user = await db
        .selectFrom('users')
        .select(['password_hash'])
        .where('id', '=', session.user_id)
        .executeTakeFirst();

      if (!user || !(await verifyPassword(user.password_hash, current_password))) {
        return (reply as FastifyReply).code(403).send({ error: 'forbidden', message: 'parola hatali' });
      }

      const newHash = await hashPassword(new_password);

      await db.transaction().execute(async (trx) => {
        await trx
          .updateTable('users')
          .set({ password_hash: newHash, credential_version: (eb) => eb('credential_version', '+', 1) })
          .where('id', '=', session.user_id)
          .execute();

        await revokeAllUserAccess(trx, session.user_id, new Date());
      });

      return reply.send({ ok: true });
    },
  );

  app.post(
    '/v1/auth/reset/request',
    {
      schema: {
        body: Type.Object({ email: Type.String() }, { additionalProperties: false }),
        response: {
          200: Type.Object({ message: Type.String() }),
        },
      },
    },
    async (req, reply) => {
      const { email } = req.body as { email: string };
      const key = normalizeEmailKey(email);
      const user = await db
        .selectFrom('users')
        .select(['id', 'status'])
        .where('email_key', '=', key)
        .executeTakeFirst();

      if (user && user.status === 'active') {
        await createResetToken(db, user.id);
      }

      return reply.send({ message: 'talep alindi' });
    },
  );

  app.post(
    '/v1/auth/reset/consume',
    {
      schema: {
        body: Type.Object(
          {
            reset_token: Type.String(),
            new_password: Type.String({ minLength: 8, maxLength: 128 }),
          },
          { additionalProperties: false },
        ),
        response: {
          200: Type.Object({ ok: Type.Boolean() }),
          default: Type.Object({ error: Type.String(), message: Type.String() }),
        },
      },
    },
    async (req, reply) => {
      if (!requireCsrf(req)) {
        return (reply as FastifyReply).code(403).send({ error: 'csrf_invalid', message: 'csrf gecersiz' });
      }

      const { reset_token, new_password } = req.body as {
        reset_token: string;
        new_password: string;
      };

      const consumed = await consumeResetToken(db, reset_token);
      if (!consumed.ok) {
        return (reply as FastifyReply).code(409).send({ error: 'reset_invalid', message: 'reset gecersiz' });
      }

      const newHash = await hashPassword(new_password);

      await db.transaction().execute(async (trx) => {
        await trx
          .updateTable('users')
          .set({
            password_hash: newHash,
            credential_version: (eb) => eb('credential_version', '+', 1),
            auth_generation: (eb) => eb('auth_generation', '+', 1),
          })
          .where('id', '=', consumed.userId)
          .execute();

        await revokeAllUserAccess(trx, consumed.userId, new Date());
      });

      return reply.send({ ok: true });
    },
  );

  app.get(
    '/v1/me',
    {
      schema: {
        response: {
          200: Type.Object(
            {
              role: Type.String(),
              status: Type.String(),
              desk_id: Type.Union([Type.String(), Type.Null()]),
            },
            { additionalProperties: false },
          ),
          default: Type.Object({ error: Type.String(), message: Type.String() }),
        },
      },
    },
    async (req, reply) => {
      const jar = req.cookies as Record<string, string | undefined>;
      const activeCookie = Object.keys(jar)
        .filter((k) => k.startsWith('__Host-tp-a-'))
        .map((k) => ({ name: k, value: jar[k]! }))
        .at(0);

      if (!activeCookie) {
        return (reply as FastifyReply).code(401).send({ error: 'unauthenticated', message: 'oturum yok' });
      }

      const session = await validateSession(db, activeCookie.value);
      if (!session) {
        return (reply as FastifyReply).code(401).send({ error: 'unauthenticated', message: 'oturum gecersiz' });
      }

      return reply.send({
        role: session.role,
        status: session.status,
        desk_id: session.desk_id,
      });
    },
  );
}
