import type { Kysely } from 'kysely';
import type { Database } from '../db/index.js';
import { generateToken, tokenEquals, tokenHash } from './token.js';

const IDLE_USER_MS = 30 * 60 * 1000;
const IDLE_ADMIN_MS = 90 * 60 * 1000;
const REMEMBER_DAYS = 30;
const RESET_TTL_MS = 60 * 60 * 1000;
const MAX_FAMILIES = 2;

export type SessionOutcome =
  | { ok: true; sessionToken: string; rememberToken: string | undefined; familyId: string }
  | { ok: false; reason: 'invalid_credentials' | 'suspended' | 'trading_disabled' | 'error' };

function idleFor(role: 'master' | 'sub_admin' | 'user'): number {
  return role === 'user' ? IDLE_USER_MS : IDLE_ADMIN_MS;
}

export async function login(
  db: Kysely<Database>,
  user: { id: string; role: 'master' | 'sub_admin' | 'user'; status: string },
  passwordOk: boolean,
  rememberMe: boolean,
  now: Date = new Date(),
): Promise<SessionOutcome> {
  if (!passwordOk) return { ok: false, reason: 'invalid_credentials' };
  if (user.status !== 'active') return { ok: false, reason: 'suspended' };

  const remember = user.role === 'user' && rememberMe === true;

  const created = await db.transaction().execute(async (trx) => {
    const locked = await trx
      .selectFrom('users')
      .select(['id', 'status', 'role', 'credential_version', 'auth_generation'])
      .where('id', '=', user.id)
      .forUpdate()
      .executeTakeFirst();

    if (!locked || locked.status !== 'active') {
      return { ok: false as const, reason: 'suspended' as const };
    }

    const activeSessionFamilies = await trx
      .selectFrom('auth_sessions as s')
      .innerJoin('auth_session_families as f', 'f.id', 's.session_family_id')
      .select(['f.id', 'f.last_user_activity_at', 'f.created_at'])
      .where('f.user_id', '=', user.id)
      .where('f.revoked_at', 'is', null)
      .where('s.revoked_at', 'is', null)
      .where('s.idle_expires_at', '>', now)
      .groupBy(['f.id', 'f.last_user_activity_at', 'f.created_at'])
      .execute();

    const liveGrantFamilies = await trx
      .selectFrom('remembered_browser_grants as g')
      .innerJoin('auth_session_families as f', 'f.id', 'g.session_family_id')
      .select(['f.id', 'f.last_user_activity_at', 'f.created_at'])
      .where('f.user_id', '=', user.id)
      .where('f.revoked_at', 'is', null)
      .where('g.revoked_at', 'is', null)
      .where('g.expires_at', '>', now)
      .groupBy(['f.id', 'f.last_user_activity_at', 'f.created_at'])
      .execute();

    const merged = new Map<string, { last: Date | null; created: Date }>();
    for (const f of [...activeSessionFamilies, ...liveGrantFamilies]) {
      const prev = merged.get(f.id);
      const cur = { last: f.last_user_activity_at, created: f.created_at };
      if (!prev) {
        merged.set(f.id, cur);
      } else {
        const prevT = prev.last?.getTime() ?? 0;
        const curT = cur.last?.getTime() ?? 0;
        if (curT > prevT) merged.set(f.id, cur);
      }
    }
    const liveFamilies = [...merged.entries()].map(([id, meta]) => ({
      id,
      last: meta.last,
      created: meta.created,
    }));

    if (liveFamilies.length >= MAX_FAMILIES) {
      const lru = [...liveFamilies].sort((a, b) => {
        const at = a.last?.getTime() ?? 0;
        const bt = b.last?.getTime() ?? 0;
        if (at !== bt) return at - bt;
        return a.created.getTime() - b.created.getTime();
      })[0]!;
      await revokeFamily(trx, lru.id, now);
    }

    const familyRow = await trx
      .insertInto('auth_session_families')
      .values({
        id: crypto.randomUUID(),
        user_id: user.id,
        created_at: now,
        last_user_activity_at: now,
        version: 1,
      })
      .returning('id')
      .executeTakeFirstOrThrow();
    const targetFamily = familyRow.id;

    const session = generateToken('active');
    const idleMs = idleFor(locked.role);

    await trx
      .insertInto('auth_sessions')
      .values({
        id: crypto.randomUUID(),
        user_id: user.id,
        session_family_id: targetFamily,
        token_hash: session.hash,
        created_at: now,
        last_user_activity_at: now,
        idle_expires_at: new Date(now.getTime() + idleMs),
        credential_version: locked.credential_version,
        authorization_version: 1,
        auth_generation: locked.auth_generation,
      })
      .execute();

    let rememberToken: string | undefined;

    if (remember) {
      const grant = generateToken('remember');
      await trx
        .insertInto('remembered_browser_grants')
        .values({
          id: crypto.randomUUID(),
          user_id: user.id,
          session_family_id: targetFamily,
          secret_hash: grant.hash,
          credential_authenticated_at: now,
          expires_at: new Date(now.getTime() + REMEMBER_DAYS * 24 * 60 * 60 * 1000),
          credential_version: locked.credential_version,
          auth_generation: locked.auth_generation,
        })
        .execute();
      rememberToken = grant.raw;
    }

    return { ok: true as const, sessionToken: session.raw, rememberToken, familyId: targetFamily };
  });

  return created;
}

export async function revokeFamily(
  trx: Kysely<Database>,
  familyId: string,
  now: Date,
): Promise<void> {
  await trx
    .updateTable('auth_sessions')
    .set({ revoked_at: now })
    .where('session_family_id', '=', familyId)
    .where('revoked_at', 'is', null)
    .execute();
  await trx
    .updateTable('remembered_browser_grants')
    .set({ revoked_at: now })
    .where('session_family_id', '=', familyId)
    .where('revoked_at', 'is', null)
    .execute();
  await trx
    .updateTable('auth_session_families')
    .set({ revoked_at: now })
    .where('id', '=', familyId)
    .where('revoked_at', 'is', null)
    .execute();
}

export async function revokeAllUserAccess(
  db: Kysely<Database>,
  userId: string,
  now: Date,
): Promise<void> {
  await db
    .updateTable('auth_sessions')
    .set({ revoked_at: now })
    .where('user_id', '=', userId)
    .where('revoked_at', 'is', null)
    .execute();
  await db
    .updateTable('remembered_browser_grants')
    .set({ revoked_at: now })
    .where('user_id', '=', userId)
    .where('revoked_at', 'is', null)
    .execute();
  await db
    .updateTable('auth_session_families')
    .set({ revoked_at: now })
    .where('user_id', '=', userId)
    .where('revoked_at', 'is', null)
    .execute();
}

export async function validateSession(
  db: Kysely<Database>,
  rawToken: string,
  now: Date = new Date(),
) {
  const hash = tokenHash('active', rawToken);
  const row = await db
    .selectFrom('auth_sessions as s')
    .innerJoin('auth_session_families as f', 'f.id', 's.session_family_id')
    .innerJoin('users as u', 'u.id', 's.user_id')
    .select([
      's.id as session_id',
      's.user_id',
      's.session_family_id',
      's.token_hash',
      's.revoked_at',
      's.idle_expires_at',
      's.absolute_expires_at',
      's.credential_version',
      's.auth_generation',
      'f.revoked_at as family_revoked_at',
      'u.role',
      'u.status',
      'u.desk_id',
      'u.credential_version as user_credential_version',
      'u.auth_generation as user_auth_generation',
    ])
    .where('s.token_hash', '=', hash)
    .executeTakeFirst();

  if (!row) return null;
  if (row.revoked_at || row.family_revoked_at) return null;
  if (row.idle_expires_at && row.idle_expires_at.getTime() <= now.getTime()) return null;
  if (row.absolute_expires_at && row.absolute_expires_at.getTime() <= now.getTime()) return null;
  if (row.credential_version !== row.user_credential_version) return null;
  if (row.auth_generation !== row.user_auth_generation) return null;
  if (!tokenEquals(row.token_hash, hash)) return null;

  return row;
}

export async function touchSession(
  db: Kysely<Database>,
  sessionId: string,
  now: Date = new Date(),
) {
  const row = await db
    .selectFrom('auth_sessions')
    .select('idle_expires_at')
    .where('id', '=', sessionId)
    .executeTakeFirst();
  if (!row) return;

  const idleMs = 30 * 60 * 1000;
  const base = row.idle_expires_at ? row.idle_expires_at.getTime() - idleMs : now.getTime();

  await db
    .updateTable('auth_sessions')
    .set({
      last_user_activity_at: now,
      idle_expires_at: new Date(Math.max(now.getTime(), base) + idleMs),
    })
    .where('id', '=', sessionId)
    .execute();
}

export async function createResetToken(
  db: Kysely<Database>,
  userId: string,
  now: Date = new Date(),
) {
  const token = generateToken('reset');
  await db
    .insertInto('password_reset_tokens')
    .values({
      id: crypto.randomUUID(),
      user_id: userId,
      token_hash: token.hash,
      expires_at: new Date(now.getTime() + RESET_TTL_MS),
      created_at: now,
      credential_version: 1,
      auth_generation: 1,
    })
    .execute();
  return token.raw;
}

export async function consumeResetToken(
  db: Kysely<Database>,
  rawToken: string,
  now: Date = new Date(),
) {
  const hash = tokenHash('reset', rawToken);
  const row = await db
    .selectFrom('password_reset_tokens')
    .select(['id', 'user_id', 'expires_at', 'used_at', 'revoked_at'])
    .where('token_hash', '=', hash)
    .executeTakeFirst();

  if (!row) return { ok: false as const, reason: 'invalid' as const };
  if (row.used_at || row.revoked_at) return { ok: false as const, reason: 'used' as const };
  if (row.expires_at.getTime() <= now.getTime()) {
    return { ok: false as const, reason: 'expired' as const };
  }

  await db
    .updateTable('password_reset_tokens')
    .set({ used_at: now })
    .where('id', '=', row.id)
    .execute();

  return { ok: true as const, userId: row.user_id };
}

export async function cleanupExpiredSessions(db: Kysely<Database>, now: Date = new Date()) {
  await db
    .deleteFrom('auth_sessions')
    .where('idle_expires_at', 'is not', null)
    .where('idle_expires_at', '<=', now)
    .where('revoked_at', 'is', null)
    .execute();
}
