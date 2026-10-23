import { getDb, closeDb } from './db/index.js';
import { hashPassword } from './auth/password.js';

const db = getDb();
const now = new Date();

const email = 'master@gmdmarket.com';
const existing = await db.selectFrom('users').select('id').where('email_key', '=', email).executeTakeFirst();

if (!existing) {
  const hash = await hashPassword('MasterParola123');
  await db
    .insertInto('users')
    .values({
      id: crypto.randomUUID(),
      email,
      email_key: email,
      password_hash: hash,
      role: 'master',
      status: 'active',
      desk_id: null,
      profile_version: 1,
      credential_version: 1,
      authorization_version: 1,
      auth_generation: 1,
      customer_trading_enabled: true,
      created_at: now,
    })
    .execute();
  console.log('MASTER_OLUSTURULDU');
} else {
  console.log('MASTER_ZATEN_VAR');
}

await closeDb();
