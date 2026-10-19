import { Kysely, PostgresDialect } from 'kysely';
import pg from 'pg';

export interface Users {
  id: string;
  desk_id: string | null;
  role: 'master' | 'sub_admin' | 'user';
  status: 'active' | 'suspended';
  email: string;
  email_key: string;
  password_hash: string;
  profile_version: number;
  credential_version: number;
  authorization_version: number;
  auth_generation: number;
  customer_trading_enabled: boolean;
  created_by: string | null;
  created_at: Date;
}

export interface Desks {
  id: string;
  name: string;
  owner_id: string;
  default_currency: string;
  status: 'active' | 'suspended';
  created_at: Date;
}

export interface Accounts {
  id: string;
  user_id: string;
  desk_id: string;
  currency: string;
  balance: string;
  last_publication_seq: number;
  last_operation_seq: number;
  state_version: number;
  status: 'active' | 'suspended' | 'closed';
  created_at: Date;
}

export interface RegistrationQueue {
  id: string;
  user_id: string;
  origin: 'self_without_invite' | 'self_with_invite' | 'sub_admin_created';
  invite_id: string | null;
  version: number;
  requested_at: Date;
  status: 'pending' | 'approved' | 'rejected';
  reviewed_by: string | null;
  reviewed_at: Date | null;
  initial_account_id: string | null;
}

export interface AuthSessionFamilies {
  id: string;
  user_id: string;
  created_at: Date;
  last_user_activity_at: Date | null;
  revoked_at: Date | null;
  version: number;
}

export interface AuthSessions {
  id: string;
  user_id: string;
  session_family_id: string;
  token_hash: Buffer;
  created_at: Date;
  last_user_activity_at: Date | null;
  idle_expires_at: Date | null;
  absolute_expires_at: Date | null;
  revoked_at: Date | null;
  credential_version: number;
  authorization_version: number;
  auth_generation: number;
}

export interface RememberedBrowserGrants {
  id: string;
  user_id: string;
  session_family_id: string;
  secret_hash: Buffer;
  credential_authenticated_at: Date;
  expires_at: Date;
  revoked_at: Date | null;
  credential_version: number;
  auth_generation: number;
}

export interface PasswordResetTokens {
  id: string;
  user_id: string;
  token_hash: Buffer;
  expires_at: Date;
  used_at: Date | null;
  created_at: Date;
  credential_version: number;
  auth_generation: number;
  revoked_at: Date | null;
}

export interface F1CommandResults {
  id: string;
  installation_id: string;
  actor_id: string | null;
  command_key: string;
  action: string;
  target_user_id: string | null;
  request_fingerprint: Buffer;
  fingerprint_key_id: string;
  operation_generation: string;
  accept_until: Date;
  outcome: 'applied' | 'rejected' | 'no_op';
  result_ref: string | null;
  committed_at: Date | null;
  retention_anchor_at: Date | null;
  created_at: Date;
}

export interface DeskInvites {
  id: string;
  desk_id: string;
  code_hash: Buffer;
  created_by: string;
  max_uses: number;
  used_count: number;
  expires_at: Date;
  active: boolean;
  created_at: Date;
}

export interface HealthProbe {
  id: number;
  checked_at: Date;
}

export interface Database {
  users: Users;
  desks: Desks;
  accounts: Accounts;
  registration_queue: RegistrationQueue;
  auth_session_families: AuthSessionFamilies;
  auth_sessions: AuthSessions;
  remembered_browser_grants: RememberedBrowserGrants;
  password_reset_tokens: PasswordResetTokens;
  f1_command_results: F1CommandResults;
  desk_invites: DeskInvites;
  health_probe: HealthProbe;
}

let instance: Kysely<Database> | null = null;

export function getDb(): Kysely<Database> {
  if (instance) return instance;

  const url = process.env.DATABASE_URL;
  if (!url) throw new Error('DATABASE_URL tanimli degil');

  instance = new Kysely<Database>({
    dialect: new PostgresDialect({
      pool: new pg.Pool({
        connectionString: url,
        max: 10,
        idleTimeoutMillis: 30_000,
        connectionTimeoutMillis: 5_000,
      }),
    }),
  });

  return instance;
}

export async function closeDb(): Promise<void> {
  if (!instance) return;
  await instance.destroy();
  instance = null;
}
