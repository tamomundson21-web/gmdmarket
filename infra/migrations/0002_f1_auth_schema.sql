-- F1-a: Auth temel şeması
-- Sözleşme: f1-kayit-oturum-api-sozlesmesi.md + f1-schema.md
-- Kısıtlar: F1-C01..C06, Kİ1, EP1, AG4, O07

BEGIN;

-- ---- users ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
  id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  desk_id                 uuid,
  role                    text NOT NULL CHECK (role IN ('master', 'sub_admin', 'user')),
  status                  text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  email                   text NOT NULL,
  email_key               text NOT NULL,
  password_hash           text NOT NULL,
  profile_version         bigint NOT NULL DEFAULT 1 CHECK (profile_version > 0),
  credential_version      bigint NOT NULL DEFAULT 1 CHECK (credential_version > 0),
  authorization_version   bigint NOT NULL DEFAULT 1 CHECK (authorization_version > 0),
  auth_generation         bigint NOT NULL DEFAULT 1 CHECK (auth_generation > 0),
  customer_trading_enabled boolean NOT NULL DEFAULT true,
  created_by              uuid,
  created_at              timestamptz NOT NULL DEFAULT now()
);

-- F1-C01: email_key UNIQUE (kurulum içi)
CREATE UNIQUE INDEX IF NOT EXISTS users_email_key_unique
  ON users (email_key);

-- F1-C02: master desk NULL, sub_admin desk NOT NULL
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'users_role_desk_check'
  ) THEN
    ALTER TABLE users ADD CONSTRAINT users_role_desk_check
      CHECK (
        (role = 'master' AND desk_id IS NULL)
        OR (role = 'sub_admin' AND desk_id IS NOT NULL)
        OR (role = 'user')
      );
  END IF;
END
$$;

-- ---- desks ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS desks (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name              text NOT NULL,
  owner_id          uuid NOT NULL,
  default_currency  text NOT NULL DEFAULT 'USD' CHECK (default_currency = 'USD'),
  status            text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  created_at        timestamptz NOT NULL DEFAULT now()
);

-- F1-C02: desks.owner_id UNIQUE (birebir)
CREATE UNIQUE INDEX IF NOT EXISTS desks_owner_unique ON desks (owner_id);

-- users.desk_id -> desks.id
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'users_desk_fk'
  ) THEN
    ALTER TABLE users ADD CONSTRAINT users_desk_fk
      FOREIGN KEY (desk_id) REFERENCES desks (id);
  END IF;
END
$$;

-- ---- accounts ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS accounts (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id               uuid NOT NULL,
  desk_id               uuid NOT NULL,
  currency              text NOT NULL DEFAULT 'USD' CHECK (currency = 'USD'),
  balance               numeric(20,2) NOT NULL DEFAULT 0,
  last_publication_seq  bigint NOT NULL DEFAULT 0,
  last_operation_seq    bigint NOT NULL DEFAULT 0,
  state_version         bigint NOT NULL DEFAULT 1,
  status                text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'closed')),
  created_at            timestamptz NOT NULL DEFAULT now()
);

-- F1-C03: accounts(id,user_id,desk_id) tam UNIQUE
CREATE UNIQUE INDEX IF NOT EXISTS accounts_user_desk_unique
  ON accounts (id, user_id, desk_id);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'accounts_user_fk'
  ) THEN
    ALTER TABLE accounts ADD CONSTRAINT accounts_user_fk
      FOREIGN KEY (user_id) REFERENCES users (id);
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'accounts_desk_fk'
  ) THEN
    ALTER TABLE accounts ADD CONSTRAINT accounts_desk_fk
      FOREIGN KEY (desk_id) REFERENCES desks (id);
  END IF;
END
$$;

-- ---- registration_queue ---------------------------------------------------
CREATE TABLE IF NOT EXISTS registration_queue (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id             uuid NOT NULL,
  origin              text NOT NULL CHECK (origin IN ('self_without_invite', 'self_with_invite', 'sub_admin_created')),
  invite_id           uuid,
  version             bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  requested_at         timestamptz NOT NULL DEFAULT now(),
  status              text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
  reviewed_by         uuid,
  reviewed_at         timestamptz,
  initial_account_id  uuid
);

-- F1-C03: registration_queue.user_id UNIQUE
CREATE UNIQUE INDEX IF NOT EXISTS registration_queue_user_unique
  ON registration_queue (user_id);
CREATE UNIQUE INDEX IF NOT EXISTS registration_queue_initial_account_unique
  ON registration_queue (initial_account_id);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'registration_queue_user_fk'
  ) THEN
    ALTER TABLE registration_queue ADD CONSTRAINT registration_queue_user_fk
      FOREIGN KEY (user_id) REFERENCES users (id);
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'registration_queue_initial_account_fk'
  ) THEN
    ALTER TABLE registration_queue ADD CONSTRAINT registration_queue_initial_account_fk
      FOREIGN KEY (initial_account_id) REFERENCES accounts (id);
  END IF;
END
$$;

-- ---- auth_session_families -----------------------------------------------
CREATE TABLE IF NOT EXISTS auth_session_families (
  id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id                 uuid NOT NULL,
  created_at              timestamptz NOT NULL DEFAULT now(),
  last_user_activity_at   timestamptz,
  revoked_at              timestamptz,
  version                 bigint NOT NULL DEFAULT 1 CHECK (version > 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS auth_session_families_user_unique
  ON auth_session_families (id, user_id);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'auth_session_families_user_fk'
  ) THEN
    ALTER TABLE auth_session_families ADD CONSTRAINT auth_session_families_user_fk
      FOREIGN KEY (user_id) REFERENCES users (id);
  END IF;
END
$$;

-- ---- auth_sessions --------------------------------------------------------
CREATE TABLE IF NOT EXISTS auth_sessions (
  id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id                 uuid NOT NULL,
  session_family_id       uuid NOT NULL,
  token_hash              bytea NOT NULL,
  created_at              timestamptz NOT NULL DEFAULT now(),
  last_user_activity_at   timestamptz,
  idle_expires_at         timestamptz,
  absolute_expires_at     timestamptz,
  revoked_at              timestamptz,
  credential_version      bigint NOT NULL,
  authorization_version   bigint NOT NULL,
  auth_generation         bigint NOT NULL
);

CREATE INDEX IF NOT EXISTS auth_sessions_user_family_idx
  ON auth_sessions (user_id, session_family_id);
CREATE UNIQUE INDEX IF NOT EXISTS auth_sessions_token_hash_unique
  ON auth_sessions (token_hash);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'auth_sessions_user_fk'
  ) THEN
    ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_user_fk
      FOREIGN KEY (user_id) REFERENCES users (id);
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'auth_sessions_family_fk'
  ) THEN
    ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_family_fk
      FOREIGN KEY (session_family_id) REFERENCES auth_session_families (id);
  END IF;
END
$$;

-- ---- remembered_browser_grants -------------------------------------------
CREATE TABLE IF NOT EXISTS remembered_browser_grants (
  id                          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id                     uuid NOT NULL,
  session_family_id           uuid NOT NULL,
  secret_hash                 bytea NOT NULL,
  credential_authenticated_at timestamptz NOT NULL,
  expires_at                  timestamptz NOT NULL,
  revoked_at                  timestamptz,
  credential_version          bigint NOT NULL,
  auth_generation             bigint NOT NULL
);

CREATE INDEX IF NOT EXISTS remembered_browser_grants_user_family_idx
  ON remembered_browser_grants (user_id, session_family_id);
CREATE UNIQUE INDEX IF NOT EXISTS remembered_browser_grants_secret_hash_unique
  ON remembered_browser_grants (secret_hash);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'remembered_browser_grants_user_fk'
  ) THEN
    ALTER TABLE remembered_browser_grants ADD CONSTRAINT remembered_browser_grants_user_fk
      FOREIGN KEY (user_id) REFERENCES users (id);
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'remembered_browser_grants_family_fk'
  ) THEN
    ALTER TABLE remembered_browser_grants ADD CONSTRAINT remembered_browser_grants_family_fk
      FOREIGN KEY (session_family_id) REFERENCES auth_session_families (id);
  END IF;
END
$$;

-- ---- password_reset_tokens ------------------------------------------------
CREATE TABLE IF NOT EXISTS password_reset_tokens (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id             uuid NOT NULL,
  token_hash          bytea NOT NULL,
  expires_at          timestamptz NOT NULL,
  used_at             timestamptz,
  created_at          timestamptz NOT NULL DEFAULT now(),
  credential_version  bigint NOT NULL,
  auth_generation     bigint NOT NULL,
  revoked_at          timestamptz
);

CREATE UNIQUE INDEX IF NOT EXISTS password_reset_tokens_token_hash_unique
  ON password_reset_tokens (token_hash);
CREATE INDEX IF NOT EXISTS password_reset_tokens_user_expiry_idx
  ON password_reset_tokens (user_id, expires_at);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'password_reset_tokens_user_fk'
  ) THEN
    ALTER TABLE password_reset_tokens ADD CONSTRAINT password_reset_tokens_user_fk
      FOREIGN KEY (user_id) REFERENCES users (id);
  END IF;
END
$$;

-- ---- f1_command_results --------------------------------------------------
CREATE TABLE IF NOT EXISTS f1_command_results (
  id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  installation_id         uuid NOT NULL,
  actor_id                uuid,
  command_key             text NOT NULL,
  action                  text NOT NULL,
  target_user_id          uuid,
  request_fingerprint     bytea NOT NULL,
  fingerprint_key_id      text NOT NULL,
  operation_generation    bigint NOT NULL,
  accept_until            timestamptz NOT NULL,
  outcome                 text NOT NULL CHECK (outcome IN ('applied', 'rejected', 'no_op')),
  result_ref              text,
  committed_at            timestamptz,
  retention_anchor_at     timestamptz,
  created_at              timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS f1_command_results_installation_command_unique
  ON f1_command_results (installation_id, command_key);
CREATE INDEX IF NOT EXISTS f1_command_results_target_user_idx
  ON f1_command_results (target_user_id);

-- ---- desk_invites ---------------------------------------------------------
CREATE TABLE IF NOT EXISTS desk_invites (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  desk_id     uuid NOT NULL,
  code_hash   bytea NOT NULL,
  created_by  uuid NOT NULL,
  max_uses    integer NOT NULL CHECK (max_uses > 0),
  used_count  integer NOT NULL DEFAULT 0 CHECK (used_count >= 0),
  expires_at  timestamptz NOT NULL,
  active      boolean NOT NULL DEFAULT true,
  created_at  timestamptz NOT NULL DEFAULT now(),
  CHECK (used_count <= max_uses)
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'desk_invites_desk_fk'
  ) THEN
    ALTER TABLE desk_invites ADD CONSTRAINT desk_invites_desk_fk
      FOREIGN KEY (desk_id) REFERENCES desks (id);
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'desk_invites_created_by_fk'
  ) THEN
    ALTER TABLE desk_invites ADD CONSTRAINT desk_invites_created_by_fk
      FOREIGN KEY (created_by) REFERENCES users (id);
  END IF;
END
$$;

COMMIT;
