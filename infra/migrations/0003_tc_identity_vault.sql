-- F1-c: T.C. kimlik kasıtlı şifreli saklama (O07)
-- Düz metin kolon yoktur; yalnız ciphertext/nonce/tag/key_id/sürüm.

BEGIN;

CREATE TABLE IF NOT EXISTS tc_identity_vault (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id           uuid NOT NULL,
  tc_ciphertext     bytea NOT NULL,
  tc_nonce          bytea NOT NULL,
  tc_auth_tag       bytea NOT NULL,
  tc_key_id         text NOT NULL,
  tc_crypto_version text NOT NULL,
  created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS tc_identity_vault_user_unique
  ON tc_identity_vault (user_id);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'tc_identity_vault_user_fk'
  ) THEN
    ALTER TABLE tc_identity_vault ADD CONSTRAINT tc_identity_vault_user_fk
      FOREIGN KEY (user_id) REFERENCES users (id);
  END IF;
END
$$;

COMMIT;
