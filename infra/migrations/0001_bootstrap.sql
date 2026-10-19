-- GMD Market — F1 baslangic sablonu
-- Kysely ile calistirilir: psql -f ile de elle calistirilabilir.
-- SIRA ONEMLI: once roller, sonra tablolar.

BEGIN;

-- ---- Roller -------------------------------------------------------------
-- Normal DB rolu sema sahibi/superuser/BYPASSRLS olmaz.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gmd_app') THEN
    CREATE ROLE gmd_app NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gmd_migrator') THEN
    CREATE ROLE gmd_migrator NOLOGIN;
  END IF;
END
$$;

-- ---- Semasi -------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS gmd AUTHORIZATION gmd_migrator;

-- ---- Tablo ornegi (F1 kayit/auth fazinda genisleyecek) ------------------
CREATE TABLE IF NOT EXISTS gmd.health_probe (
  id          integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  checked_at  timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE gmd.health_probe IS
  'Sadece baglanti/boot dogrulama. F1 kayit/auth tablolariyla iliskisiz.';

COMMIT;
