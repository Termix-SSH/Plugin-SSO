-- sso 0004: restore legacy_callback
-- 0003 moved every provider to the new redirect URI, which broke sign in for
-- identity providers still set up with /users/oidc/callback. Providers made
-- before 2.9.0 go back to it.

ALTER TABLE "p_sso_providers" ADD COLUMN "legacy_callback" boolean NOT NULL DEFAULT false;
UPDATE "p_sso_providers" SET "legacy_callback" = true WHERE "created_at" < '2026-10-01 21:20:00';
