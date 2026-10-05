-- sso 0003: drop legacy_callback
-- Every provider sends the plugin's own redirect URI from 26.10.0.

ALTER TABLE "p_sso_providers" DROP COLUMN "legacy_callback";
