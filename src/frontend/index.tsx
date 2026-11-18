import type { TermixApp } from "@termix-ssh/plugin-sdk/frontend";
import { LinkedAccounts } from "./LinkedAccounts";
import { ProvidersSetting } from "./ProvidersSetting";

// Termix draws the sign in buttons itself from the providers the backend
// lists; this plugin's screens are the linked accounts and provider settings.
export function activate(app: TermixApp): void {
  app.registerLoginMethod({
    id: "oidc",
    titleKey: "loginWithSso",
    enrollment: LinkedAccounts,
  });
  app.registerSettingsComponent("providers", ProvidersSetting);
}
