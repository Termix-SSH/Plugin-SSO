import { toast } from "sonner";
import type { TermixApp } from "@termix-ssh/plugin-sdk/frontend";
import { LinkedAccounts } from "./LinkedAccounts";
import { OidcLoginButtons } from "./OidcLoginButtons";
import { ProvidersSetting } from "./ProvidersSetting";

const LINK_RESULT_PARAM = "sso_link";

/** Says how a link went once the provider sent the user back. */
function showLinkResult(app: TermixApp) {
  const url = new URL(window.location.href);
  const result = url.searchParams.get(LINK_RESULT_PARAM);
  if (!result) return;
  url.searchParams.delete(LINK_RESULT_PARAM);
  window.history.replaceState(window.history.state, "", url);
  if (result === "linked") toast.success(app.t("links.linked"));
  else if (result === "identity_in_use") toast.error(app.t("links.inUse"));
  else if (result === "provider_linked") toast.error(app.t("links.already"));
  else toast.error(app.t("links.failed"));
}

export function activate(app: TermixApp): void {
  app.registerLoginMethod({
    id: "oidc",
    titleKey: "loginWithSso",
    component: OidcLoginButtons,
    enrollment: LinkedAccounts,
  });
  app.registerSettingsComponent("providers", ProvidersSetting);
  showLinkResult(app);
}
