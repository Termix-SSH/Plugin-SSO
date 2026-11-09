import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { Button, ListBadge, useConfirm } from "@termix-ssh/plugin-sdk/ui";
import { usePluginApi, useTranslation } from "@termix-ssh/plugin-sdk/frontend";
import { createSsoApi, type SsoLink } from "./sso-api";

function errorCode(error: unknown): string | undefined {
  return (error as { response?: { data?: { code?: string } } })?.response?.data
    ?.code;
}

/** Settings > Security: link or unlink the user's single sign-on accounts. */
export function LinkedAccounts() {
  const { t } = useTranslation();
  const confirm = useConfirm();
  const pluginApi = usePluginApi();
  const api = useMemo(() => createSsoApi(pluginApi), [pluginApi]);
  const [links, setLinks] = useState<SsoLink[]>([]);
  const [allowed, setAllowed] = useState(false);
  const [busy, setBusy] = useState(false);

  async function load() {
    const data = await api.links();
    setLinks(data.providers);
    setAllowed(data.allowed);
  }

  useEffect(() => {
    load().catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [api]);

  async function link(provider: string) {
    setBusy(true);
    try {
      window.location.assign(await api.startLink(provider));
    } catch {
      toast.error(t("links.failed"));
      setBusy(false);
    }
  }

  async function unlink(entry: SsoLink) {
    const ok = await confirm({
      title: t("links.unlinkTitle", { name: entry.label }),
      description: t("links.unlinkBody", { name: entry.label }),
      confirmLabel: t("links.unlink"),
      destructive: true,
    });
    if (!ok) return;
    setBusy(true);
    try {
      await api.unlink(entry.id);
      await load();
    } catch (error) {
      toast.error(
        t(
          errorCode(error) === "last_login"
            ? "links.lastLogin"
            : "links.failed",
        ),
      );
    } finally {
      setBusy(false);
    }
  }

  if (links.length === 0) return null;

  return (
    <div className="flex flex-col gap-2">
      <p className="text-xs text-muted-foreground">
        {t(allowed ? "links.description" : "links.turnedOff")}
      </p>
      {links.map((entry) => (
        <div key={entry.id} className="flex items-center gap-2">
          <span className="min-w-0 flex-1 truncate text-xs">{entry.label}</span>
          {entry.linked && <ListBadge>{t("links.linkedBadge")}</ListBadge>}
          {entry.linked ? (
            <Button
              variant="outline"
              disabled={busy}
              onClick={() => void unlink(entry)}
            >
              {t("links.unlink")}
            </Button>
          ) : (
            allowed && (
              <Button
                variant="outline"
                disabled={busy}
                onClick={() => void link(entry.id)}
              >
                {t("links.link")}
              </Button>
            )
          )}
        </div>
      ))}
    </div>
  );
}
