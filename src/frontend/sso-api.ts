import type { PluginApiClient } from "@termix-ssh/plugin-sdk/frontend";

export type SsoProviderType = "oidc" | "github" | "google";

export interface SsoProvider {
  id: number;
  name: string;
  type: SsoProviderType;
  enabled: boolean;
  displayOrder: number;
  legacyCallback: boolean;
  config: Record<string, unknown>;
  hasClientSecret: boolean;
  redirectUri: string;
}

export interface SsoLink {
  id: string;
  label: string;
  linked: boolean;
}

export interface SsoProviderInput {
  name?: string;
  type?: SsoProviderType;
  enabled?: boolean;
  legacyCallback?: boolean;
  config?: Record<string, unknown>;
}

/** Paths are relative to /plugin-api/sso/. */
export function createSsoApi(api: PluginApiClient) {
  return {
    async links() {
      const { data } = await api.get<{
        allowed: boolean;
        providers: SsoLink[];
      }>("/links");
      return data;
    },
    async startLink(provider: string) {
      const { data } = await api.post<{ redirectUrl: string }>("/links/start", {
        provider,
      });
      return data.redirectUrl;
    },
    async unlink(provider: string) {
      await api.delete(`/links/${encodeURIComponent(provider)}`);
    },
    async list() {
      const { data } = await api.get<{
        providers: SsoProvider[];
        newRedirectUri: string;
      }>("/providers");
      return data;
    },
    async create(input: SsoProviderInput) {
      return (await api.post<SsoProvider>("/providers", input)).data;
    },
    async update(id: number, input: SsoProviderInput) {
      return (await api.put<SsoProvider>(`/providers/${id}`, input)).data;
    },
    async remove(id: number) {
      await api.delete(`/providers/${id}`);
    },
  };
}
