import type { PluginApiClient } from "@termix-ssh/plugin-sdk/frontend";

export type SsoProviderType = "oidc" | "github" | "google" | "saml";

export interface SsoProvider {
  id: number;
  name: string;
  type: SsoProviderType;
  enabled: boolean;
  displayOrder: number;
  legacyCallback: boolean;
  config: Record<string, unknown>;
  hasClientSecret: boolean;
  hasSpPrivateKey?: boolean;
  redirectUri: string;
  samlEntityId?: string;
  samlMetadataUrl?: string;
}

export interface SamlIdpFields {
  saml_idp_issuer: string;
  saml_entry_point: string;
  saml_idp_cert: string;
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
        result?: string;
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
    async readSamlMetadata(source: { url?: string; xml?: string }) {
      return (await api.post<SamlIdpFields>("/providers/saml-metadata", source))
        .data;
    },
    async remove(id: number) {
      await api.delete(`/providers/${id}`);
    },
  };
}
