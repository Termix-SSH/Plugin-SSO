import type { PluginContext } from "@termix-ssh/plugin-sdk/backend";
import { fetchWithOptions, providerFetchOptions } from "./oidc-protocol.js";
import type { ProviderStore } from "./providers.js";
import type { ResolvedProvider } from "./types.js";

/** What core gives a login method's logoutRedirect (Termix 26.11.3). */
export interface LogoutSession {
  providerId: number | null;
  sub: string | null;
  sid: string | null;
  baseUrl: string;
}

const DISCOVERY_TTL_MS = 60 * 60_000;

/**
 * RP initiated sign out: sends the browser to the provider's sign out page
 * with the client id and a way back, so the provider ends its own session.
 */
export function createLogout(ctx: PluginContext, store: ProviderStore) {
  const endpoints = new Map<string, { url: string | null; at: number }>();

  async function discovered(
    provider: ResolvedProvider,
  ): Promise<string | null> {
    const issuer = provider.config.issuer_url?.replace(/\/+$/, "");
    if (!issuer) return null;
    const cached = endpoints.get(issuer);
    if (cached && Date.now() - cached.at < DISCOVERY_TTL_MS) return cached.url;
    let url: string | null = null;
    try {
      const res = await fetchWithOptions(
        `${issuer}/.well-known/openid-configuration`,
        providerFetchOptions(provider.config),
      );
      if (res.ok) {
        const doc = (await res.json()) as Record<string, unknown>;
        if (typeof doc.end_session_endpoint === "string") {
          url = doc.end_session_endpoint;
        }
      }
    } catch (error) {
      ctx.log.warn(`OIDC discovery for sign out failed: ${String(error)}`);
      return null;
    }
    endpoints.set(issuer, { url, at: Date.now() });
    return url;
  }

  return async function logoutRedirect(
    session: LogoutSession,
  ): Promise<string | null> {
    const provider = await store.resolve(session.providerId);
    if (!provider || provider.type !== "oidc") return null;
    if (provider.config.sign_out_at_provider !== "1") return null;
    const endpoint =
      provider.config.end_session_url?.trim() || (await discovered(provider));
    if (!endpoint) return null;
    let url: URL;
    try {
      url = new URL(endpoint);
    } catch {
      return null;
    }
    if (url.protocol !== "https:" && url.protocol !== "http:") return null;
    url.searchParams.set("client_id", provider.config.client_id);
    if (session.baseUrl) {
      url.searchParams.set("post_logout_redirect_uri", `${session.baseUrl}/`);
    }
    return url.toString();
  };
}
