import crypto from "node:crypto";
import type { Request, Response, Router } from "express";
import {
  LoginMethodError,
  type PluginContext,
} from "@termix-ssh/plugin-sdk/backend";
import {
  applyProviderDefaults,
  fetchWithOptions,
  isValidOidcIssuer,
  validateLogoutToken,
} from "./oidc-protocol.js";
import { isSsoType, type ProviderStore } from "./providers.js";
import {
  LINK_RESULT_PREFIX,
  METHOD_ID,
  redirectUriFor,
  type SsoLogin,
} from "./login.js";

/** A one time link start, opened in a browser tab that has the login. */
const LINK_GO_PREFIX = "link-go:";
const LINK_GO_TTL_MS = 2 * 60 * 1000;
import type { OidcConfig, ProviderRow, SsoProviderType } from "./types.js";
import {
  SAML_METADATA_PATH,
  parseIdpMetadata,
  samlEntityId,
  samlMetadata,
  splitCerts,
} from "./saml.js";

export const PUBLIC_PATHS = [
  "/start",
  "/callback",
  "/backchannel-logout",
  "/config",
  "/saml/acs",
  "/saml/metadata",
];

const LOGOUT_JTI_TTL_MS = 5 * 60 * 1000;
const REQUIRED_OIDC_FIELDS = [
  "client_id",
  "client_secret",
  "issuer_url",
  "authorization_url",
  "token_url",
] as const;
const URL_FIELDS = [
  "authorization_url",
  "token_url",
  "userinfo_url",
  "end_session_url",
] as const;

function isHttpUrl(value: unknown): boolean {
  if (typeof value !== "string") return false;
  try {
    return ["http:", "https:"].includes(new URL(value).protocol);
  } catch {
    return false;
  }
}

function fail(
  ctx: PluginContext,
  res: Response,
  message: string,
  error: unknown,
) {
  ctx.log.error(
    message,
    error instanceof Error ? error : new Error(String(error)),
  );
  res.status(500).json({ error: message });
}

export function registerSsoRoutes(
  router: Router,
  ctx: PluginContext,
  store: ProviderStore,
  login: SsoLogin,
): void {
  // Replayed logout tokens are answered but not acted on twice.
  const seenLogoutJti = new Map<string, number>();

  async function present(req: Request, row: ProviderRow) {
    const config = await store.parseConfig(row.config);
    const {
      client_secret: secret,
      saml_sp_private_key: spKey,
      ...rest
    } = config;
    const baseUrl = ctx.http.baseUrl(req);
    return {
      id: row.id,
      name: row.name,
      type: row.type,
      enabled: !!row.enabled,
      displayOrder: row.displayOrder,
      legacyCallback: !!row.legacyCallback,
      config: rest,
      hasClientSecret: typeof secret === "string" && secret.length > 0,
      hasSpPrivateKey: typeof spKey === "string" && spKey.length > 0,
      redirectUri: redirectUriFor(baseUrl, {
        legacyCallback: !!row.legacyCallback,
        type: row.type as SsoProviderType,
      }),
      ...(row.type === "saml"
        ? {
            samlEntityId: samlEntityId(
              baseUrl,
              config as unknown as OidcConfig,
            ),
            samlMetadataUrl: `${baseUrl}${SAML_METADATA_PATH}?provider=${row.id}`,
          }
        : {}),
    };
  }

  /** Checks a full provider config; returns the error to show, if any. */
  function validate(type: SsoProviderType, config: Partial<OidcConfig>) {
    if (type === "saml") {
      if (!isHttpUrl(config.saml_entry_point)) {
        return "The IdP sign in URL must be an HTTP(S) URL";
      }
      if (splitCerts(config.saml_idp_cert).length === 0) {
        return "The IdP signing certificate is required";
      }
      const key = config.saml_sp_private_key?.trim();
      if (key && !/-----BEGIN (RSA |EC )?PRIVATE KEY-----/.test(key)) {
        return "The signing key must be a PEM private key";
      }
      return null;
    }
    if (type === "oidc") {
      const missing = REQUIRED_OIDC_FIELDS.filter((field) => !config[field]);
      if (missing.length > 0) {
        return `Missing required OIDC fields: ${missing.join(", ")}`;
      }
    } else if (!config.client_id || !config.client_secret) {
      return "Client ID and Client Secret are required";
    }
    if (config.issuer_url && !isValidOidcIssuer(config.issuer_url)) {
      return "Issuer URL must be an HTTP(S) issuer and not a userinfo endpoint";
    }
    for (const field of URL_FIELDS) {
      const value = config[field];
      if (value && !isHttpUrl(value)) {
        return `${field} must be an HTTP(S) URL`;
      }
    }
    return null;
  }

  /**
   * @openapi
   * /plugin-api/sso/start:
   *   get:
   *     summary: Start an SSO login in the browser
   *     description: Public. Sends the browser straight to the provider, so a link can start a login. The provider is picked by the provider query parameter, or the default one.
   *     tags:
   *       - SSO
   *     parameters:
   *       - in: query
   *         name: provider
   *         schema:
   *           type: string
   *     responses:
   *       302:
   *         description: Redirect to the identity provider.
   *       404:
   *         description: SSO is not configured.
   */
  router.get("/start", async (req: Request, res: Response) => {
    try {
      const instance =
        typeof req.query.provider === "string" ? req.query.provider : null;
      const { redirectUrl } = await login.start(req as never, instance);
      res.redirect(redirectUrl);
    } catch (error) {
      if (error instanceof LoginMethodError) {
        res.status(error.status).json({ error: error.message });
        return;
      }
      fail(ctx, res, "Failed to start SSO login", error);
    }
  });

  /**
   * @openapi
   * /plugin-api/sso/callback:
   *   get:
   *     summary: SSO callback
   *     description: Public. The redirect URI to register with an identity provider. Exchanges the code and redirects back to the app with a session, a second-factor step or an error.
   *     tags:
   *       - SSO
   *     responses:
   *       302:
   *         description: Back to the app.
   *   post:
   *     summary: SSO callback (form post)
   *     description: Same as the GET form, for providers that post their answer.
   *     tags:
   *       - SSO
   *     responses:
   *       302:
   *         description: Back to the app.
   */
  const callback = async (req: Request, res: Response) => {
    const state = req.query.state ?? req.body?.state;
    if (await login.isLink(state)) {
      try {
        res.redirect(await login.finishLink(req as never));
      } catch (error) {
        if (error instanceof LoginMethodError) {
          res.status(error.status).json({ error: error.message });
          return;
        }
        fail(ctx, res, "Failed to link SSO", error);
      }
      return;
    }
    return ctx.auth.completeRedirectLogin(METHOD_ID, req, res);
  };
  router.get("/callback", callback);
  router.post("/callback", callback);

  /**
   * @openapi
   * /plugin-api/sso/saml/acs:
   *   post:
   *     summary: SAML assertion consumer service
   *     description: Public. The ACS URL to register with a SAML identity provider (HTTP-POST binding). Keeps the answer for a moment and sends the browser on to the callback, where the login is checked and finished. Only answers to a login Termix started are taken.
   *     tags:
   *       - SSO
   *     requestBody:
   *       content:
   *         application/x-www-form-urlencoded:
   *           schema:
   *             type: object
   *             properties:
   *               SAMLResponse:
   *                 type: string
   *               RelayState:
   *                 type: string
   *     responses:
   *       303:
   *         description: On to the callback.
   *       400:
   *         description: No login is waiting for this answer.
   */
  router.post("/saml/acs", async (req: Request, res: Response) => {
    try {
      const relayState = req.body?.RelayState;
      const token = await login.stashSamlResponse(
        relayState,
        req.body?.SAMLResponse,
      );
      if (!token) {
        res.status(400).json({ error: "No login is waiting for this answer" });
        return;
      }
      const next = new URL(`${ctx.http.baseUrl(req)}/plugin-api/sso/callback`);
      next.searchParams.set("state", String(relayState));
      next.searchParams.set("saml", token);
      res.redirect(303, next.toString());
    } catch (error) {
      fail(ctx, res, "Failed to take the SAML answer", error);
    }
  });

  /**
   * @openapi
   * /plugin-api/sso/saml/metadata:
   *   get:
   *     summary: SAML service provider metadata
   *     description: Public. The metadata XML of one SAML provider, to give to the identity provider.
   *     tags:
   *       - SSO
   *     parameters:
   *       - in: query
   *         name: provider
   *         required: true
   *         schema:
   *           type: integer
   *     responses:
   *       200:
   *         description: Metadata XML.
   *       404:
   *         description: No enabled SAML provider with that id.
   */
  router.get("/saml/metadata", async (req: Request, res: Response) => {
    try {
      const id = Number.parseInt(String(req.query.provider ?? ""), 10);
      const provider = Number.isInteger(id) ? await store.resolve(id) : null;
      if (!provider || provider.type !== "saml") {
        res.status(404).json({ error: "SAML provider not found" });
        return;
      }
      res
        .type("application/samlmetadata+xml")
        .send(samlMetadata(ctx, provider.config, ctx.http.baseUrl(req)));
    } catch (error) {
      fail(ctx, res, "Failed to build SAML metadata", error);
    }
  });

  async function selfLinkAllowed(): Promise<boolean> {
    return (await ctx.settings.get("allowSelfLink")) !== false;
  }

  /**
   * @openapi
   * /plugin-api/sso/links:
   *   get:
   *     summary: The current user's SSO links
   *     description: Each enabled provider and whether the signed in user is linked to it.
   *     tags:
   *       - SSO
   *     responses:
   *       200:
   *         description: "{ allowed, providers, result } where each provider has id, label and linked, and result is the outcome of the last link, given once."
   */
  router.get("/links", async (_req: Request, res: Response) => {
    try {
      const userId = ctx.currentActor();
      if (!userId) return res.status(401).json({ error: "Not signed in" });
      const linked = new Set(
        (await ctx.auth.identities.list(userId)).map(
          (identity) => identity.provider,
        ),
      );
      // The result of a link finished in another tab, shown once.
      const resultKey = `${LINK_RESULT_PREFIX}${userId}`;
      const result = await ctx.kv.get(resultKey);
      if (result) await ctx.kv.delete(resultKey);
      res.json({
        allowed: await selfLinkAllowed(),
        ...(typeof result === "string" ? { result } : {}),
        providers: (await store.listInstances()).map((instance) => ({
          id: instance.id,
          label: instance.label,
          linked: linked.has(login.providerKeyOf(instance.id)),
        })),
      });
    } catch (error) {
      fail(ctx, res, "Failed to load SSO links", error);
    }
  });

  /**
   * @openapi
   * /plugin-api/sso/links/start:
   *   post:
   *     summary: Start linking an SSO provider
   *     description: Gives a one time address for the signed in user to open in a browser tab. It goes on to the provider, and when the provider sends them back its identity is tied to their account. GET /plugin-api/sso/links then reports the result once.
   *     tags:
   *       - SSO
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               provider:
   *                 type: string
   *     responses:
   *       200:
   *         description: "{ redirectUrl }"
   *       403:
   *         description: An admin turned linking off.
   *       404:
   *         description: No such provider.
   */
  router.post("/links/start", async (req: Request, res: Response) => {
    try {
      const userId = ctx.currentActor();
      if (!userId) return res.status(401).json({ error: "Not signed in" });
      if (!(await selfLinkAllowed())) {
        return res.status(403).json({ error: "Linking is turned off" });
      }
      const provider =
        typeof req.body?.provider === "string" ? req.body.provider : null;
      if (!provider) {
        return res.status(400).json({ error: "Provider is required" });
      }
      const token = crypto.randomBytes(24).toString("base64url");
      await ctx.kv.set(`${LINK_GO_PREFIX}${token}`, {
        userId,
        provider,
        createdAt: Date.now(),
      });
      const base = ctx.http.baseUrl(req).replace(/\/+$/, "");
      res.json({ redirectUrl: `${base}/plugin-api/sso/links/go/${token}` });
    } catch (error) {
      if (error instanceof LoginMethodError) {
        res.status(error.status).json({ error: error.message });
        return;
      }
      fail(ctx, res, "Failed to start SSO link", error);
    }
  });

  /**
   * @openapi
   * /plugin-api/sso/links/go/{token}:
   *   get:
   *     summary: Open the provider to link an account
   *     description: The address /links/start gave, opened in a browser tab. Only the person who asked can use it, once, within two minutes. Sends the browser on to the provider.
   *     tags:
   *       - SSO
   *     parameters:
   *       - in: path
   *         name: token
   *         required: true
   *         schema: { type: string }
   *     responses:
   *       302:
   *         description: On to the provider.
   *       401:
   *         description: Not signed in.
   *       404:
   *         description: Unknown, used, expired or someone else's link.
   */
  router.get("/links/go/:token", async (req: Request, res: Response) => {
    try {
      const userId = ctx.currentActor();
      if (!userId) return res.status(401).json({ error: "Not signed in" });
      const key = `${LINK_GO_PREFIX}${String(req.params.token)}`;
      const entry = (await ctx.kv.get(key)) as {
        userId?: unknown;
        provider?: unknown;
        createdAt?: unknown;
      } | null;
      if (entry) await ctx.kv.delete(key);
      if (
        !entry ||
        entry.userId !== userId ||
        typeof entry.provider !== "string" ||
        typeof entry.createdAt !== "number" ||
        Date.now() - entry.createdAt > LINK_GO_TTL_MS
      ) {
        return res.status(404).json({ error: "This link expired" });
      }
      if (!(await selfLinkAllowed())) {
        return res.status(403).json({ error: "Linking is turned off" });
      }
      const base = ctx.http.baseUrl(req).replace(/\/+$/, "");
      const { redirectUrl } = await login.start(req as never, entry.provider, {
        linkUserId: userId,
        returnTo: `${base}/`,
      });
      res.redirect(302, redirectUrl);
    } catch (error) {
      if (error instanceof LoginMethodError) {
        res.status(error.status).json({ error: error.message });
        return;
      }
      fail(ctx, res, "Failed to start SSO link", error);
    }
  });

  /**
   * @openapi
   * /plugin-api/sso/links/{provider}:
   *   delete:
   *     summary: Unlink an SSO provider
   *     description: Removes the provider from the signed in user's account.
   *     tags:
   *       - SSO
   *     parameters:
   *       - in: path
   *         name: provider
   *         required: true
   *         schema:
   *           type: string
   *     responses:
   *       200:
   *         description: Unlinked.
   *       409:
   *         description: It is the user's only way to sign in.
   */
  router.delete("/links/:provider", async (req: Request, res: Response) => {
    try {
      const userId = ctx.currentActor();
      if (!userId) return res.status(401).json({ error: "Not signed in" });
      await ctx.auth.identities.unlink(
        userId,
        login.providerKeyOf(String(req.params.provider)),
      );
      res.json({ success: true });
    } catch (error) {
      const refused = error as { status?: number; code?: string };
      if (refused.code === "last_login") {
        res.status(refused.status ?? 409).json({
          error: "Set a password before unlinking your only sign in",
          code: refused.code,
        });
        return;
      }
      fail(ctx, res, "Failed to unlink SSO", error);
    }
  });

  /**
   * @openapi
   * /plugin-api/sso/backchannel-logout:
   *   post:
   *     summary: OIDC back-channel logout
   *     description: Public. Where an identity provider sends a signed logout token. Ends the Termix sessions that came from the matching provider login.
   *     tags:
   *       - SSO
   *     requestBody:
   *       required: true
   *       content:
   *         application/x-www-form-urlencoded:
   *           schema:
   *             type: object
   *             properties:
   *               logout_token:
   *                 type: string
   *     responses:
   *       200:
   *         description: Logout processed.
   *       400:
   *         description: Missing, invalid or unknown logout token.
   */
  router.post("/backchannel-logout", async (req: Request, res: Response) => {
    res.setHeader("Cache-Control", "no-store");
    const logoutToken = (req.body as Record<string, unknown> | undefined)
      ?.logout_token;
    if (typeof logoutToken !== "string" || !logoutToken) {
      res.status(400).json({ error: "missing logout_token" });
      return;
    }

    let issuer: string | null = null;
    try {
      const parts = logoutToken.split(".");
      if (parts.length === 3) {
        const claims = JSON.parse(Buffer.from(parts[1], "base64").toString());
        issuer = typeof claims.iss === "string" ? claims.iss : null;
      }
    } catch {
      issuer = null;
    }
    if (!issuer) {
      res.status(400).json({ error: "invalid logout_token" });
      return;
    }

    try {
      const provider = await store.resolveByIssuer(issuer);
      if (!provider) {
        ctx.log.warn(`Back-channel logout for unknown issuer ${issuer}`);
        res.status(400).json({ error: "unknown issuer" });
        return;
      }
      const claims = await validateLogoutToken(logoutToken, provider.config);

      const now = Date.now();
      for (const [key, expiry] of seenLogoutJti) {
        if (expiry <= now) seenLogoutJti.delete(key);
      }
      if (seenLogoutJti.has(claims.jti)) {
        res.status(200).json({ ok: true });
        return;
      }

      try {
        await ctx.auth.revokeSessions({
          providerId: provider.rowId,
          sub: claims.sub,
          sid: claims.sid,
        });
      } catch (error) {
        fail(ctx, res, "logout processing failed", error);
        return;
      }
      seenLogoutJti.set(claims.jti, now + LOGOUT_JTI_TTL_MS);
      res.status(200).json({ ok: true });
    } catch (error) {
      ctx.log.warn(`Back-channel logout failed: ${String(error)}`);
      res.status(400).json({ error: "invalid logout_token" });
    }
  });

  /**
   * @openapi
   * /plugin-api/sso/config:
   *   get:
   *     summary: Default provider's public configuration
   *     description: Public, for 2.8 clients. The client id, issuer, authorization URL and scopes of the default provider, or null.
   *     tags:
   *       - SSO
   *     responses:
   *       200:
   *         description: Public configuration, or null.
   */
  router.get("/config", async (_req: Request, res: Response) => {
    try {
      const provider = await store.resolve(null);
      if (!provider) {
        res.json(null);
        return;
      }
      const { config } = provider;
      res.json({
        client_id: config.client_id,
        issuer_url: config.issuer_url,
        authorization_url: config.authorization_url,
        scopes: config.scopes,
      });
    } catch (error) {
      fail(ctx, res, "Failed to get OIDC config", error);
    }
  });

  // Everything below manages providers.
  const manage = ctx.rbac.require("manage") as never;

  /**
   * @openapi
   * /plugin-api/sso/providers:
   *   get:
   *     summary: List SSO providers
   *     description: Every OIDC, GitHub, Google and SAML provider with its redirect URI or ACS URL. Secrets are never sent, only whether one is set. Needs sso.manage.
   *     tags:
   *       - SSO
   *     responses:
   *       200:
   *         description: Providers.
   *       403:
   *         description: Missing permission.
   */
  router.get("/providers", manage, async (req: Request, res: Response) => {
    try {
      const rows = await store.listRows();
      res.json({
        providers: await Promise.all(rows.map((row) => present(req, row))),
        newRedirectUri: redirectUriFor(ctx.http.baseUrl(req), {
          legacyCallback: false,
        }),
      });
    } catch (error) {
      fail(ctx, res, "Failed to list SSO providers", error);
    }
  });

  /**
   * @openapi
   * /plugin-api/sso/providers:
   *   post:
   *     summary: Add an SSO provider
   *     description: Adds an OIDC, GitHub, Google or SAML provider. GitHub and Google fill in their own endpoints. Needs sso.manage.
   *     tags:
   *       - SSO
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               name:
   *                 type: string
   *               type:
   *                 type: string
   *                 enum: [oidc, github, google, saml]
   *               enabled:
   *                 type: boolean
   *               config:
   *                 type: object
   *     responses:
   *       201:
   *         description: Provider added.
   *       400:
   *         description: Missing or invalid fields.
   *       403:
   *         description: Missing permission.
   */
  /**
   * @openapi
   * /plugin-api/sso/providers/saml-metadata:
   *   post:
   *     summary: Read a SAML identity provider's metadata
   *     description: Fetches the metadata from a URL, or reads pasted XML, and returns the sign in URL, entity id and signing certificates for the provider form. Saves nothing. Needs sso.manage.
   *     tags:
   *       - SSO
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               url:
   *                 type: string
   *               xml:
   *                 type: string
   *     responses:
   *       200:
   *         description: The fields read from the metadata.
   *       400:
   *         description: The metadata could not be read.
   *       403:
   *         description: Missing permission.
   */
  router.post(
    "/providers/saml-metadata",
    manage,
    async (req: Request, res: Response) => {
      const { url, xml } = req.body ?? {};
      let text = typeof xml === "string" ? xml : "";
      try {
        if (!text) {
          if (!isHttpUrl(url)) {
            res
              .status(400)
              .json({ error: "A metadata URL or XML is required" });
            return;
          }
          // An admin typed this address, so a private host is fine.
          const response = await fetchWithOptions(String(url), {
            allowHosts: [new URL(String(url)).hostname],
          });
          if (!response.ok) {
            res
              .status(400)
              .json({ error: `The metadata URL answered ${response.status}` });
            return;
          }
          text = await response.text();
        }
        if (text.length > 2 * 1024 * 1024) {
          res.status(400).json({ error: "The metadata is too large" });
          return;
        }
        res.json(parseIdpMetadata(text));
      } catch (error) {
        res.status(400).json({
          error: error instanceof Error ? error.message : String(error),
        });
      }
    },
  );

  router.post("/providers", manage, async (req: Request, res: Response) => {
    try {
      const {
        name,
        type,
        enabled = true,
        displayOrder = 0,
        config = {},
      } = req.body ?? {};
      if (typeof name !== "string" || !name.trim()) {
        res.status(400).json({ error: "Provider name is required" });
        return;
      }
      if (!isSsoType(type)) {
        res.status(400).json({ error: "Invalid provider type" });
        return;
      }
      const full = applyProviderDefaults(config as OidcConfig, type);
      const invalid = validate(type, full);
      if (invalid) {
        res.status(400).json({ error: invalid });
        return;
      }
      const row = await store.create({
        name: name.trim(),
        type,
        enabled: !!enabled,
        displayOrder: Number(displayOrder) || 0,
        config: { ...(config as Record<string, unknown>) },
      });
      await ctx.audit.record({
        action: "sso_provider_create",
        resourceType: "sso_provider",
        resourceId: String(row.id),
        resourceName: row.name,
        success: true,
      });
      res.status(201).json(await present(req, row));
    } catch (error) {
      fail(ctx, res, "Failed to create SSO provider", error);
    }
  });

  /**
   * @openapi
   * /plugin-api/sso/providers/{id}:
   *   put:
   *     summary: Update an SSO provider
   *     description: Changes a provider. Config fields are merged over the stored ones; an empty client secret keeps the stored secret. legacyCallback false moves it to the new redirect URI. Needs sso.manage.
   *     tags:
   *       - SSO
   *     parameters:
   *       - in: path
   *         name: id
   *         required: true
   *         schema:
   *           type: integer
   *     responses:
   *       200:
   *         description: Provider updated.
   *       400:
   *         description: Invalid fields.
   *       403:
   *         description: Missing permission.
   *       404:
   *         description: Provider not found.
   */
  router.put("/providers/:id", manage, async (req: Request, res: Response) => {
    try {
      const id = Number.parseInt(String(req.params.id), 10);
      const row = Number.isInteger(id) ? await store.findRow(id) : null;
      if (!row) {
        res.status(404).json({ error: "Provider not found" });
        return;
      }
      const { name, enabled, displayOrder, config, legacyCallback } =
        req.body ?? {};
      const values: Parameters<ProviderStore["update"]>[1] = {};
      if (name !== undefined) {
        if (typeof name !== "string" || !name.trim()) {
          res.status(400).json({ error: "Provider name is required" });
          return;
        }
        values.name = name.trim();
      }
      if (enabled !== undefined) values.enabled = !!enabled;
      if (displayOrder !== undefined) {
        values.displayOrder = Number(displayOrder) || 0;
      }
      if (legacyCallback !== undefined) {
        values.legacyCallback = !!legacyCallback;
      }
      if (config && typeof config === "object") {
        const incoming = { ...(config as Record<string, unknown>) };
        if (!incoming.client_secret) delete incoming.client_secret;
        if (!incoming.saml_sp_private_key) delete incoming.saml_sp_private_key;
        const merged = {
          ...(await store.parseConfig(row.config)),
          ...incoming,
        };
        const invalid = validate(
          row.type as SsoProviderType,
          applyProviderDefaults(merged as unknown as OidcConfig, row.type),
        );
        if (invalid) {
          res.status(400).json({ error: invalid });
          return;
        }
        values.config = merged;
      }
      const updated = await store.update(id, values);
      await ctx.audit.record({
        action: "sso_provider_update",
        resourceType: "sso_provider",
        resourceId: String(id),
        resourceName: updated?.name ?? row.name,
        success: true,
      });
      res.json(await present(req, updated ?? row));
    } catch (error) {
      fail(ctx, res, "Failed to update SSO provider", error);
    }
  });

  /**
   * @openapi
   * /plugin-api/sso/providers/{id}:
   *   delete:
   *     summary: Delete an SSO provider
   *     description: Refused while users still sign in with it. Needs sso.manage.
   *     tags:
   *       - SSO
   *     parameters:
   *       - in: path
   *         name: id
   *         required: true
   *         schema:
   *           type: integer
   *     responses:
   *       200:
   *         description: Provider deleted.
   *       403:
   *         description: Missing permission.
   *       404:
   *         description: Provider not found.
   *       409:
   *         description: Users are still linked to it.
   */
  router.delete(
    "/providers/:id",
    manage,
    async (req: Request, res: Response) => {
      try {
        const id = Number.parseInt(String(req.params.id), 10);
        const row = Number.isInteger(id) ? await store.findRow(id) : null;
        if (!row) {
          res.status(404).json({ error: "Provider not found" });
          return;
        }
        if ((await ctx.auth.countLinkedUsers(String(id))) > 0) {
          res.status(409).json({
            error:
              "Users still sign in with this provider. Disable it instead, or remove those users first.",
          });
          return;
        }
        await store.remove(id);
        await ctx.audit.record({
          action: "sso_provider_delete",
          resourceType: "sso_provider",
          resourceId: String(id),
          resourceName: row.name,
          success: true,
        });
        res.json({ message: "SSO provider deleted" });
      } catch (error) {
        fail(ctx, res, "Failed to delete SSO provider", error);
      }
    },
  );
}
