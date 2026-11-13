import http from "node:http";
import type { AddressInfo } from "node:net";
import { fileURLToPath } from "node:url";
import express, {
  type Response as ExpressResponse,
  type Router,
} from "express";
import { vi } from "vitest";
import {
  createMockCtx,
  createTestDb,
  type MockPluginContext,
  type TestDb,
} from "@termix-ssh/plugin-sdk/testing";
import { PluginCapabilityError } from "@termix-ssh/plugin-sdk/backend";
import type { PluginManifest } from "@termix-ssh/plugin-sdk/manifest";
import manifestJson from "../../manifest.json";

export const pluginDir = fileURLToPath(new URL("../..", import.meta.url));
export const manifest = manifestJson as unknown as PluginManifest;

/** Core's 2.8 sso_providers, as db/index.ts created it. */
export const LEGACY_DDL = `
  CREATE TABLE IF NOT EXISTS sso_providers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    display_order INTEGER NOT NULL DEFAULT 0,
    config TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`;

export interface TestServer {
  db: TestDb;
  mock: MockPluginContext;
  request: (
    method: string,
    path: string,
    options?: {
      user?: string;
      body?: unknown;
      form?: Record<string, string>;
      headers?: Record<string, string>;
    },
    // Route bodies vary per test; asserting on them is the point.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  ) => Promise<{
    status: number;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    body: any;
    location: string | null;
    setCookie: string[];
  }>;
  close: () => Promise<void>;
}

// The IdP is stubbed through the global fetch; calls to the test server
// itself still go out for real.
const realFetch = globalThis.fetch;

export async function startServer(
  options: {
    capabilities?: string[];
    permissions?: string[];
    linkedUsers?: Record<string, number>;
    before?: (sqlite: TestDb["sqlite"]) => void;
    settings?: Record<string, unknown>;
  } = {},
): Promise<TestServer> {
  const db = await createTestDb(pluginDir, { before: options.before });
  db.sqlite
    .prepare("INSERT INTO users (id, username, is_admin) VALUES (?, ?, 1)")
    .run("admin", "admin");

  let router: Router | null = null;
  const capabilities = options.capabilities ?? manifest.capabilities;
  const mock = createMockCtx({
    sandbox: true,
    pluginId: manifest.id,
    manifest,
    capabilities,
    db: db.database,
    // ctx.fetch goes to the global fetch, which stubIdp replaces.
    fetch: (url, init) => globalThis.fetch(url, init as RequestInit),
    router: () => (router = express.Router()),
    permissions: options.permissions,
    linkedUsers: options.linkedUsers,
    baseUrl: "https://termix.test",
    settings: options.settings,
  });
  // SDK 2.2.1's sandbox mock still refuses login methods and
  // completeRedirectLogin; 2.2.2 takes them. Drop this once the lock moves
  // to 2.2.2.
  const auth = mock.ctx.auth as unknown as Record<string, unknown>;
  const registerLogin = auth.registerLoginMethod as (method: unknown) => void;
  auth.registerLoginMethod = (method: never) => {
    try {
      registerLogin(method);
    } catch (error) {
      if ((error as { code?: string }).code !== "SANDBOX_UNSUPPORTED") {
        throw error;
      }
      if (!capabilities.includes("auth:provide")) {
        throw new PluginCapabilityError(manifest.id, "auth:provide");
      }
      mock.auth.loginMethods.push(method);
    }
  };
  const complete = auth.completeRedirectLogin as (
    ...args: unknown[]
  ) => Promise<void>;
  auth.completeRedirectLogin = async (
    methodId: string,
    req: never,
    res: ExpressResponse,
  ) => {
    try {
      return await complete(methodId, req, res);
    } catch (error) {
      if ((error as { code?: string }).code !== "SANDBOX_UNSUPPORTED") {
        throw error;
      }
    }
    // What the 2.2.2 fake does: the identity as JSON, or a redirect back
    // with the error.
    const method = mock.auth.loginMethods.find((m) => m.id === methodId);
    try {
      const identity = await method!.callback!(req);
      mock.auth.completedLogins.push({ methodId, identity });
      res.status(200).json({ completed: methodId, identity });
    } catch (error) {
      const returnTo = (error as { returnTo?: string }).returnTo;
      const message = (error as Error).message;
      if (returnTo) {
        const url = new URL(returnTo);
        url.searchParams.set(
          "error",
          (error as { code?: string }).code ?? message,
        );
        res.redirect(url.toString());
        return;
      }
      res.status((error as { status?: number }).status ?? 500).json({
        error: message,
      });
    }
  };

  const { activate } = await import("../../src/backend/index.js");
  await activate(mock.ctx);

  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));
  app.use((req, _res, next) => {
    mock.setActor(req.header("x-test-user") || undefined);
    next();
  });
  app.use((req, res, next) => router!(req, res, next));

  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const { port } = server.address() as AddressInfo;

  return {
    db,
    mock,
    async request(
      method,
      path,
      { user = "admin", body, form, headers = {} } = {},
    ) {
      const payload =
        form !== undefined
          ? new URLSearchParams(form).toString()
          : body !== undefined && method !== "GET"
            ? JSON.stringify(body)
            : undefined;
      const response = await realFetch(`http://127.0.0.1:${port}${path}`, {
        method,
        redirect: "manual",
        headers: {
          "x-test-user": user,
          ...(form !== undefined
            ? { "content-type": "application/x-www-form-urlencoded" }
            : payload !== undefined
              ? { "content-type": "application/json" }
              : {}),
          ...headers,
        },
        body: payload,
      });
      const text = await response.text();
      let parsed: unknown = null;
      try {
        parsed = text ? JSON.parse(text) : null;
      } catch {
        parsed = text;
      }
      return {
        status: response.status,
        body: parsed,
        location: response.headers.get("location"),
        setCookie: response.headers.getSetCookie(),
      };
    },
    async close() {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      db.close();
    },
  };
}

export const ISSUER = "https://idp.example";

export interface FakeIdp {
  /** Claims the next id_token carries. */
  claims: Record<string, unknown>;
  /** Form bodies the token endpoint received. */
  tokenRequests: URLSearchParams[];
  /** Signs any payload with the IdP's key, for logout tokens. */
  sign: (payload: Record<string, unknown>) => Promise<string>;
  /** Extra handlers, checked first. */
  routes: Map<string, () => Response>;
}

/**
 * A minimal OpenID provider behind the global fetch: discovery, JWKS, a
 * token endpoint that issues a signed id_token and a userinfo endpoint.
 */
export async function installIdp(): Promise<FakeIdp> {
  const { exportJWK, generateKeyPair, SignJWT } = await import("jose");
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const jwk = { ...(await exportJWK(publicKey)), kid: "k1", alg: "RS256" };

  const idp: FakeIdp = {
    claims: {},
    tokenRequests: [],
    routes: new Map(),
    sign: (payload) =>
      new SignJWT(payload)
        .setProtectedHeader({ alg: "RS256", kid: "k1" })
        .setIssuer(ISSUER)
        .setAudience("termix")
        .setIssuedAt()
        .setExpirationTime("5m")
        .sign(privateKey),
  };

  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      const custom = idp.routes.get(url);
      if (custom) return custom();
      if (url.startsWith("http://127.0.0.1")) return realFetch(input, init);
      if (url === `${ISSUER}/.well-known/openid-configuration`) {
        return Response.json({
          jwks_uri: `${ISSUER}/jwks`,
          userinfo_endpoint: `${ISSUER}/userinfo`,
        });
      }
      if (url === `${ISSUER}/jwks`) return Response.json({ keys: [jwk] });
      if (url === `${ISSUER}/token`) {
        idp.tokenRequests.push(new URLSearchParams(String(init?.body)));
        return Response.json({
          access_token: "access",
          id_token: await idp.sign(idp.claims),
        });
      }
      if (url === `${ISSUER}/userinfo`) {
        return Response.json({ email: "alice@example.com" });
      }
      return new Response("not found", { status: 404 });
    }),
  );
  return idp;
}

export const OIDC_CONFIG = {
  client_id: "termix",
  client_secret: "shhh",
  issuer_url: ISSUER,
  authorization_url: `${ISSUER}/authorize`,
  token_url: `${ISSUER}/token`,
  identifier_path: "sub",
  name_path: "name",
  scopes: "openid email profile",
  admin_group: "termix-admins",
  role_map: "ops-team:ops",
};
