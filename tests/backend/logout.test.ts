import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ISSUER,
  OIDC_CONFIG,
  installIdp,
  startServer,
  type TestServer,
} from "./helpers.js";

let server: TestServer | null = null;

afterEach(async () => {
  await server?.close();
  server = null;
  vi.unstubAllGlobals();
});

type LogoutRedirect = (session: {
  providerId: number | null;
  sub: string | null;
  sid: string | null;
  baseUrl: string;
}) => Promise<string | null>;

async function withProvider(config: Record<string, unknown>) {
  const idp = await installIdp();
  server = await startServer();
  const created = await server.request("POST", "/providers", {
    body: {
      name: "Keycloak",
      type: "oidc",
      config: { ...OIDC_CONFIG, ...config },
    },
  });
  expect(created.status).toBe(201);
  const method = server.mock.auth.loginMethods[0] as unknown as {
    logoutRedirect: LogoutRedirect;
  };
  const session = {
    providerId: created.body.id as number,
    sub: "u1",
    sid: null,
    baseUrl: "https://termix.test",
  };
  return { idp, method, session };
}

describe("sign out at the provider", () => {
  it("is off unless the provider asks for it", async () => {
    const { method, session } = await withProvider({});
    expect(await method.logoutRedirect(session)).toBeNull();
  });

  it("uses the sign out URL with the client id and a way back", async () => {
    const { method, session } = await withProvider({
      sign_out_at_provider: "1",
      end_session_url: `${ISSUER}/logout`,
    });
    const url = new URL((await method.logoutRedirect(session))!);
    expect(`${url.origin}${url.pathname}`).toBe(`${ISSUER}/logout`);
    expect(url.searchParams.get("client_id")).toBe("termix");
    expect(url.searchParams.get("post_logout_redirect_uri")).toBe(
      "https://termix.test/",
    );
  });

  it("finds the sign out page in the discovery document", async () => {
    const { idp, method, session } = await withProvider({
      sign_out_at_provider: "1",
    });
    idp.routes.set(`${ISSUER}/.well-known/openid-configuration`, () =>
      Response.json({ end_session_endpoint: `${ISSUER}/end` }),
    );
    expect(await method.logoutRedirect(session)).toMatch(
      new RegExp(`^${ISSUER}/end\\?client_id=termix`),
    );
  });

  it("gives nothing when the provider lists no sign out page", async () => {
    const { method, session } = await withProvider({
      sign_out_at_provider: "1",
    });
    expect(await method.logoutRedirect(session)).toBeNull();
  });

  it("refuses a sign out URL that is not http(s)", async () => {
    await installIdp();
    server = await startServer();
    const res = await server.request("POST", "/providers", {
      body: {
        name: "Bad",
        type: "oidc",
        config: { ...OIDC_CONFIG, end_session_url: "javascript:alert(1)" },
      },
    });
    expect(res.status).toBe(400);
  });
});
