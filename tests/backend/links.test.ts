import { afterEach, describe, expect, it, vi } from "vitest";
import {
  OIDC_CONFIG,
  installIdp,
  startServer,
  type TestServer,
} from "./helpers.js";

let server: TestServer | null = null;

afterEach(async () => {
  vi.unstubAllGlobals();
  await server?.close();
  server = null;
});

async function stubIdp(sub: string) {
  const idp = await installIdp();
  idp.claims = { sub };
  return idp.claims;
}

async function startWithProvider() {
  const s = await startServer();
  const created = await s.request("POST", "/providers", {
    body: { name: "Keycloak", type: "oidc", config: OIDC_CONFIG },
  });
  expect(created.status).toBeLessThan(300);
  return { s, providerId: String(created.body.id) };
}

async function begin(s: TestServer, provider: string, user = "admin") {
  const started = await s.request("POST", "/links/start", {
    user,
    body: { provider },
  });
  const cookie = started.setCookie
    .find((value) => value.startsWith("termix_sso_binding="))
    ?.split(";")[0];
  return { started, cookie, url: new URL(started.body.redirectUrl) };
}

describe("linking an SSO account", () => {
  it("ties the provider's identity to the signed in user", async () => {
    const { s, providerId } = await startWithProvider();
    server = s;
    const claims = await stubIdp("idp-user");
    const { url, cookie } = await begin(s, providerId);
    claims.nonce = url.searchParams.get("nonce");

    const done = await s.request(
      "GET",
      `/callback?code=c&state=${url.searchParams.get("state")}`,
      { user: "", headers: { cookie: cookie! } },
    );

    expect(done.status).toBe(302);
    expect(new URL(done.location!).searchParams.get("sso_link")).toBe("linked");
    expect(s.mock.auth.identities).toEqual([
      expect.objectContaining({
        userId: "admin",
        provider: providerId,
        subject: "idp-user",
      }),
    ]);
    expect(s.mock.auth.completedLogins).toEqual([]);
    const links = await s.request("GET", "/links");
    expect(links.body.providers[0]).toEqual({
      id: providerId,
      label: "Keycloak",
      linked: true,
    });
  });

  it("refuses a callback from another browser", async () => {
    const { s, providerId } = await startWithProvider();
    server = s;
    const claims = await stubIdp("idp-user");
    const { url } = await begin(s, providerId);
    claims.nonce = url.searchParams.get("nonce");

    const done = await s.request(
      "GET",
      `/callback?code=c&state=${url.searchParams.get("state")}`,
      { user: "" },
    );

    expect(new URL(done.location!).searchParams.get("sso_link")).toBe("failed");
    expect(s.mock.auth.identities).toEqual([]);
  });

  it("says so when another account holds the identity", async () => {
    const { s, providerId } = await startWithProvider();
    server = s;
    s.mock.auth.identities.push({
      userId: "someone-else",
      provider: providerId,
      subject: "idp-user",
    });
    const claims = await stubIdp("idp-user");
    const { url, cookie } = await begin(s, providerId);
    claims.nonce = url.searchParams.get("nonce");

    const done = await s.request(
      "GET",
      `/callback?code=c&state=${url.searchParams.get("state")}`,
      { user: "", headers: { cookie: cookie! } },
    );

    expect(new URL(done.location!).searchParams.get("sso_link")).toBe(
      "identity_in_use",
    );
    expect(s.mock.auth.identities).toHaveLength(1);
  });

  it("can be turned off by an admin", async () => {
    const { s, providerId } = await startWithProvider();
    server = s;
    await s.mock.ctx.settings.set("allowSelfLink", false);
    const started = await s.request("POST", "/links/start", {
      body: { provider: providerId },
    });
    expect(started.status).toBe(403);
    expect((await s.request("GET", "/links")).body.allowed).toBe(false);
  });

  it("unlinks a provider", async () => {
    const { s, providerId } = await startWithProvider();
    server = s;
    s.mock.auth.identities.push({
      userId: "admin",
      provider: providerId,
      subject: "idp-user",
    });
    const done = await s.request("DELETE", `/links/${providerId}`);
    expect(done.status).toBe(200);
    expect(s.mock.auth.identities).toEqual([]);
  });

  it("is not public", async () => {
    const { s } = await startWithProvider();
    server = s;
    const links = await s.request("GET", "/links", { user: "" });
    expect(links.status).toBe(401);
  });
});
