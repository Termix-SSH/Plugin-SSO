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

/** The settings screen asks for a link address; the person opens it in a tab. */
async function begin(s: TestServer, provider: string, user = "admin") {
  const started = await s.request("POST", "/links/start", {
    user,
    body: { provider },
  });
  const token = String(started.body.redirectUrl).split("/links/go/")[1];
  const go = await s.request("GET", `/links/go/${token}`, { user });
  const cookie = go.setCookie
    .find((value) => value.startsWith("tmxp_sso_binding="))
    ?.split(";")[0];
  return { started, go, token, cookie, url: new URL(go.location!) };
}

async function result(s: TestServer, user = "admin") {
  return (await s.request("GET", "/links", { user })).body.result;
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
    expect(new URL(done.location!).search).toBe("");
    expect(await result(s)).toBe("linked");
    // Reported once.
    expect(await result(s)).toBeUndefined();
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

    expect(done.status).toBe(302);
    expect(await result(s)).toBe("failed");
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

    expect(done.status).toBe(302);
    expect(await result(s)).toBe("identity_in_use");
    expect(s.mock.auth.identities).toHaveLength(1);
  });

  it("gives the settings screen an address on this server, never the provider's", async () => {
    const { s, providerId } = await startWithProvider();
    server = s;
    await stubIdp("idp-user");
    const started = await s.request("POST", "/links/start", {
      body: { provider: providerId },
    });
    expect(started.status).toBe(200);
    expect(started.body.redirectUrl).toMatch(
      /\/plugin-api\/sso\/links\/go\/[A-Za-z0-9_-]{32}$/,
    );
    expect(started.setCookie).toEqual([]);
  });

  it("opens the address only for the person who asked, once", async () => {
    const { s, providerId } = await startWithProvider();
    server = s;
    await stubIdp("idp-user");
    const started = await s.request("POST", "/links/start", {
      body: { provider: providerId },
    });
    const token = String(started.body.redirectUrl).split("/links/go/")[1];
    const stolen = await s.request("GET", `/links/go/${token}`, {
      user: "someone-else",
    });
    expect(stolen.status).toBe(404);
    // Someone else trying it used it up.
    expect((await s.request("GET", `/links/go/${token}`)).status).toBe(404);
    expect((await s.request("GET", "/links/go/made-up")).status).toBe(404);
  });

  it("lets an address go stale after two minutes", async () => {
    const { s, providerId } = await startWithProvider();
    server = s;
    await stubIdp("idp-user");
    const now = Date.now();
    const clock = vi.spyOn(Date, "now").mockReturnValue(now);
    const started = await s.request("POST", "/links/start", {
      body: { provider: providerId },
    });
    const token = String(started.body.redirectUrl).split("/links/go/")[1];
    clock.mockReturnValue(now + 3 * 60 * 1000);
    expect((await s.request("GET", `/links/go/${token}`)).status).toBe(404);
    clock.mockRestore();
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
