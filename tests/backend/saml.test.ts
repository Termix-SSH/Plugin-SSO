import { inflateRawSync } from "node:zlib";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { generate } from "selfsigned";
import { SignedXml } from "xml-crypto";
import { parseIdpMetadata, splitCerts } from "../../src/backend/saml.js";
import { startServer, type TestServer } from "./helpers.js";

const ACS = "https://termix.test/plugin-api/sso/saml/acs";
const ENTITY = "https://termix.test/plugin-api/sso/saml/metadata";
const IDP = "https://idp.example/saml";

let server: TestServer | null = null;
let idpKey = "";
let idpCert = "";
let otherKey = "";
let otherCert = "";

beforeAll(async () => {
  const idp = await generate([{ name: "commonName", value: "idp" }], {
    keySize: 2048,
  });
  idpKey = idp.private;
  idpCert = idp.cert;
  const other = await generate([{ name: "commonName", value: "other" }], {
    keySize: 2048,
  });
  otherKey = other.private;
  otherCert = other.cert;
});

afterEach(async () => {
  await server?.close();
  server = null;
  vi.unstubAllGlobals();
});

async function withSamlProvider(config: Record<string, string> = {}) {
  server = await startServer();
  const created = await server.request("POST", "/providers", {
    body: {
      name: "Corp SAML",
      type: "saml",
      config: {
        saml_entry_point: `${IDP}/sso`,
        saml_idp_cert: idpCert,
        saml_idp_issuer: IDP,
        admin_group: "termix-admins",
        role_map: "ops-team:ops",
        ...config,
      },
    },
  });
  expect(created.status).toBe(201);
  return { s: server, id: created.body.id as number };
}

/** Starts a login and returns the relay state, request id and binding cookie. */
async function begin(s: TestServer, id: number) {
  const started = await s.request("GET", `/start?provider=${id}`, {
    headers: { referer: "https://termix.test/login" },
  });
  expect(started.status).toBe(302);
  const url = new URL(started.location!);
  expect(url.origin + url.pathname).toBe(`${IDP}/sso`);
  const request = inflateRawSync(
    Buffer.from(url.searchParams.get("SAMLRequest")!, "base64"),
  ).toString("utf8");
  const cookie = started.setCookie
    .find((c) => c.startsWith("tmxp_sso_binding="))!
    .split(";")[0];
  return {
    state: url.searchParams.get("RelayState")!,
    requestId: request.match(/ID="([^"]+)"/)![1],
    request,
    cookie,
    cookiePath: started.setCookie
      .find((c) => c.startsWith("tmxp_sso_binding="))!
      .match(/Path=([^;]+)/i)?.[1],
  };
}

function iso(offsetMs: number) {
  return new Date(Date.now() + offsetMs).toISOString();
}

function samlResponse(
  inResponseTo: string,
  options: {
    key?: string;
    cert?: string;
    audience?: string;
    notOnOrAfter?: string;
    assertionId?: string;
    attributes?: Record<string, string[]>;
    nameId?: string;
  } = {},
) {
  const attributes = options.attributes ?? {
    email: ["alice@example.com"],
    uid: ["alice"],
    groups: ["termix-admins", "ops-team"],
  };
  const attrXml = Object.entries(attributes)
    .map(
      ([name, values]) =>
        `<saml:Attribute Name="${name}">${values
          .map((v) => `<saml:AttributeValue>${v}</saml:AttributeValue>`)
          .join("")}</saml:Attribute>`,
    )
    .join("");
  const notOnOrAfter = options.notOnOrAfter ?? iso(5 * 60_000);
  const xml =
    `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r${Math.random().toString(36).slice(2)}" Version="2.0" IssueInstant="${iso(0)}" Destination="${ACS}" InResponseTo="${inResponseTo}">` +
    `<saml:Issuer>${IDP}</saml:Issuer>` +
    `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
    `<saml:Assertion ID="${options.assertionId ?? `_a${Math.random().toString(36).slice(2)}`}" Version="2.0" IssueInstant="${iso(0)}">` +
    `<saml:Issuer>${IDP}</saml:Issuer>` +
    `<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${options.nameId ?? "alice@example.com"}</saml:NameID>` +
    `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="${inResponseTo}" NotOnOrAfter="${notOnOrAfter}" Recipient="${ACS}"/></saml:SubjectConfirmation></saml:Subject>` +
    `<saml:Conditions NotBefore="${iso(-60_000)}" NotOnOrAfter="${notOnOrAfter}"><saml:AudienceRestriction><saml:Audience>${options.audience ?? ENTITY}</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
    `<saml:AuthnStatement AuthnInstant="${iso(0)}" SessionIndex="s1"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>` +
    `<saml:AttributeStatement>${attrXml}</saml:AttributeStatement>` +
    `</saml:Assertion></samlp:Response>`;
  const sig = new SignedXml({
    privateKey: options.key ?? idpKey,
    publicCert: options.cert ?? idpCert,
    signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
  });
  sig.addReference({
    xpath: "//*[local-name(.)='Assertion']",
    transforms: [
      "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
      "http://www.w3.org/2001/10/xml-exc-c14n#",
    ],
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
  });
  sig.computeSignature(xml, {
    location: {
      reference: "//*[local-name(.)='Assertion']/*[local-name(.)='Issuer']",
      action: "after",
    },
  });
  return Buffer.from(sig.getSignedXml()).toString("base64");
}

/** Posts to the ACS, then follows its redirect with the binding cookie. */
async function post(
  s: TestServer,
  state: string,
  response: string,
  cookie?: string,
) {
  const acs = await s.request("POST", "/saml/acs", {
    form: { SAMLResponse: response, RelayState: state },
  });
  if (acs.status !== 303) return acs;
  const next = new URL(acs.location!);
  expect(next.pathname).toBe("/plugin-api/sso/callback");
  return s.request("GET", `/callback${next.search}`, {
    headers: cookie ? { cookie } : {},
  });
}

/** Core sends the browser back to the app with an error and no session. */
function expectRefused(
  s: TestServer,
  done: Awaited<ReturnType<TestServer["request"]>>,
) {
  expect(done.status).toBe(302);
  expect(done.location).toMatch(/\?error=/);
  expect(s.mock.auth.completedLogins).toHaveLength(0);
}

describe("SAML providers", () => {
  it("need a sign in URL and a certificate", async () => {
    server = await startServer();
    const missing = await server.request("POST", "/providers", {
      body: { name: "x", type: "saml", config: { saml_entry_point: "" } },
    });
    expect(missing.status).toBe(400);
    const noCert = await server.request("POST", "/providers", {
      body: {
        name: "x",
        type: "saml",
        config: { saml_entry_point: `${IDP}/sso`, saml_idp_cert: "nope" },
      },
    });
    expect(noCert.status).toBe(400);
  });

  it("show the ACS URL, entity id and metadata URL, never the signing key", async () => {
    const { s, id } = await withSamlProvider();
    const list = await s.request("GET", "/providers");
    const provider = list.body.providers.find(
      (p: { id: number }) => p.id === id,
    );
    expect(provider.redirectUri).toBe(ACS);
    expect(provider.samlEntityId).toBe(ENTITY);
    expect(provider.samlMetadataUrl).toBe(`${ENTITY}?provider=${id}`);
    expect(provider.config.saml_sp_private_key).toBeUndefined();

    const metadata = await s.request("GET", `/saml/metadata?provider=${id}`);
    expect(metadata.status).toBe(200);
    expect(metadata.body).toContain(`entityID="${ENTITY}"`);
    expect(metadata.body).toContain(`Location="${ACS}"`);
  });
});

describe("SAML login", () => {
  it("sends an AuthnRequest and binds the cookie on the callback path", async () => {
    const { s, id } = await withSamlProvider();
    const { request, cookiePath } = await begin(s, id);
    expect(request).toContain(`AssertionConsumerServiceURL="${ACS}"`);
    expect(request).toContain(ENTITY);
    expect(cookiePath).toBe("/plugin-api/sso/callback");
  });

  it("hands core the identity from a signed answer", async () => {
    const { s, id } = await withSamlProvider();
    const { state, requestId, cookie } = await begin(s, id);
    const done = await post(s, state, samlResponse(requestId), cookie);
    expect(done.status).toBe(200);
    expect(done.body.identity).toMatchObject({
      kind: "external",
      provider: String(id),
      subject: "alice@example.com",
      email: "alice@example.com",
      name: "alice",
      groups: ["termix-admins", "ops-team"],
      isAdmin: true,
      roles: { desired: ["ops"], managed: ["ops"] },
      returnTo: "https://termix.test/",
    });
  });

  it("uses the configured attribute names", async () => {
    const { s, id } = await withSamlProvider({
      saml_identifier_attr: "employeeId",
      saml_name_attr: "login",
    });
    const { state, requestId, cookie } = await begin(s, id);
    const done = await post(
      s,
      state,
      samlResponse(requestId, {
        attributes: { employeeId: ["e-42"], login: ["al"] },
      }),
      cookie,
    );
    expect(done.body.identity).toMatchObject({ subject: "e-42", name: "al" });
  });

  it("refuses an answer signed by another key", async () => {
    const { s, id } = await withSamlProvider();
    const { state, requestId, cookie } = await begin(s, id);
    const done = await post(
      s,
      state,
      samlResponse(requestId, { key: otherKey, cert: otherCert }),
      cookie,
    );
    expectRefused(s, done);
  });

  it("refuses an answer for another audience", async () => {
    const { s, id } = await withSamlProvider();
    const { state, requestId, cookie } = await begin(s, id);
    const done = await post(
      s,
      state,
      samlResponse(requestId, { audience: "https://other.example" }),
      cookie,
    );
    expectRefused(s, done);
  });

  it("refuses an expired answer", async () => {
    const { s, id } = await withSamlProvider();
    const { state, requestId, cookie } = await begin(s, id);
    const done = await post(
      s,
      state,
      samlResponse(requestId, { notOnOrAfter: iso(-10 * 60_000) }),
      cookie,
    );
    expectRefused(s, done);
  });

  it("refuses an answer to a request Termix did not send", async () => {
    const { s, id } = await withSamlProvider();
    const { state, cookie } = await begin(s, id);
    const done = await post(s, state, samlResponse("_unknown"), cookie);
    expectRefused(s, done);
  });

  it("refuses the same answer twice", async () => {
    const { s, id } = await withSamlProvider();
    const { state, requestId, cookie } = await begin(s, id);
    const response = samlResponse(requestId);
    expect((await post(s, state, response, cookie)).status).toBe(200);
    const again = await post(s, state, response, cookie);
    expect(again.status).toBe(400);
  });

  it("refuses a login finished in another browser", async () => {
    const { s, id } = await withSamlProvider();
    const { state, requestId } = await begin(s, id);
    const done = await post(s, state, samlResponse(requestId));
    expectRefused(s, done);
  });

  it("does not keep answers for logins nobody started", async () => {
    const { s } = await withSamlProvider();
    const acs = await s.request("POST", "/saml/acs", {
      form: { SAMLResponse: "x", RelayState: "made-up" },
    });
    expect(acs.status).toBe(400);
    expect(s.mock.kv.size).toBe(0);
  });
});

describe("IdP metadata", () => {
  it("reads the sign in URL, entity id and signing certificate", () => {
    const body = idpCert
      .replace(/-----(BEGIN|END) CERTIFICATE-----/g, "")
      .replace(/\s+/g, "");
    const parsed = parseIdpMetadata(
      `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${IDP}">` +
        `<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
        `<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>${body}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>` +
        `<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${IDP}/post"/>` +
        `<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${IDP}/sso?a=1&amp;b=2"/>` +
        `</md:IDPSSODescriptor></md:EntityDescriptor>`,
    );
    expect(parsed.saml_idp_issuer).toBe(IDP);
    expect(parsed.saml_entry_point).toBe(`${IDP}/sso?a=1&b=2`);
    expect(splitCerts(parsed.saml_idp_cert)).toEqual([body]);
  });

  it("is read through the admin route", async () => {
    server = await startServer();
    const bad = await server.request("POST", "/providers/saml-metadata", {
      body: { xml: "<nope/>" },
    });
    expect(bad.status).toBe(400);
    await server.close();
    server = await startServer({ permissions: [] });
    const denied = await server.request("POST", "/providers/saml-metadata", {
      body: { xml: "<nope/>" },
    });
    expect(denied.status).toBe(403);
  });
});
