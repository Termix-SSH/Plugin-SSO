/**
 * SAML 2.0 sign in. Termix sends an AuthnRequest with the HTTP-Redirect
 * binding and takes the answer on the HTTP-POST binding at /saml/acs.
 * Only logins Termix started are accepted (InResponseTo is required).
 */

import {
  SAML,
  ValidateInResponseTo,
  type CacheProvider,
  type Profile,
} from "@node-saml/node-saml";
import type { PluginContext } from "@termix-ssh/plugin-sdk/backend";
import type { OidcConfig } from "./types.js";

export const SAML_ACS_PATH = "/plugin-api/sso/saml/acs";
export const SAML_METADATA_PATH = "/plugin-api/sso/saml/metadata";

const REQUEST_PREFIX = "saml-req:";
const ASSERTION_PREFIX = "saml-asrt:";
const REQUEST_TTL_MS = 10 * 60 * 1000;
const CLOCK_SKEW_MS = 2 * 60 * 1000;

const DEFAULT_EMAIL_ATTRS = [
  "email",
  "mail",
  "emailaddress",
  "urn:oid:0.9.2342.19200300.100.1.3",
  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
];
const DEFAULT_NAME_ATTRS = [
  "username",
  "uid",
  "preferred_username",
  "urn:oid:0.9.2342.19200300.100.1.1",
  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
  "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname",
  "name",
  "displayName",
];
const DEFAULT_GROUP_ATTRS = [
  "groups",
  "memberOf",
  "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
  "http://schemas.xmlsoap.org/claims/Group",
  "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
  "Role",
  "role",
];

/** Base64 body of each certificate, as node-saml wants them. */
export function splitCerts(raw: string | undefined): string[] {
  if (!raw) return [];
  const blocks = raw.match(
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g,
  );
  const bodies = blocks
    ? blocks.map((block) =>
        block
          .replace(/-----(BEGIN|END) CERTIFICATE-----/g, "")
          .replace(/\s+/g, ""),
      )
    : [raw.replace(/\s+/g, "")];
  return bodies.filter((body) => /^[A-Za-z0-9+/=]{100,}$/.test(body));
}

export function samlEntityId(baseUrl: string, config: OidcConfig): string {
  return config.saml_sp_entity_id?.trim() || `${baseUrl}${SAML_METADATA_PATH}`;
}

/** Request ids and seen assertion ids live in kv, so a restart keeps them. */
export function kvCache(ctx: PluginContext): CacheProvider {
  async function sweep() {
    const now = Date.now();
    for (const key of await ctx.kv.list()) {
      if (!key.startsWith(REQUEST_PREFIX) && !key.startsWith(ASSERTION_PREFIX))
        continue;
      const entry = (await ctx.kv.get(key)) as { expiresAt?: number } | null;
      if (!entry || (entry.expiresAt ?? 0) < now) await ctx.kv.delete(key);
    }
  }
  async function read(key: string): Promise<string | null> {
    const entry = (await ctx.kv.get(key)) as {
      value?: string;
      expiresAt?: number;
    } | null;
    if (!entry || typeof entry.value !== "string") return null;
    return (entry.expiresAt ?? 0) < Date.now() ? null : entry.value;
  }
  return {
    async saveAsync(key, value) {
      await sweep();
      const createdAt = Date.now();
      await ctx.kv.set(`${REQUEST_PREFIX}${key}`, {
        value,
        expiresAt: createdAt + REQUEST_TTL_MS,
      });
      return { value, createdAt };
    },
    getAsync: (key) => read(`${REQUEST_PREFIX}${key}`),
    async removeAsync(key) {
      if (!key) return null;
      const value = await read(`${REQUEST_PREFIX}${key}`);
      await ctx.kv.delete(`${REQUEST_PREFIX}${key}`);
      return value;
    },
    async consumeAsync(key) {
      const value = await read(`${REQUEST_PREFIX}${key}`);
      await ctx.kv.delete(`${REQUEST_PREFIX}${key}`);
      return value;
    },
    async saveIfAbsentAsync(key, value, expiresAtMs) {
      const full = `${ASSERTION_PREFIX}${key}`;
      if ((await read(full)) !== null) return false;
      await ctx.kv.set(full, { value, expiresAt: expiresAtMs });
      return true;
    },
  };
}

export function createSamlClient(
  ctx: PluginContext,
  config: OidcConfig,
  baseUrl: string,
): SAML {
  const issuer = samlEntityId(baseUrl, config);
  const privateKey = config.saml_sp_private_key?.trim();
  return new SAML({
    entryPoint: config.saml_entry_point,
    idpCert: splitCerts(config.saml_idp_cert),
    idpIssuer: config.saml_idp_issuer?.trim() || undefined,
    issuer,
    audience: issuer,
    callbackUrl: `${baseUrl}${SAML_ACS_PATH}`,
    identifierFormat: config.saml_nameid_format?.trim() || null,
    wantAssertionsSigned: true,
    wantAuthnResponseSigned: config.saml_want_response_signed === "1",
    validateInResponseTo: ValidateInResponseTo.always,
    requestIdExpirationPeriodMs: REQUEST_TTL_MS,
    rejectReplayedAssertions: true,
    acceptedClockSkewMs: CLOCK_SKEW_MS,
    cacheProvider: kvCache(ctx),
    disableRequestedAuthnContext: true,
    signatureAlgorithm: "sha256",
    ...(privateKey
      ? {
          privateKey,
          ...(config.saml_sp_cert?.trim()
            ? { publicCert: config.saml_sp_cert.trim() }
            : {}),
        }
      : {}),
  });
}

/** This server's SP metadata for one provider. */
export function samlMetadata(
  ctx: PluginContext,
  config: OidcConfig,
  baseUrl: string,
): string {
  const client = createSamlClient(ctx, config, baseUrl);
  const cert = config.saml_sp_cert?.trim();
  return client.generateServiceProviderMetadata(null, cert ? [cert] : null);
}

type Attributes = Record<string, unknown>;

function attributesOf(profile: Profile): Attributes {
  const nested = (profile as { attributes?: unknown }).attributes;
  return {
    ...(profile as unknown as Attributes),
    ...(nested && typeof nested === "object" ? (nested as Attributes) : {}),
  };
}

function lookup(attrs: Attributes, names: string[]): unknown {
  const lower = new Map(
    Object.keys(attrs).map((key) => [key.toLowerCase(), key]),
  );
  for (const name of names) {
    const key = lower.get(name.toLowerCase());
    if (key === undefined) continue;
    const value = attrs[key];
    if (value !== undefined && value !== null && value !== "") return value;
  }
  return undefined;
}

function first(value: unknown): string | null {
  const one = Array.isArray(value) ? value[0] : value;
  return typeof one === "string" && one.trim() ? one.trim() : null;
}

function names(configured: string | undefined, defaults: string[]): string[] {
  const own = (configured ?? "")
    .split(",")
    .map((name) => name.trim())
    .filter(Boolean);
  return own.length > 0 ? own : defaults;
}

export interface SamlUser {
  subject: string;
  email: string | null;
  name: string;
  groups: string[];
}

/** Picks the Termix identity out of a verified profile. */
export function samlUser(profile: Profile, config: OidcConfig): SamlUser {
  const attrs = attributesOf(profile);
  const transient = /:transient$/.test(profile.nameIDFormat ?? "");
  const identifierAttr = config.saml_identifier_attr?.trim();
  const email = first(
    lookup(attrs, names(config.saml_email_attr, DEFAULT_EMAIL_ATTRS)),
  );
  const subject =
    (identifierAttr ? first(lookup(attrs, [identifierAttr])) : null) ??
    (!transient && profile.nameID ? profile.nameID : null) ??
    email;
  if (!subject) {
    throw new Error(
      `No user identifier in the SAML answer. Attributes: ${Object.keys(
        (profile as { attributes?: object }).attributes ?? {},
      ).join(", ")}`,
    );
  }
  const name =
    first(lookup(attrs, names(config.saml_name_attr, DEFAULT_NAME_ATTRS))) ??
    (email ? email.split("@")[0] : subject);
  const rawGroups = lookup(
    attrs,
    names(config.saml_groups_attr, DEFAULT_GROUP_ATTRS),
  );
  const groups = (Array.isArray(rawGroups) ? rawGroups : [rawGroups])
    .filter((group): group is string => typeof group === "string")
    .map((group) => group.trim())
    .filter(Boolean);
  return { subject, email, name, groups };
}

export interface ParsedIdpMetadata {
  saml_idp_issuer: string;
  saml_entry_point: string;
  saml_idp_cert: string;
}

/** Reads the fields Termix needs out of an IdP metadata document. */
export function parseIdpMetadata(xml: string): ParsedIdpMetadata {
  const descriptor = xml.match(
    /<(?:\w+:)?IDPSSODescriptor[\s\S]*?<\/(?:\w+:)?IDPSSODescriptor>/,
  )?.[0];
  if (!descriptor) throw new Error("No IDPSSODescriptor in the metadata");
  const entity = xml.match(
    /<(?:\w+:)?EntityDescriptor[^>]*\sentityID="([^"]+)"/,
  );
  let entryPoint = "";
  for (const tag of descriptor.match(
    /<(?:\w+:)?SingleSignOnService\b[^>]*>/g,
  ) ?? []) {
    if (
      /Binding="urn:oasis:names:tc:SAML:2\.0:bindings:HTTP-Redirect"/.test(tag)
    ) {
      entryPoint = tag.match(/Location="([^"]+)"/)?.[1] ?? "";
      break;
    }
  }
  if (!entryPoint) throw new Error("The IdP has no HTTP-Redirect sign in URL");
  const certs: string[] = [];
  for (const key of descriptor.match(
    /<(?:\w+:)?KeyDescriptor\b[^>]*>[\s\S]*?<\/(?:\w+:)?KeyDescriptor>/g,
  ) ?? []) {
    if (/use="encryption"/.test(key)) continue;
    for (const cert of key.match(
      /<(?:\w+:)?X509Certificate>([\s\S]*?)<\/(?:\w+:)?X509Certificate>/g,
    ) ?? []) {
      const body = cert.replace(/<[^>]+>/g, "").replace(/\s+/g, "");
      if (body && !certs.includes(body)) certs.push(body);
    }
  }
  if (certs.length === 0)
    throw new Error("No signing certificate in the metadata");
  return {
    saml_idp_issuer: entity?.[1] ?? "",
    saml_entry_point: entryPoint.replace(/&amp;/g, "&"),
    saml_idp_cert: certs
      .map(
        (body) =>
          `-----BEGIN CERTIFICATE-----\n${body.match(/.{1,64}/g)!.join("\n")}\n-----END CERTIFICATE-----`,
      )
      .join("\n"),
  };
}
