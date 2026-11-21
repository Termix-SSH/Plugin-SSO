export type SsoProviderType = "oidc" | "github" | "google" | "saml";

export const SSO_PROVIDER_TYPES: readonly SsoProviderType[] = [
  "oidc",
  "github",
  "google",
  "saml",
];

export interface OidcConfig {
  client_id: string;
  client_secret: string;
  issuer_url: string;
  authorization_url: string;
  token_url: string;
  userinfo_url: string;
  identifier_path: string;
  name_path: string;
  scopes: string;
  allowed_users: string;
  admin_group: string;
  group_claim?: string;
  role_map?: string;
  ca_cert?: string;
  /** "1" sends the browser to the provider's sign out page on sign out. */
  sign_out_at_provider?: string;
  /** The provider's sign out page. Empty uses end_session_endpoint from discovery. */
  end_session_url?: string;
  /** SAML: the identity provider's sign in URL (HTTP-Redirect binding). */
  saml_entry_point?: string;
  /** SAML: the identity provider's signing certificates, PEM. */
  saml_idp_cert?: string;
  /** SAML: the identity provider's entity id. Empty skips the issuer check. */
  saml_idp_issuer?: string;
  /** SAML: this server's entity id. Empty uses the metadata URL. */
  saml_sp_entity_id?: string;
  saml_nameid_format?: string;
  /** SAML: attribute names. Empty identifier uses the NameID. */
  saml_identifier_attr?: string;
  saml_email_attr?: string;
  saml_name_attr?: string;
  saml_groups_attr?: string;
  /** SAML: "1" also needs the whole response signed, not just the assertion. */
  saml_want_response_signed?: string;
  /** SAML: PEM key and certificate to sign requests with. */
  saml_sp_private_key?: string;
  saml_sp_cert?: string;
}

/** A provider ready to sign someone in: secrets opened, defaults applied. */
export interface ResolvedProvider {
  config: OidcConfig;
  type: SsoProviderType;
  /** The row id, or null for the provider configured through OIDC_* env vars. */
  rowId: number | null;
  /** Sends the 2.8 redirect URI, /users/oidc/callback, which core forwards. */
  legacyCallback: boolean;
}

export interface ProviderRow {
  id: number;
  name: string;
  type: string;
  enabled: boolean;
  displayOrder: number;
  config: string;
  legacyCallback: boolean;
  createdAt: string;
  updatedAt: string;
}
