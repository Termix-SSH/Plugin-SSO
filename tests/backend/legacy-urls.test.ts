import { describe, expect, it } from "vitest";
import { validateManifest } from "@termix/plugin-sdk/manifest";
import manifest from "../../manifest.json";

// The 2.8 config URL Termix-Mobile still reads keeps reaching the plugin.
const redirects = manifest.contributes.http.legacyRedirects as unknown[];

describe("legacy URLs", () => {
  it("declares them in a manifest that validates", () => {
    expect(validateManifest(manifest)).toEqual([]);
  });

  it("redirects /users/oidc-config, which 2.8 clients read", () => {
    expect(redirects).toContainEqual({
      from: "/users/oidc-config",
      to: "/config",
    });
  });

  it("no longer redirects the 2.8 callback URLs", () => {
    const from = redirects.map((entry) => (entry as { from: string }).from);
    expect(from).not.toContain("/users/oidc/callback");
    expect(from).not.toContain("/users/oidc/backchannel-logout");
  });
});
