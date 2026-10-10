import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import {
  renderWithApp,
  type RenderedPluginApp,
} from "@termix-ssh/plugin-sdk/testing";
import type { PluginManifest } from "@termix-ssh/plugin-sdk/manifest";
import * as plugin from "../../src/frontend/index";
import manifestJson from "../../manifest.json";
import locales from "../../locales/en.json";

const manifest = manifestJson as unknown as PluginManifest;

let rendered: RenderedPluginApp | null = null;

afterEach(async () => {
  await rendered?.deactivate();
  rendered = null;
});

const OIDC_FIELDS = {
  client_id: "termix",
  issuer_url: "https://idp.example",
  authorization_url: "https://idp.example/authorize",
  token_url: "https://idp.example/token",
};

const providers = {
  providers: [
    {
      id: 3,
      name: "Keycloak",
      type: "oidc",
      enabled: true,
      displayOrder: 0,
      legacyCallback: true,
      config: { client_id: "termix" },
      hasClientSecret: true,
      redirectUri: "https://termix.test/users/oidc/callback",
    },
  ],
  newRedirectUri: "https://termix.test/plugin-api/sso/callback",
};

describe(`${manifest.id} activate`, () => {
  it("registers the login buttons and the provider settings", async () => {
    rendered = await renderWithApp(plugin, { manifest, locales });
    expect(rendered.registered.loginMethods()).toEqual(["oidc"]);
    expect(rendered.registered.settingsComponents()).toEqual(["providers"]);
  });

  it("draws a button per provider that starts the redirect", async () => {
    rendered = await renderWithApp(plugin, { manifest, locales });
    const startRedirect = vi.fn(async () => {});
    rendered.renderLoginMethod("oidc", {
      instances: [
        { id: "3", label: "Keycloak" },
        { id: "5", label: "Google" },
      ],
      startRedirect,
    });
    fireEvent.click(screen.getByText("Sign in with Google"));
    await waitFor(() => expect(startRedirect).toHaveBeenCalledWith("5"));
    expect(screen.getByText("Sign in with Keycloak")).toBeTruthy();
  });

  it("lists providers with the redirect URI to register", async () => {
    const get = vi.fn(async () => ({ data: providers }));
    rendered = await renderWithApp(plugin, {
      manifest,
      locales,
      api: { get } as never,
    });
    rendered.renderSettingsComponent("providers");
    expect(await screen.findByText("Keycloak")).toBeTruthy();
    expect(
      screen.getByText("https://termix.test/users/oidc/callback"),
    ).toBeTruthy();
    expect(get).toHaveBeenCalledWith("/providers");
  });

  it("adds a provider and never sends an empty secret", async () => {
    const get = vi.fn(async () => ({
      data: { providers: [], newRedirectUri: providers.newRedirectUri },
    }));
    const post = vi.fn(async () => ({ data: {} }));
    rendered = await renderWithApp(plugin, {
      manifest,
      locales,
      api: { get, post } as never,
    });
    rendered.renderSettingsComponent("providers");
    fireEvent.click(await screen.findByText(locales.providers.add));
    fireEvent.change(
      screen.getByPlaceholderText(locales.providers.namePlaceholder),
      { target: { value: "Corp" } },
    );
    fireEvent.change(screen.getByPlaceholderText("your-client-id"), {
      target: { value: "termix" },
    });
    fireEvent.click(screen.getByText(locales.providers.save));
    await waitFor(() => expect(post).toHaveBeenCalled());
    const [path, body] = post.mock.calls[0] as unknown as [
      string,
      { name: string; type: string; config: Record<string, string> },
    ];
    expect(path).toBe("/providers");
    expect(body).toMatchObject({ name: "Corp", type: "oidc" });
    expect(body.config.client_id).toBe("termix");
    expect(body.config).not.toHaveProperty("client_secret");
  });

  it("sends cleared fields so they are cleared on the server", async () => {
    const withAdminGroup = {
      ...providers,
      providers: [
        {
          ...providers.providers[0],
          config: { ...OIDC_FIELDS, admin_group: "admins" },
        },
      ],
    };
    const get = vi.fn(async () => ({ data: withAdminGroup }));
    const put = vi.fn(async () => ({ data: {} }));
    rendered = await renderWithApp(plugin, {
      manifest,
      locales,
      api: { get, put } as never,
    });
    rendered.renderSettingsComponent("providers");
    fireEvent.click(await screen.findByTitle(locales.providers.edit));
    fireEvent.change(await screen.findByDisplayValue("admins"), {
      target: { value: "" },
    });
    fireEvent.click(screen.getByText(locales.providers.save));
    await waitFor(() => expect(put).toHaveBeenCalled());
    const [path, body] = put.mock.calls[0] as unknown as [
      string,
      { config: Record<string, string> },
    ];
    expect(path).toBe("/providers/3");
    expect(body.config.admin_group).toBe("");
    expect(body.config.issuer_url).toBe(OIDC_FIELDS.issuer_url);
    expect(body.config).not.toHaveProperty("client_secret");
  });

  it("saves an edited allowed users list", async () => {
    const withAllowed = {
      ...providers,
      providers: [
        {
          ...providers.providers[0],
          config: { ...OIDC_FIELDS, allowed_users: "a@x.test\nb@x.test" },
        },
      ],
    };
    const get = vi.fn(async () => ({ data: withAllowed }));
    const put = vi.fn(async () => ({ data: {} }));
    rendered = await renderWithApp(plugin, {
      manifest,
      locales,
      api: { get, put } as never,
    });
    rendered.renderSettingsComponent("providers");
    fireEvent.click(await screen.findByTitle(locales.providers.edit));
    fireEvent.change(await screen.findByDisplayValue(/a@x.test/), {
      target: { value: "a@x.test" },
    });
    fireEvent.click(screen.getByText(locales.providers.save));
    await waitFor(() => expect(put).toHaveBeenCalled());
    const [, body] = put.mock.calls[0] as unknown as [
      string,
      { config: Record<string, string> },
    ];
    expect(body.config.allowed_users).toBe("a@x.test");
  });

  it("removes everything on deactivate", async () => {
    const app = await renderWithApp(plugin, { manifest, locales });
    await app.deactivate();
    expect(app.registered.loginMethods()).toEqual([]);
    expect(app.registered.settingsComponents()).toEqual([]);
  });
});
