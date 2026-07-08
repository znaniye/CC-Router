import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs";

const MOCK_DIR = vi.hoisted(() => {
  const tmp = process.env["TMPDIR"] ?? process.env["TEMP"] ?? "/tmp";
  return `${tmp}/cc-router-keys-${Date.now()}-${Math.floor(Math.random() * 10_000)}`;
});

vi.mock("../config/paths.js", () => ({
  CONFIG_DIR: MOCK_DIR,
  ACCOUNTS_PATH: `${MOCK_DIR}/accounts.json`,
  CONFIG_PATH: `${MOCK_DIR}/config.json`,
  CLAUDE_SETTINGS_PATH: `${MOCK_DIR}/settings.json`,
  PROXY_PORT: 3456,
  LITELLM_PORT: 4000,
  LITELLM_URL: undefined,
}));

import {
  addAuthorizedKey,
  listAuthorizedKeys,
  revokeAuthorizedKey,
  generateUserKey,
} from "../config/manager.js";
import {
  buildCredentials,
  extractPresented,
  authenticate,
  describeAuthFailure,
  fingerprint,
} from "../proxy/auth.js";

/** Convenience: authenticate a raw Bearer token against a config. */
function authBearer(config: Parameters<typeof buildCredentials>[0], token: string) {
  return authenticate(buildCredentials(config), extractPresented({ authorization: `Bearer ${token}` }));
}

beforeEach(() => {
  fs.mkdirSync(MOCK_DIR, { recursive: true });
});

afterEach(() => {
  fs.rmSync(MOCK_DIR, { recursive: true, force: true });
});

describe("generateUserKey", () => {
  it("uses the sk-proxy- prefix and is unguessable", () => {
    const key = generateUserKey();
    expect(key.startsWith("sk-proxy-")).toBe(true);
    expect(key.length).toBeGreaterThan(20);
    expect(generateUserKey()).not.toBe(key);
  });
});

describe("authorized keys config helpers", () => {
  it("adds, lists, and revokes keys with a config round-trip", () => {
    const alice = addAuthorizedKey("alice");
    expect(alice.user).toBe("alice");
    expect(alice.enabled).toBe(true);
    expect(alice.key.startsWith("sk-proxy-")).toBe(true);

    addAuthorizedKey("bob");
    const listed = listAuthorizedKeys();
    expect(listed.map(k => k.user).sort()).toEqual(["alice", "bob"]);

    expect(revokeAuthorizedKey("alice")).toBe(true);
    expect(listAuthorizedKeys().map(k => k.user)).toEqual(["bob"]);
  });

  it("rejects a duplicate user", () => {
    addAuthorizedKey("alice");
    expect(() => addAuthorizedKey("alice")).toThrow(/already exists/);
  });

  it("rejects an empty user", () => {
    expect(() => addAuthorizedKey("   ")).toThrow(/must not be empty/);
  });

  it("returns false when revoking an unknown user", () => {
    expect(revokeAuthorizedKey("nobody")).toBe(false);
  });
});

describe("extractPresented", () => {
  it("reads a Bearer token from Authorization", () => {
    expect(extractPresented({ authorization: "Bearer abc" }))
      .toEqual({ token: "abc", via: "authorization", malformed: false });
  });

  it("reads x-api-key when Authorization is absent", () => {
    expect(extractPresented({ "x-api-key": "abc" }))
      .toEqual({ token: "abc", via: "x-api-key", malformed: false });
  });

  it("flags a non-Bearer Authorization header as malformed", () => {
    expect(extractPresented({ authorization: "Basic abc" }))
      .toEqual({ token: "", via: "authorization", malformed: true });
  });

  it("reports no credentials when neither header is present", () => {
    expect(extractPresented({})).toEqual({ token: "", via: "none", malformed: false });
  });
});

describe("authenticate", () => {
  it("accepts the legacy proxySecret under the 'shared' label", () => {
    expect(authBearer({ proxySecret: "cc-rtr-legacy" }, "cc-rtr-legacy"))
      .toEqual({ ok: true, user: "shared" });
  });

  it("accepts any enabled per-user key and returns its owner", () => {
    const config = {
      authorizedKeys: [
        { user: "alice", key: "cc-key-alice", enabled: true },
        { user: "bob", key: "cc-key-bob" },
      ],
    };
    expect(authBearer(config, "cc-key-alice")).toEqual({ ok: true, user: "alice" });
    expect(authBearer(config, "cc-key-bob")).toEqual({ ok: true, user: "bob" });
  });

  it("accepts the legacy secret and per-user keys together", () => {
    const config = {
      proxySecret: "cc-rtr-legacy",
      authorizedKeys: [{ user: "alice", key: "cc-key-alice" }],
    };
    expect(authBearer(config, "cc-rtr-legacy")).toEqual({ ok: true, user: "shared" });
    expect(authBearer(config, "cc-key-alice")).toEqual({ ok: true, user: "alice" });
  });

  it("distinguishes a correct-but-disabled key from an unknown token", () => {
    const config = { authorizedKeys: [{ user: "carol", key: "cc-key-carol", enabled: false }] };

    const disabled = authBearer(config, "cc-key-carol");
    expect(disabled.ok).toBe(false);
    if (!disabled.ok) {
      expect(disabled.reason).toBe("disabled_key");
      expect(disabled.user).toBe("carol");
      expect(disabled.fingerprint).toBe(fingerprint("cc-key-carol"));
    }

    const unknown = authBearer(config, "cc-key-nope");
    expect(unknown.ok).toBe(false);
    if (!unknown.ok) {
      expect(unknown.reason).toBe("unknown_token");
      expect(unknown.user).toBeUndefined();
      expect(unknown.fingerprint).toBe(fingerprint("cc-key-nope"));
    }
  });

  it("reports no_credentials and malformed_header distinctly", () => {
    const creds = buildCredentials({ authorizedKeys: [{ user: "alice", key: "cc-key-alice" }] });
    const none = authenticate(creds, extractPresented({}));
    const bad = authenticate(creds, extractPresented({ authorization: "Basic x" }));
    expect(none.ok === false && none.reason).toBe("no_credentials");
    expect(bad.ok === false && bad.reason).toBe("malformed_header");
  });

  it("treats a differing-length token as unknown, not a match", () => {
    const result = authBearer({ authorizedKeys: [{ user: "alice", key: "cc-key-alice" }] }, "cc-key-alice-extra");
    expect(result.ok === false && result.reason).toBe("unknown_token");
  });

  it("produces no credentials when nothing is configured", () => {
    expect(buildCredentials({})).toHaveLength(0);
  });
});

describe("fingerprint", () => {
  it("is stable, 8 hex chars, and non-reversible", () => {
    const fp = fingerprint("cc-key-alice");
    expect(fp).toMatch(/^[0-9a-f]{8}$/);
    expect(fingerprint("cc-key-alice")).toBe(fp);
    expect(fingerprint("cc-key-bob")).not.toBe(fp);
    expect(fp).not.toContain("alice");
  });
});

describe("describeAuthFailure", () => {
  it("never includes the token, only length and fingerprint", () => {
    const secret = "cc-key-supersecretvalue";
    const outcome = authBearer({ authorizedKeys: [{ user: "x", key: "cc-key-other" }] }, secret);
    if (outcome.ok) throw new Error("expected rejection");
    const msg = describeAuthFailure(outcome);
    expect(msg).toContain(`fp=${fingerprint(secret)}`);
    expect(msg).toContain(`len=${secret.length}`);
    expect(msg).not.toContain(secret);
  });
});
