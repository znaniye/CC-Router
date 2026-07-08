import { createHash, timingSafeEqual } from "crypto";
import type { AuthorizedKey } from "../config/manager.js";

export interface Credential {
  /** Owner label used for per-user attribution. */
  user: string;
  buf: Buffer;
  /** Disabled credentials still match (so we can report it) but never authorize. */
  enabled: boolean;
}

/**
 * Build the list of known credentials from proxy config. The legacy single
 * `proxySecret` is included under the "shared" label; every per-user key is
 * included with its enabled flag. Disabled keys are kept (not dropped) so the
 * authenticator can distinguish "correct-but-disabled" from "unknown".
 */
export function buildCredentials(config: {
  proxySecret?: string;
  authorizedKeys?: AuthorizedKey[];
}): Credential[] {
  const credentials: Credential[] = [];
  if (config.proxySecret) {
    credentials.push({ user: "shared", buf: Buffer.from(config.proxySecret, "utf-8"), enabled: true });
  }
  for (const k of config.authorizedKeys ?? []) {
    credentials.push({ user: k.user, buf: Buffer.from(k.key, "utf-8"), enabled: k.enabled !== false });
  }
  return credentials;
}

/**
 * Short, non-reversible fingerprint of a token. Lets an operator correlate a
 * rejected token in the server log with a key shown by `cc-router keys list`
 * without ever exposing the secret itself.
 */
export function fingerprint(token: string): string {
  return createHash("sha256").update(token).digest("hex").slice(0, 8);
}

export interface PresentedToken {
  /** The extracted token value (empty when none/ malformed). */
  token: string;
  /** Which header carried the credential. */
  via: "authorization" | "x-api-key" | "none";
  /** Authorization header present but not in "Bearer <token>" form. */
  malformed: boolean;
}

/**
 * Extract the presented credential from request headers, distinguishing a
 * missing header from a malformed one. Bearer takes precedence over x-api-key.
 */
export function extractPresented(headers: {
  authorization?: string;
  "x-api-key"?: string | string[];
}): PresentedToken {
  const auth = typeof headers.authorization === "string" ? headers.authorization : "";
  const apiKeyRaw = headers["x-api-key"];
  const apiKey = Array.isArray(apiKeyRaw) ? apiKeyRaw[0] ?? "" : apiKeyRaw ?? "";

  if (auth) {
    if (auth.startsWith("Bearer ")) {
      return { token: auth.slice(7), via: "authorization", malformed: false };
    }
    // Header is present but not "Bearer <token>" — a common misconfiguration.
    return { token: "", via: "authorization", malformed: true };
  }
  if (apiKey) {
    return { token: apiKey, via: "x-api-key", malformed: false };
  }
  return { token: "", via: "none", malformed: false };
}

export type AuthReason =
  | "no_credentials"    // no Authorization or x-api-key header
  | "malformed_header"  // Authorization present but not "Bearer <token>"
  | "empty_token"       // header present but the token was empty
  | "disabled_key"      // token matches a configured key that is disabled
  | "unknown_token";    // a token was presented but matches nothing

export type AuthOutcome =
  | { ok: true; user: string }
  | {
      ok: false;
      reason: AuthReason;
      via: PresentedToken["via"];
      /** Owner label for the disabled_key case. */
      user?: string;
      tokenLen: number;
      /** Present whenever a non-empty token was actually presented. */
      fingerprint?: string;
    };

/**
 * Authenticate a presented token against the known credentials. Returns a
 * structured outcome so callers can log precisely what happened without
 * leaking the secret. Constant-time compare per candidate; disabled matches
 * are recorded but never authorize.
 */
export function authenticate(credentials: Credential[], presented: PresentedToken): AuthOutcome {
  const { token, via, malformed } = presented;

  if (malformed) return { ok: false, reason: "malformed_header", via, tokenLen: 0 };
  if (via === "none") return { ok: false, reason: "no_credentials", via, tokenLen: 0 };
  if (!token) return { ok: false, reason: "empty_token", via, tokenLen: 0 };

  const presentedBuf = Buffer.from(token, "utf-8");
  let disabledUser: string | undefined;
  for (const cred of credentials) {
    if (presentedBuf.length === cred.buf.length && timingSafeEqual(presentedBuf, cred.buf)) {
      if (cred.enabled) return { ok: true, user: cred.user };
      disabledUser = cred.user;
    }
  }

  const fp = fingerprint(token);
  if (disabledUser !== undefined) {
    return { ok: false, reason: "disabled_key", via, user: disabledUser, tokenLen: token.length, fingerprint: fp };
  }
  return { ok: false, reason: "unknown_token", via, tokenLen: token.length, fingerprint: fp };
}

/**
 * Human-readable, secret-safe description of a failed auth outcome, suitable
 * for the server log. Never includes the token — only its length and
 * fingerprint.
 */
export function describeAuthFailure(outcome: Extract<AuthOutcome, { ok: false }>): string {
  switch (outcome.reason) {
    case "no_credentials":
      return "no credentials (no Authorization or x-api-key header)";
    case "malformed_header":
      return "malformed Authorization header (expected 'Bearer <token>')";
    case "empty_token":
      return `empty token (via ${outcome.via})`;
    case "disabled_key":
      return `token matches DISABLED key for "${outcome.user}" (via ${outcome.via}, len=${outcome.tokenLen}, fp=${outcome.fingerprint})`;
    case "unknown_token":
      return `unknown token (via ${outcome.via}, len=${outcome.tokenLen}, fp=${outcome.fingerprint})`;
  }
}
