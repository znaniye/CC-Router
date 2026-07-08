import type { Command } from "commander";
import chalk from "chalk";
import {
  addAuthorizedKey,
  listAuthorizedKeys,
  revokeAuthorizedKey,
} from "../config/manager.js";
import { PROXY_PORT } from "../config/paths.js";
import { fingerprint } from "../proxy/auth.js";

const RESTART_HINT = "  Restart cc-router for the change to take effect.";

export function registerKeys(program: Command): void {
  const keys = program
    .command("keys")
    .description("Manage per-user access keys for a hosted CC-Router");

  // ── keys add <user> ────────────────────────────────────────────────────────
  keys
    .command("add <user>")
    .description("Generate a new access key for a user")
    .action((user: string) => {
      let record;
      try {
        record = addAuthorizedKey(user);
      } catch (err) {
        console.error(chalk.red((err as Error).message));
        process.exit(1);
      }

      console.log(chalk.green(`✓ Access key created for "${record.user}".`));
      console.log("  " + chalk.bold.yellow("Save this — it will not be shown again:"));
      console.log("  " + chalk.bold(record.key));
      console.log();
      console.log(chalk.gray("  The user sets it as ANTHROPIC_AUTH_TOKEN, or connects with:"));
      console.log(chalk.gray(`    cc-router client connect <url> --secret ${record.key}`));
      console.log(chalk.gray(RESTART_HINT));
    });

  // ── keys list ──────────────────────────────────────────────────────────────
  keys
    .command("list")
    .description("List configured access keys (with live usage if the proxy is up)")
    .option("--json", "Output as JSON")
    .action(async (opts: { json?: boolean }) => {
      const stored = listAuthorizedKeys();
      const usage = await fetchUsageByUser();

      if (opts.json) {
        console.log(JSON.stringify(
          stored.map(k => ({
            user: k.user,
            enabled: k.enabled !== false,
            fingerprint: fingerprint(k.key),
            requests: usage?.[k.user] ?? null,
          })),
          null,
          2,
        ));
        return;
      }

      if (stored.length === 0) {
        console.log(chalk.yellow("No access keys configured. Add one with: cc-router keys add <user>"));
        return;
      }

      console.log(chalk.bold(`\n  Access keys (${stored.length})\n`));
      if (usage) console.log(chalk.green("  ● Proxy is running — showing live usage\n"));

      for (const k of stored) {
        const status = k.enabled === false
          ? chalk.red("disabled")
          : chalk.green("enabled ");
        const masked = maskKey(k.key);
        const fp = chalk.gray(`fp=${fingerprint(k.key)}`);
        const reqs = usage
          ? chalk.gray(`  req ${usage[k.user] ?? 0}`)
          : "";
        console.log(`  ${chalk.bold(k.user.padEnd(20))}  ${status}  ${chalk.gray(masked)}  ${fp}${reqs}`);
      }
      console.log();
      console.log(chalk.gray("  fp matches the fingerprint shown in rejected-auth server logs."));
    });

  // ── keys revoke <user> ─────────────────────────────────────────────────────
  keys
    .command("revoke <user>")
    .description("Remove a user's access key")
    .action((user: string) => {
      const removed = revokeAuthorizedKey(user);
      if (!removed) {
        console.error(chalk.red(`No access key found for "${user}".`));
        process.exit(1);
      }
      console.log(chalk.green(`✓ Access key for "${user}" revoked.`));
      console.log(chalk.gray(RESTART_HINT));
    });
}

/** Show only the prefix and last 4 chars so the key stays unguessable in logs. */
function maskKey(key: string): string {
  if (key.length <= 13) return "…";
  return `${key.slice(0, 9)}…${key.slice(-4)}`;
}

/** Best-effort per-user request counts from a running proxy. Null if it's down. */
async function fetchUsageByUser(): Promise<Record<string, number> | null> {
  try {
    const res = await fetch(`http://localhost:${PROXY_PORT}/cc-router/health`, {
      signal: AbortSignal.timeout(1_000),
    });
    if (!res.ok) return null;
    const data = await res.json() as { usageByUser?: Record<string, number> };
    return data.usageByUser ?? {};
  } catch {
    return null;
  }
}
