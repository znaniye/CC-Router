import chalk from "chalk";

function ts(): string {
  return new Date().toISOString().slice(11, 19); // HH:MM:SS
}

export function logRoute(accountId: string, requestCount: number, expiresInMin: number, user?: string): void {
  console.log(
    chalk.gray(`[${ts()}]`) +
    chalk.green(` → ${accountId}`) +
    (user ? chalk.blueBright(` [${user}]`) : "") +
    chalk.gray(` req#${requestCount}`) +
    chalk.yellow(` exp=${expiresInMin}min`)
  );
}

/**
 * Log a rejected connection attempt at the auth boundary. `reason` is a short
 * label ("no token" / "invalid token") — the presented token is never logged.
 */
export function logAuthReject(clientIp: string, reason: string, method?: string, path?: string): void {
  const where = method && path ? ` ${method} ${path}` : "";
  console.log(chalk.red(`[${ts()}] [AUTH] ✗ rejected ${clientIp}${where} — ${reason}`));
}

/** Log an accepted connection at the auth boundary (first request per user). */
export function logAuthAccept(user: string, clientIp: string): void {
  console.log(chalk.green(`[${ts()}] [AUTH] ✓ accepted ${user} from ${clientIp}`));
}

export function logRefresh(accountId: string, ok: boolean, expiresInMin?: number): void {
  if (ok) {
    console.log(chalk.yellow(`[${ts()}] [REFRESH] ${accountId}: OK — expires in ${expiresInMin}min`));
  } else {
    console.log(chalk.red(`[${ts()}] [REFRESH] ${accountId}: FAILED`));
  }
}

export function logError(accountId: string, status: number, message: string): void {
  const statusStr = status > 0 ? ` HTTP ${status}` : "";
  console.log(chalk.red(`[${ts()}] [ERROR] ${accountId}:${statusStr} ${message}`));
}

export interface StartupAccountCounts {
  anthropic: number;
  openai: number;
}

function formatStartupAccountCounts(counts: StartupAccountCounts): string {
  const total = counts.anthropic + counts.openai;
  return `${total} (Claude ${counts.anthropic}, OpenAI ${counts.openai})`;
}

export function logStartup(port: number, host: string, mode: string, target: string, accountCounts: StartupAccountCounts): void {
  const listen = host === "127.0.0.1" ? `http://localhost:${port}` : `http://${host}:${port}`;
  const accounts = formatStartupAccountCounts(accountCounts);
  console.log(chalk.cyan(`
╔══════════════════════════════════════════════╗
║  CC-Router                                   ║
║  Listening: ${listen.padEnd(33)}║
║  Mode     : ${mode.padEnd(33)}║
║  Target   : ${target.slice(0, 33).padEnd(33)}║
║  Accounts : ${accounts.padEnd(33)}║
╚══════════════════════════════════════════════╝
`));
}
