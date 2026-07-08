export interface LogEntry {
  ts: number;
  accountId: string;
  model: string;
  type: "route" | "refresh" | "error";
  details?: string;
  statusCode?: number;
  durationMs?: number;
  method?: string;
  path?: string;
  source?: "cli" | "desktop" | "api";
  /** Owner label of the access key that authenticated this request, if any. */
  user?: string;
  // Token usage from Anthropic response (message_start + message_delta events)
  cacheReadTokens?: number;
  cacheCreationTokens?: number;
  inputTokens?: number;
  outputTokens?: number;
}

const MAX_LOG_ENTRIES = 100;

class ProxyStats {
  totalRequests = 0;
  totalErrors = 0;
  totalRefreshes = 0;
  totalCacheReadTokens = 0;
  totalCacheCreationTokens = 0;
  totalInputTokens = 0;
  totalOutputTokens = 0;
  readonly startTime = Date.now();
  private logs: LogEntry[] = [];
  private requestsByUser = new Map<string, number>();

  addLog(entry: LogEntry): void {
    this.logs.push(entry);
    if (this.logs.length > MAX_LOG_ENTRIES) this.logs.shift();
  }

  /** Increment the per-user request counter. No-op when user is undefined. */
  incrUser(user?: string): void {
    if (!user) return;
    this.requestsByUser.set(user, (this.requestsByUser.get(user) ?? 0) + 1);
  }

  /** Snapshot of request counts keyed by access-key owner. */
  getUsageByUser(): Record<string, number> {
    return Object.fromEntries(this.requestsByUser);
  }

  getRecentLogs(n = 20): LogEntry[] {
    return [...this.logs].reverse().slice(0, n);
  }

  getUptimeSeconds(): number {
    return Math.round((Date.now() - this.startTime) / 1000);
  }
}

// Singleton — shared across server and health endpoint
export const stats = new ProxyStats();
