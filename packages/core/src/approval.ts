import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import Database from 'better-sqlite3';
import { v4 as uuidv4 } from 'uuid';
import { ApprovalRequest, ApprovalScope, HIGH_RISK_ACTIONS } from './types.js';
import { approvalStorePath } from './paths.js';

/** Pending requests that no human answers expire. An unanswered prompt is a "no". */
export const DEFAULT_PENDING_TTL_MS = 15 * 60 * 1000;

export class ApprovalError extends Error {
  constructor(
    message: string,
    readonly code: 'SELF_APPROVAL' | 'NOT_PENDING' | 'PENDING_EXPIRED' | 'NOT_FOUND'
  ) {
    super(message);
    this.name = 'ApprovalError';
  }
}

export interface GrantOptions {
  /**
   * Scope chosen by the APPROVER. The requester's proposed scope is advisory only.
   * Defaults to 'once' for high-risk actions, otherwise the requested scope.
   */
  scope?: ApprovalScope;
}

export class ApprovalManager {
  private db: Database.Database;
  private readonly cwd: string;

  constructor(cwd = process.cwd()) {
    this.cwd = cwd;
    const path = approvalStorePath(cwd);
    mkdirSync(dirname(path), { recursive: true });
    this.db = new Database(path);
    this.db.pragma('journal_mode = WAL');
    this.init();
  }

  private init(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS approvals (
        request_id TEXT PRIMARY KEY,
        agent_id TEXT NOT NULL,
        shell_id TEXT NOT NULL,
        action TEXT NOT NULL,
        resource TEXT NOT NULL,
        reason TEXT NOT NULL,
        requested_scope TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        created_at TEXT NOT NULL,
        expires_at TEXT,
        decided_at TEXT,
        decided_by TEXT,
        run_id TEXT,
        trace_id TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_approvals_agent ON approvals(agent_id, status);
      CREATE INDEX IF NOT EXISTS idx_approvals_action ON approvals(action, resource, status);
    `);
    // v0.3 migration — additive columns, safe on existing v0.2 databases.
    const cols = new Set(
      (this.db.prepare(`PRAGMA table_info(approvals)`).all() as { name: string }[]).map((c) => c.name)
    );
    const add = (name: string, type: string) => {
      if (!cols.has(name)) this.db.exec(`ALTER TABLE approvals ADD COLUMN ${name} ${type}`);
    };
    add('params_hash', 'TEXT');
    add('params_preview', 'TEXT');
    add('granted_scope', 'TEXT');
    add('pending_expires_at', 'TEXT');
    add('consumed_at', 'TEXT');
  }

  createRequest(input: {
    agentId: string;
    shellId: string;
    action: string;
    resource: string;
    reason: string;
    scope?: ApprovalScope;
    runId?: string;
    traceId?: string;
    /** @deprecated use pendingTtlMs */
    expiresInMs?: number;
    pendingTtlMs?: number;
    /** actionBindingHash(action, resource, parameters) — binds the approval to exact arguments. */
    paramsHash?: string;
    /** Human-readable summary of the bound arguments, shown to the approver. */
    paramsPreview?: string;
  }): ApprovalRequest {
    const now = new Date();
    const ttl = input.pendingTtlMs ?? input.expiresInMs ?? DEFAULT_PENDING_TTL_MS;
    const request: ApprovalRequest = {
      request_id: uuidv4(),
      agent_id: input.agentId,
      shell_id: input.shellId,
      action: input.action,
      resource: input.resource,
      reason: input.reason,
      requested_scope: input.scope ?? 'once',
      status: 'pending',
      created_at: now.toISOString(),
      pending_expires_at: new Date(now.getTime() + ttl).toISOString(),
      params_hash: input.paramsHash,
      params_preview: input.paramsPreview,
      run_id: input.runId,
      trace_id: input.traceId,
    };

    this.db
      .prepare(
        `INSERT INTO approvals (
          request_id, agent_id, shell_id, action, resource, reason,
          requested_scope, status, created_at, expires_at, run_id, trace_id,
          params_hash, params_preview, pending_expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?)`
      )
      .run(
        request.request_id,
        request.agent_id,
        request.shell_id,
        request.action,
        request.resource,
        request.reason,
        request.requested_scope,
        request.status,
        request.created_at,
        request.run_id ?? null,
        request.trace_id ?? null,
        request.params_hash ?? null,
        request.params_preview ?? null,
        request.pending_expires_at ?? null
      );

    return request;
  }

  /**
   * Grant a pending request. Returns undefined when the request does not exist,
   * is no longer pending, or its pending window has elapsed.
   * Throws ApprovalError(SELF_APPROVAL) when the approver is the requesting agent.
   */
  grant(requestId: string, decidedBy: string, options: GrantOptions = {}): ApprovalRequest | undefined {
    const row = this.get(requestId);
    if (!row || row.status !== 'pending') return undefined;
    if (isSelfApproval(row, decidedBy)) {
      throw new ApprovalError(
        `Agent '${row.agent_id}' cannot approve its own request`,
        'SELF_APPROVAL'
      );
    }
    const now = new Date();
    if (row.pending_expires_at && new Date(row.pending_expires_at) <= now) {
      this.markExpired(requestId);
      return undefined;
    }

    const scope = options.scope ?? defaultGrantScope(row);
    const expiresAt = computeExpiry(scope, now.toISOString());

    const changed = this.db
      .prepare(
        `UPDATE approvals SET status = 'granted', decided_at = ?, decided_by = ?, expires_at = ?, granted_scope = ?
         WHERE request_id = ? AND status = 'pending'`
      )
      .run(now.toISOString(), decidedBy, expiresAt, scope, requestId).changes;
    if (changed !== 1) return undefined;

    return this.get(requestId);
  }

  deny(requestId: string, decidedBy: string): ApprovalRequest | undefined {
    const now = new Date().toISOString();
    const changed = this.db
      .prepare(
        `UPDATE approvals SET status = 'denied', decided_at = ?, decided_by = ? WHERE request_id = ? AND status = 'pending'`
      )
      .run(now, decidedBy, requestId).changes;
    return changed === 1 ? this.get(requestId) : undefined;
  }

  get(requestId: string): ApprovalRequest | undefined {
    const row = this.db
      .prepare(`SELECT * FROM approvals WHERE request_id = ?`)
      .get(requestId) as Record<string, string> | undefined;
    return row ? this.rowToRequest(row) : undefined;
  }

  listPending(agentId?: string): ApprovalRequest[] {
    this.expireStalePending();
    const rows = agentId
      ? (this.db
          .prepare(`SELECT * FROM approvals WHERE status = 'pending' AND agent_id = ?`)
          .all(agentId) as Record<string, string>[])
      : (this.db.prepare(`SELECT * FROM approvals WHERE status = 'pending'`).all() as Record<
          string,
          string
        >[]);
    return rows.map((r) => this.rowToRequest(r));
  }

  listGranted(agentId?: string): ApprovalRequest[] {
    const now = new Date().toISOString();
    const rows = agentId
      ? (this.db
          .prepare(
            `SELECT * FROM approvals WHERE status = 'granted' AND consumed_at IS NULL AND agent_id = ? AND (expires_at IS NULL OR expires_at > ?)`
          )
          .all(agentId, now) as Record<string, string>[])
      : (this.db
          .prepare(
            `SELECT * FROM approvals WHERE status = 'granted' AND consumed_at IS NULL AND (expires_at IS NULL OR expires_at > ?)`
          )
          .all(now) as Record<string, string>[]);
    return rows.map((r) => this.rowToRequest(r));
  }

  /**
   * Atomically claim a once-scoped approval BEFORE the protected action runs.
   * Exactly one caller can win; concurrent or repeated use gets false.
   * The claim is not refunded if the action fails — a once-approval is single-use.
   * Returns true for non-once scopes (they remain valid until expiry).
   */
  claim(requestId: string): boolean {
    const row = this.get(requestId);
    if (!row || row.status !== 'granted') return false;
    const scope = row.granted_scope ?? row.requested_scope;
    if (scope !== 'once') {
      return !row.expires_at || new Date(row.expires_at) > new Date();
    }
    const now = new Date().toISOString();
    const changed = this.db
      .prepare(
        `UPDATE approvals SET status = 'expired', consumed_at = ?
         WHERE request_id = ? AND status = 'granted' AND consumed_at IS NULL
           AND (expires_at IS NULL OR expires_at > ?)`
      )
      .run(now, requestId, now).changes;
    return changed === 1;
  }

  /** @deprecated v0.2 consumed after success; v0.3 claims before execution. Kept for API compat. */
  consumeOnce(requestId: string): boolean {
    return this.claim(requestId);
  }

  private markExpired(requestId: string): void {
    this.db
      .prepare(`UPDATE approvals SET status = 'expired' WHERE request_id = ? AND status = 'pending'`)
      .run(requestId);
  }

  private expireStalePending(): void {
    this.db
      .prepare(
        `UPDATE approvals SET status = 'expired' WHERE status = 'pending' AND pending_expires_at IS NOT NULL AND pending_expires_at <= ?`
      )
      .run(new Date().toISOString());
  }

  private rowToRequest(row: Record<string, string>): ApprovalRequest {
    return {
      request_id: row.request_id,
      agent_id: row.agent_id,
      shell_id: row.shell_id,
      action: row.action,
      resource: row.resource,
      reason: row.reason,
      requested_scope: row.requested_scope as ApprovalScope,
      granted_scope: (row.granted_scope ?? undefined) as ApprovalScope | undefined,
      status: row.status as ApprovalRequest['status'],
      created_at: row.created_at,
      expires_at: row.expires_at ?? undefined,
      pending_expires_at: row.pending_expires_at ?? undefined,
      decided_at: row.decided_at ?? undefined,
      decided_by: row.decided_by ?? undefined,
      consumed_at: row.consumed_at ?? undefined,
      params_hash: row.params_hash ?? undefined,
      params_preview: row.params_preview ?? undefined,
      run_id: row.run_id ?? undefined,
      trace_id: row.trace_id ?? undefined,
    };
  }

  close(): void {
    this.db.close();
  }
}

function isSelfApproval(row: ApprovalRequest, decidedBy: string): boolean {
  const who = decidedBy.trim().toLowerCase();
  return who === row.agent_id.toLowerCase() || who === row.shell_id.toLowerCase() || who === '';
}

function defaultGrantScope(row: ApprovalRequest): ApprovalScope {
  if (HIGH_RISK_ACTIONS.has(row.action) || row.action.startsWith('payment.')) return 'once';
  return row.requested_scope;
}

function computeExpiry(scope: ApprovalScope, decidedAt: string): string | null {
  const base = new Date(decidedAt);
  switch (scope) {
    case 'once':
      return new Date(base.getTime() + 5 * 60 * 1000).toISOString();
    case 'session':
      return new Date(base.getTime() + 8 * 60 * 60 * 1000).toISOString();
    case 'project':
      return new Date(base.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString();
    case 'permanent':
      return null;
    default:
      return new Date(base.getTime() + 5 * 60 * 1000).toISOString();
  }
}

export function createApprovalManager(cwd?: string): ApprovalManager {
  return new ApprovalManager(cwd);
}
