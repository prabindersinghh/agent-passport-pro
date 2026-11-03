import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import Database from 'better-sqlite3';

/**
 * Local spend ledger. Every attempted payment gets a row — blocked ones included —
 * so budgets, velocity and split detection are computed from facts, not from what
 * the agent says it has spent.
 *
 * Statuses that consume budget: reserved, pending_approval, held, captured,
 * needs_reconciliation. A payment stuck in an unknown provider state keeps
 * consuming budget until a human reconciles it (fail closed).
 */
export type PaymentStatus =
  | 'reserved'
  | 'pending_approval'
  | 'held'
  | 'captured'
  | 'voided'
  | 'blocked'
  | 'rejected'
  | 'expired'
  | 'failed'
  | 'needs_reconciliation';

export const BUDGET_STATUSES: PaymentStatus[] = [
  'reserved',
  'pending_approval',
  'held',
  'captured',
  'needs_reconciliation',
];

export interface PaymentRow {
  id: string;
  agent_id: string;
  mandate_id: string | null;
  merchant_id: string;
  merchant_name: string;
  merchant_skeleton: string;
  payee_email: string | null;
  category: string;
  amount_minor: number;
  currency: string;
  description: string;
  status: PaymentStatus;
  idempotency_key: string | null;
  params_hash: string;
  approval_request_id: string | null;
  order_id: string | null;
  authorization_id: string | null;
  capture_id: string | null;
  findings: string;
  created_at: string;
  updated_at: string;
  hold_expires_at: string | null;
}

export class SpendLedger {
  readonly db: Database.Database;

  constructor(cwd: string) {
    const path = join(cwd, '.agent', 'payments.db');
    mkdirSync(dirname(path), { recursive: true });
    this.db = new Database(path);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('busy_timeout = 5000');
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS payments (
        id TEXT PRIMARY KEY,
        agent_id TEXT NOT NULL,
        mandate_id TEXT,
        merchant_id TEXT NOT NULL,
        merchant_name TEXT NOT NULL,
        merchant_skeleton TEXT NOT NULL,
        payee_email TEXT,
        category TEXT NOT NULL,
        amount_minor INTEGER NOT NULL,
        currency TEXT NOT NULL,
        description TEXT NOT NULL,
        status TEXT NOT NULL,
        idempotency_key TEXT,
        params_hash TEXT NOT NULL,
        approval_request_id TEXT,
        order_id TEXT,
        authorization_id TEXT,
        capture_id TEXT,
        findings TEXT NOT NULL DEFAULT '[]',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        hold_expires_at TEXT
      );
      CREATE UNIQUE INDEX IF NOT EXISTS idx_pay_idem ON payments(agent_id, idempotency_key)
        WHERE idempotency_key IS NOT NULL;
      CREATE INDEX IF NOT EXISTS idx_pay_agent_time ON payments(agent_id, created_at);
      CREATE INDEX IF NOT EXISTS idx_pay_mandate ON payments(mandate_id);
      CREATE TABLE IF NOT EXISTS frozen_mandates (
        mandate_id TEXT PRIMARY KEY,
        reason TEXT NOT NULL,
        frozen_at TEXT NOT NULL
      );
    `);
  }

  /** Run fn inside an IMMEDIATE transaction: check-then-reserve is atomic across processes. */
  atomic<T>(fn: () => T): T {
    return this.db.transaction(fn).immediate();
  }

  insert(row: PaymentRow): void {
    this.db
      .prepare(
        `INSERT INTO payments (id, agent_id, mandate_id, merchant_id, merchant_name, merchant_skeleton, payee_email,
          category, amount_minor, currency, description, status, idempotency_key, params_hash,
          approval_request_id, order_id, authorization_id, capture_id, findings, created_at, updated_at, hold_expires_at)
         VALUES (@id, @agent_id, @mandate_id, @merchant_id, @merchant_name, @merchant_skeleton, @payee_email,
          @category, @amount_minor, @currency, @description, @status, @idempotency_key, @params_hash,
          @approval_request_id, @order_id, @authorization_id, @capture_id, @findings, @created_at, @updated_at, @hold_expires_at)`
      )
      .run(row);
  }

  get(id: string): PaymentRow | undefined {
    return this.db.prepare(`SELECT * FROM payments WHERE id = ?`).get(id) as PaymentRow | undefined;
  }

  byIdempotencyKey(agentId: string, key: string): PaymentRow | undefined {
    return this.db
      .prepare(`SELECT * FROM payments WHERE agent_id = ? AND idempotency_key = ?`)
      .get(agentId, key) as PaymentRow | undefined;
  }

  /** Compare-and-set status transition. Returns false if the row was not in `from`. */
  transition(id: string, from: PaymentStatus[], to: PaymentStatus, patch: Partial<PaymentRow> = {}): boolean {
    const sets = ['status = @to', 'updated_at = @now'];
    const params: Record<string, unknown> = { id, to, now: new Date().toISOString() };
    for (const [k, v] of Object.entries(patch)) {
      if (!/^[a-z_]+$/.test(k)) throw new Error('bad column');
      sets.push(`${k} = @p_${k}`);
      params[`p_${k}`] = v;
    }
    const placeholders = from.map((_, i) => `@f${i}`).join(', ');
    from.forEach((s, i) => (params[`f${i}`] = s));
    const res = this.db
      .prepare(`UPDATE payments SET ${sets.join(', ')} WHERE id = @id AND status IN (${placeholders})`)
      .run(params);
    return res.changes === 1;
  }

  private statusList(): string {
    return BUDGET_STATUSES.map((s) => `'${s}'`).join(',');
  }

  sumForAgent(agentId: string, currency: string, sinceIso: string): number {
    const row = this.db
      .prepare(
        `SELECT COALESCE(SUM(amount_minor),0) AS s FROM payments
         WHERE agent_id = ? AND currency = ? AND created_at >= ? AND status IN (${this.statusList()})`
      )
      .get(agentId, currency, sinceIso) as { s: number };
    return row.s;
  }

  sumForMandate(mandateId: string): number {
    const row = this.db
      .prepare(
        `SELECT COALESCE(SUM(amount_minor),0) AS s FROM payments
         WHERE mandate_id = ? AND status IN (${this.statusList()})`
      )
      .get(mandateId) as { s: number };
    return row.s;
  }

  /** Attempts (any status except blocked-for-validation) in a window — velocity counts attempts, not successes. */
  countAttempts(agentId: string, sinceIso: string): number {
    const row = this.db
      .prepare(`SELECT COUNT(*) AS c FROM payments WHERE agent_id = ? AND created_at >= ?`)
      .get(agentId, sinceIso) as { c: number };
    return row.c;
  }

  sumToMerchant(agentId: string, skeleton: string, currency: string, sinceIso: string): { total: number; count: number } {
    const row = this.db
      .prepare(
        `SELECT COALESCE(SUM(amount_minor),0) AS s, COUNT(*) AS c FROM payments
         WHERE agent_id = ? AND merchant_skeleton = ? AND currency = ? AND created_at >= ?
           AND status IN (${this.statusList()})`
      )
      .get(agentId, skeleton, currency, sinceIso) as { s: number; c: number };
    return { total: row.s, count: row.c };
  }

  /** Merchants this agent has successfully paid before. */
  knownMerchants(agentId: string): { merchant_id: string; merchant_skeleton: string }[] {
    return this.db
      .prepare(
        `SELECT DISTINCT merchant_id, merchant_skeleton FROM payments WHERE agent_id = ? AND status = 'captured'`
      )
      .all(agentId) as { merchant_id: string; merchant_skeleton: string }[];
  }

  /** Payee emails previously paid at this merchant (null = merchant default account). */
  knownPayees(agentId: string, merchantId: string): (string | null)[] {
    return (
      this.db
        .prepare(`SELECT DISTINCT payee_email FROM payments WHERE agent_id = ? AND merchant_id = ? AND status = 'captured'`)
        .all(agentId, merchantId) as { payee_email: string | null }[]
    ).map((r) => r.payee_email);
  }

  countSameAmount(agentId: string, skeleton: string, amountMinor: number, currency: string, sinceIso: string): number {
    const row = this.db
      .prepare(
        `SELECT COUNT(*) AS c FROM payments WHERE agent_id = ? AND merchant_skeleton = ? AND amount_minor = ? AND currency = ?
           AND created_at >= ? AND status IN (${this.statusList()})`
      )
      .get(agentId, skeleton, amountMinor, currency, sinceIso) as { c: number };
    return row.c;
  }

  capturedAmounts(agentId: string, category: string, currency: string): number[] {
    return (
      this.db
        .prepare(
          `SELECT amount_minor FROM payments WHERE agent_id = ? AND category = ? AND currency = ? AND status = 'captured'`
        )
        .all(agentId, category, currency) as { amount_minor: number }[]
    ).map((r) => r.amount_minor);
  }

  freezeMandate(mandateId: string, reason: string): void {
    this.db
      .prepare(`INSERT OR IGNORE INTO frozen_mandates (mandate_id, reason, frozen_at) VALUES (?, ?, ?)`)
      .run(mandateId, reason, new Date().toISOString());
  }

  isFrozen(mandateId: string): string | undefined {
    const row = this.db
      .prepare(`SELECT reason FROM frozen_mandates WHERE mandate_id = ?`)
      .get(mandateId) as { reason: string } | undefined;
    return row?.reason;
  }

  listByStatus(statuses: PaymentStatus[]): PaymentRow[] {
    const ph = statuses.map(() => '?').join(',');
    return this.db
      .prepare(`SELECT * FROM payments WHERE status IN (${ph}) ORDER BY created_at`)
      .all(...statuses) as PaymentRow[];
  }

  all(): PaymentRow[] {
    return this.db.prepare(`SELECT * FROM payments ORDER BY created_at`).all() as PaymentRow[];
  }

  close(): void {
    this.db.close();
  }
}
