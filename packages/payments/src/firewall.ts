import { v4 as uuidv4 } from 'uuid';
import { z } from 'zod';
import {
  PassportGateway,
  createGateway,
  actionBindingHash,
  canonicalJson,
  verifyApproverToken,
  ApprovalError,
} from '@agent-passport/core';
import { SpendLedger, type PaymentRow, type PaymentStatus } from './ledger.js';
import { loadSpendPolicy, type SpendPolicy } from './spend-policy.js';
import { loadOrCreateMandateKey, verifyMandate, MandateError, type Mandate } from './mandate.js';
import { assertCurrency, parseMajor, formatMoney, MoneyError } from './money.js';
import { merchantSkeleton, normalizeMerchantId } from './merchant.js';
import { spendPolicyChecks, riskChecks, type Finding, type CheckInput } from './checks.js';
import { HeuristicIntentVerifier, type IntentVerifier } from './intent.js';
import { withTimeout, ProviderTimeoutError, type PaymentProvider } from './providers/provider.js';

/**
 * What an agent submits. Strict: unknown fields are rejected, amount is a decimal
 * string in major units, currency is ISO 4217. The agent never sends a limit,
 * an approval flag or a "trusted" marker — there is nowhere to put one.
 */
export const PaymentRequestSchema = z
  .object({
    agent_id: z.string().min(1).max(100),
    mandate: z.string().min(1).max(8192),
    merchant: z
      .object({
        id: z.string().min(1).max(200),
        name: z.string().min(1).max(200),
        category: z.string().min(1).max(64).regex(/^[a-z0-9_.]+$/),
        email: z.string().email().max(254).optional(),
      })
      .strict(),
    amount: z.string().min(1).max(32),
    currency: z.string().length(3),
    description: z.string().max(1000).default(''),
    idempotency_key: z.string().min(8).max(128).optional(),
  })
  .strict();

export type PaymentRequest = z.input<typeof PaymentRequestSchema>;

export type PaymentOutcome =
  | 'captured'
  | 'blocked'
  | 'pending_approval'
  | 'rejected'
  | 'expired'
  | 'failed'
  | 'needs_reconciliation';

export interface PaymentResult {
  outcome: PaymentOutcome;
  payment_id?: string;
  findings: Finding[];
  /** One line a human (or the agent) can read. Never contains secrets. */
  summary: string;
  approval_request_id?: string;
  capture_id?: string;
  duplicate?: boolean;
}

export interface FirewallOptions {
  cwd: string;
  provider: PaymentProvider;
  gateway?: PassportGateway;
  policy?: SpendPolicy;
  intent?: IntentVerifier;
  mandateKey?: Buffer;
  now?: () => Date;
  /**
   * ABLATION ONLY. Drops findings from these layers so the red-team harness can
   * measure what each layer contributes. Never set this in a deployment.
   */
  ablate?: Finding['layer'][];
}

const ACTION = 'payment.capture';

/**
 * SpendFirewall — the only component holding provider credentials.
 * Layers, in order: validation → mandate → passport policy → intent (escalate-only)
 * → [atomic] spend policy + risk + budget reservation → provider hold → capture or human.
 */
export class SpendFirewall {
  readonly ledger: SpendLedger;
  readonly gateway: PassportGateway;
  readonly policy: SpendPolicy;
  readonly provider: PaymentProvider;
  private readonly intent: IntentVerifier;
  private readonly key: Buffer;
  private readonly now: () => Date;
  private readonly cwd: string;
  private readonly ablate: Set<Finding['layer']>;

  constructor(opts: FirewallOptions) {
    this.cwd = opts.cwd;
    this.ablate = new Set(opts.ablate ?? []);
    this.ledger = new SpendLedger(opts.cwd);
    this.gateway = opts.gateway ?? createGateway({ cwd: opts.cwd });
    this.policy = opts.policy ?? loadSpendPolicy(opts.cwd);
    this.provider = opts.provider;
    this.intent = opts.intent ?? new HeuristicIntentVerifier();
    this.key = opts.mandateKey ?? loadOrCreateMandateKey();
    this.now = opts.now ?? (() => new Date());
  }

  async pay(raw: unknown): Promise<PaymentResult> {
    const now = this.now();

    // ── Layer 1: validation ────────────────────────────────────────────────
    const parsed = PaymentRequestSchema.safeParse(raw);
    if (!parsed.success) {
      const issue = parsed.error.issues[0];
      return this.reject('validation', 'MALFORMED_REQUEST', `${issue.path.join('.') || 'request'}: ${issue.message}`, raw);
    }
    const req = parsed.data;
    let amountMinor: number;
    let currency: string;
    try {
      currency = assertCurrency(req.currency);
      amountMinor = parseMajor(req.amount, currency);
    } catch (e) {
      return this.reject('validation', 'MALFORMED_AMOUNT', (e as MoneyError).message, raw);
    }
    const merchantId = normalizeMerchantId(req.merchant.id);
    const boundParams = {
      merchant_id: merchantId,
      merchant_name: req.merchant.name,
      category: req.merchant.category,
      amount_minor: amountMinor,
      currency,
      payee_email: req.merchant.email?.toLowerCase() ?? null,
    };
    const resource = `merchant:${merchantId}`;
    const paramsHash = actionBindingHash(ACTION, resource, boundParams);

    // ── Layer 2: mandate ──────────────────────────────────────────────────
    let mandate: Mandate;
    try {
      mandate = verifyMandate(req.mandate, this.key, {
        agentId: req.agent_id,
        now,
        isRevoked: (id) => this.ledger.isFrozen(id) !== undefined,
      });
    } catch (e) {
      const code = e instanceof MandateError ? `MANDATE_${e.code}` : 'MANDATE_INVALID';
      const unverified = this.ablate.has('mandate') ? decodeUnverified(req.mandate) : undefined;
      if (!unverified) return this.reject('mandate', code, (e as Error).message, raw);
      mandate = unverified;
    }

    // ── Idempotency: an agent retrying after a timeout must never double-pay ──
    if (req.idempotency_key) {
      const prior = this.ledger.byIdempotencyKey(req.agent_id, req.idempotency_key);
      if (prior) return this.replayResult(prior, paramsHash);
    }

    // ── Layer 3: passport + project policy (identity, capability) ───────────
    const findings: Finding[] = [];
    let passportDecision;
    try {
      passportDecision = this.gateway.authorize({
        agentId: req.agent_id,
        shellId: req.agent_id,
        action: ACTION,
        resource,
        parameters: boundParams,
      });
    } catch (e) {
      return this.reject('passport', 'PASSPORT_ERROR', `Passport evaluation failed (fail closed): ${(e as Error).message}`, raw);
    }
    if (passportDecision.effect === 'deny' || passportDecision.effect === 'expired') {
      findings.push({ layer: 'passport', code: 'PASSPORT_DENY', severity: 'block', message: passportDecision.reason });
    } else if (passportDecision.effect === 'approval_required') {
      findings.push({ layer: 'passport', code: 'PASSPORT_APPROVAL', severity: 'escalate', message: passportDecision.reason });
    }

    // ── Layer 4: intent (async, escalate-only) ──────────────────────────────
    const verdict = await this.intent
      .verify(mandate, {
        merchant_id: merchantId,
        merchant_name: req.merchant.name,
        category: req.merchant.category,
        description: req.description,
        amount_display: formatMoney({ amount_minor: amountMinor, currency }),
      })
      .catch((e) => ({ verdict: 'unknown' as const, reason: String(e), verifier: 'error' }));
    if (verdict.verdict !== 'consistent') {
      // Clamp: whatever the verifier returned, the strongest it can do is escalate.
      findings.push({ layer: 'intent', code: `INTENT_${verdict.verdict.toUpperCase()}`, severity: 'escalate', message: `[${verdict.verifier}] ${verdict.reason}` });
    }

    // ── Layers 5–6: spend policy + risk + reservation, atomically ───────────
    const check: CheckInput = {
      agentId: req.agent_id,
      mandate,
      merchantId,
      merchantName: req.merchant.name,
      payeeEmail: req.merchant.email?.toLowerCase() ?? null,
      category: req.merchant.category,
      amountMinor,
      currency,
      now,
    };
    const paymentId = `pay_${uuidv4()}`;
    let row: PaymentRow;
    try {
      row = this.ledger.atomic(() => {
        const all = [...findings, ...spendPolicyChecks(this.policy, this.ledger, check), ...riskChecks(this.policy, this.ledger, check)]
          .filter((f) => !this.ablate.has(f.layer));
        const blocked = all.some((x) => x.severity === 'block');
        const escalate = all.some((x) => x.severity === 'escalate');
        const r: PaymentRow = {
          id: paymentId,
          agent_id: req.agent_id,
          mandate_id: mandate.mandate_id,
          merchant_id: merchantId,
          merchant_name: req.merchant.name,
          merchant_skeleton: merchantSkeleton(merchantId),
          payee_email: req.merchant.email?.toLowerCase() ?? null,
          category: req.merchant.category,
          amount_minor: amountMinor,
          currency,
          description: req.description,
          status: blocked ? 'blocked' : escalate ? 'pending_approval' : 'reserved',
          idempotency_key: req.idempotency_key ?? null,
          params_hash: paramsHash,
          approval_request_id: null,
          order_id: null,
          authorization_id: null,
          capture_id: null,
          findings: JSON.stringify(all),
          created_at: now.toISOString(),
          updated_at: now.toISOString(),
          hold_expires_at: escalate && !blocked
            ? new Date(now.getTime() + this.policy.approval_ttl_minutes * 60_000).toISOString()
            : null,
        };
        this.ledger.insert(r);
        return r;
      });
    } catch (e) {
      if (String(e).includes('UNIQUE') && req.idempotency_key) {
        const prior = this.ledger.byIdempotencyKey(req.agent_id, req.idempotency_key);
        if (prior) return this.replayResult(prior, paramsHash);
      }
      return this.reject('spend_policy', 'LEDGER_ERROR', 'Ledger unavailable (fail closed)', raw);
    }
    const all = JSON.parse(row.findings) as Finding[];

    if (row.status === 'blocked') {
      this.audit('payment.blocked', row, all);
      return { outcome: 'blocked', payment_id: row.id, findings: all, summary: summarize('BLOCKED', row, all) };
    }

    // ── Hold funds (reversible) ─────────────────────────────────────────────
    let hold;
    try {
      hold = await withTimeout(
        'authorize',
        this.policy.provider_timeout_ms,
        this.provider.authorize({
          amount: { amount_minor: amountMinor, currency },
          payee: { merchant_id: merchantId, email: req.merchant.email },
          description: req.description,
          requestId: `${row.id}-auth`,
        })
      );
    } catch (e) {
      const f: Finding = { layer: 'provider', code: e instanceof ProviderTimeoutError ? 'HOLD_TIMEOUT' : 'HOLD_FAILED', severity: 'block', message: (e as Error).message };
      this.ledger.transition(row.id, ['reserved', 'pending_approval'], 'failed', { findings: JSON.stringify([...all, f]) });
      this.audit('payment.blocked', row, [...all, f]);
      return { outcome: 'failed', payment_id: row.id, findings: [...all, f], summary: `FAILED ${describe(row)} — could not place hold; nothing captured` };
    }
    this.audit('payment.held', { ...row, authorization_id: hold.authorizationId }, all);

    if (row.status === 'pending_approval') {
      const approval = this.gateway.approvals.createRequest({
        agentId: req.agent_id,
        shellId: req.agent_id,
        action: ACTION,
        resource,
        reason: all.filter((x) => x.severity === 'escalate').map((x) => x.message).join('; '),
        scope: 'once',
        paramsHash,
        paramsPreview: canonicalJson(boundParams),
        pendingTtlMs: this.policy.approval_ttl_minutes * 60_000,
        traceId: row.id,
      });
      this.ledger.transition(row.id, ['pending_approval'], 'pending_approval', {
        order_id: hold.orderId,
        authorization_id: hold.authorizationId,
        approval_request_id: approval.request_id,
      });
      return {
        outcome: 'pending_approval',
        payment_id: row.id,
        approval_request_id: approval.request_id,
        findings: all,
        summary: summarize('HELD FOR HUMAN', row, all),
      };
    }

    this.ledger.transition(row.id, ['reserved'], 'held', { order_id: hold.orderId, authorization_id: hold.authorizationId });
    return this.captureHeld(row.id, all);
  }

  /** Human approves a held payment. Requires the approver credential the agent never has. */
  async approve(paymentId: string, approver: string, approverToken: string | undefined): Promise<PaymentResult> {
    if (!verifyApproverToken(approverToken)) {
      return { outcome: 'blocked', payment_id: paymentId, findings: [], summary: 'Approver credential invalid' };
    }
    this.sweepExpired();
    const row = this.ledger.get(paymentId);
    if (!row || row.status !== 'pending_approval' || !row.approval_request_id) {
      return { outcome: 'blocked', payment_id: paymentId, findings: [], summary: `Payment not awaiting approval (status: ${row?.status ?? 'none'})` };
    }
    const frozen = row.mandate_id ? this.ledger.isFrozen(row.mandate_id) : undefined;
    if (frozen) return { outcome: 'blocked', payment_id: paymentId, findings: [], summary: `Mandate frozen: ${frozen}` };

    let granted;
    try {
      granted = this.gateway.approvals.grant(row.approval_request_id, approver, { scope: 'once' });
    } catch (e) {
      if (e instanceof ApprovalError) return { outcome: 'blocked', payment_id: paymentId, findings: [], summary: e.message };
      throw e;
    }
    if (!granted || granted.params_hash !== row.params_hash) {
      return { outcome: 'blocked', payment_id: paymentId, findings: [], summary: 'Approval no longer valid or not bound to this payment' };
    }
    if (!this.gateway.approvals.claim(granted.request_id)) {
      return { outcome: 'blocked', payment_id: paymentId, findings: [], summary: 'Approval already used' };
    }
    if (!this.ledger.transition(row.id, ['pending_approval'], 'held')) {
      return { outcome: 'blocked', payment_id: paymentId, findings: [], summary: 'Payment changed state concurrently' };
    }
    this.gateway.audit.emit('approval.granted', {
      agent_id: row.agent_id,
      action: ACTION,
      resource: `merchant:${row.merchant_id}`,
      decision: 'granted',
      trace_id: row.id,
      metadata: { approval_request_id: granted.request_id, decided_by: approver },
    });
    return this.captureHeld(row.id, JSON.parse(row.findings) as Finding[]);
  }

  async rejectPayment(paymentId: string, approver: string, approverToken: string | undefined): Promise<PaymentResult> {
    if (!verifyApproverToken(approverToken)) {
      return { outcome: 'blocked', payment_id: paymentId, findings: [], summary: 'Approver credential invalid' };
    }
    const row = this.ledger.get(paymentId);
    if (!row || row.status !== 'pending_approval') {
      return { outcome: 'blocked', payment_id: paymentId, findings: [], summary: 'Payment not awaiting approval' };
    }
    if (row.approval_request_id) this.gateway.approvals.deny(row.approval_request_id, approver);
    await this.releaseHold(row, 'rejected');
    return { outcome: 'rejected', payment_id: paymentId, findings: JSON.parse(row.findings), summary: `REJECTED by ${approver}; hold voided, nothing captured` };
  }

  /** Void holds whose approval window elapsed. An unanswered request is a "no". */
  sweepExpired(): number {
    const now = this.now().toISOString();
    let n = 0;
    for (const row of this.ledger.listByStatus(['pending_approval'])) {
      if (row.hold_expires_at && row.hold_expires_at <= now) {
        if (this.ledger.transition(row.id, ['pending_approval'], 'expired')) {
          n++;
          if (row.authorization_id) void this.provider.void(row.authorization_id).catch(() => undefined);
          this.audit('payment.voided', row, [{ layer: 'provider', code: 'APPROVAL_TIMEOUT', severity: 'block', message: 'No human decision before hold expiry' }]);
        }
      }
    }
    return n;
  }

  pending(): PaymentRow[] {
    this.sweepExpired();
    return this.ledger.listByStatus(['pending_approval']);
  }

  private async captureHeld(paymentId: string, findings: Finding[]): Promise<PaymentResult> {
    const row = this.ledger.get(paymentId)!;
    if (row.status !== 'held' || !row.authorization_id) {
      return { outcome: 'blocked', payment_id: paymentId, findings, summary: 'Payment not in capturable state' };
    }
    try {
      const { captureId } = await withTimeout(
        'capture',
        this.policy.provider_timeout_ms,
        this.provider.capture(row.authorization_id, `${row.id}-capture`)
      );
      this.ledger.transition(row.id, ['held'], 'captured', { capture_id: captureId });
      this.audit('payment.captured', { ...row, capture_id: captureId }, findings);
      return { outcome: 'captured', payment_id: row.id, capture_id: captureId, findings, summary: `CAPTURED ${describe(row)}` };
    } catch (e) {
      if (e instanceof ProviderTimeoutError) {
        // The irreversible call may or may not have happened. Ask, never retry blindly.
        const st = await withTimeout('status', this.policy.provider_timeout_ms, this.provider.status(row.authorization_id)).catch(() => 'unknown' as const);
        if (st === 'captured') {
          this.ledger.transition(row.id, ['held'], 'captured');
          this.audit('payment.captured', row, findings);
          return { outcome: 'captured', payment_id: row.id, findings, summary: `CAPTURED ${describe(row)} (confirmed after timeout)` };
        }
        const f: Finding = { layer: 'provider', code: 'CAPTURE_UNCERTAIN', severity: 'block', message: 'Capture timed out; state unknown. Mandate frozen pending reconciliation.' };
        this.ledger.transition(row.id, ['held'], 'needs_reconciliation', { findings: JSON.stringify([...findings, f]) });
        if (row.mandate_id) this.ledger.freezeMandate(row.mandate_id, `capture uncertain on ${row.id}`);
        this.audit('payment.blocked', row, [...findings, f]);
        return { outcome: 'needs_reconciliation', payment_id: row.id, findings: [...findings, f], summary: `UNCERTAIN ${describe(row)} — mandate frozen until a human reconciles` };
      }
      const f: Finding = { layer: 'provider', code: 'CAPTURE_FAILED', severity: 'block', message: (e as Error).message };
      await this.releaseHold(row, 'failed');
      return { outcome: 'failed', payment_id: row.id, findings: [...findings, f], summary: `FAILED ${describe(row)} — hold voided` };
    }
  }

  private async releaseHold(row: PaymentRow, to: PaymentStatus): Promise<void> {
    this.ledger.transition(row.id, ['held', 'pending_approval', 'reserved'], to);
    if (row.authorization_id) await this.provider.void(row.authorization_id).catch(() => undefined);
    this.audit('payment.voided', row, []);
  }

  private replayResult(prior: PaymentRow, paramsHash: string): PaymentResult {
    const findings = JSON.parse(prior.findings) as Finding[];
    if (prior.params_hash !== paramsHash) {
      // Same idempotency key, different payment: the agent (or an attacker) is reusing a key to smuggle a new charge.
      return {
        outcome: 'blocked',
        payment_id: prior.id,
        duplicate: true,
        findings: [{ layer: 'validation', code: 'IDEMPOTENCY_KEY_REUSE', severity: 'block', message: 'Idempotency key reused with different payment details' }],
        summary: 'BLOCKED idempotency key reused with different details',
      };
    }
    const outcome = (['captured', 'blocked', 'pending_approval', 'rejected', 'expired', 'failed', 'needs_reconciliation'] as const).includes(prior.status as PaymentOutcome)
      ? (prior.status as PaymentOutcome)
      : 'pending_approval';
    return { outcome, payment_id: prior.id, duplicate: true, findings, summary: `DUPLICATE of ${prior.id} (${prior.status}); no new charge`, capture_id: prior.capture_id ?? undefined, approval_request_id: prior.approval_request_id ?? undefined };
  }

  private reject(layer: Finding['layer'], code: string, message: string, raw: unknown): PaymentResult {
    const f: Finding = { layer, code, severity: 'block', message };
    const agent = (raw as { agent_id?: unknown })?.agent_id;
    this.gateway.audit.emit('payment.blocked', {
      agent_id: typeof agent === 'string' ? agent.slice(0, 100) : undefined,
      action: ACTION,
      decision: 'deny',
      metadata: { findings: [f] },
    });
    return { outcome: 'blocked', findings: [f], summary: `BLOCKED — ${message}` };
  }

  private audit(type: 'payment.blocked' | 'payment.held' | 'payment.captured' | 'payment.voided', row: PaymentRow, findings: Finding[]): void {
    this.gateway.audit.emit(type, {
      agent_id: row.agent_id,
      shell_id: row.agent_id,
      action: ACTION,
      resource: `merchant:${row.merchant_id}`,
      decision: type === 'payment.blocked' ? 'deny' : type === 'payment.captured' ? 'allow' : undefined,
      trace_id: row.id,
      metadata: {
        payment_id: row.id,
        mandate_id: row.mandate_id,
        amount: formatMoney({ amount_minor: row.amount_minor, currency: row.currency }),
        category: row.category,
        authorization_id: row.authorization_id,
        capture_id: row.capture_id,
        findings,
      },
    });
  }

  close(): void {
    this.ledger.close();
    this.gateway.close();
  }
}

function decodeUnverified(token: string): Mandate | undefined {
  try {
    return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8')) as Mandate;
  } catch {
    return undefined;
  }
}

function describe(row: PaymentRow): string {
  return `${formatMoney({ amount_minor: row.amount_minor, currency: row.currency })} to ${row.merchant_id} (${row.category})`;
}

function summarize(label: string, row: PaymentRow, findings: Finding[]): string {
  const key = findings.filter((f) => f.severity !== 'info').map((f) => f.code);
  return `${label} ${describe(row)}${key.length ? ` — ${key.join(', ')}` : ''}`;
}
