import type { Mandate } from './mandate.js';
import type { SpendLedger } from './ledger.js';
import { limitFor, type SpendPolicy } from './spend-policy.js';
import { parseMajor, formatMoney } from './money.js';
import { hasMixedScripts, isLookalike, merchantSkeleton, normalizeMerchantId, lookupDirectory } from './merchant.js';

export type Layer = 'validation' | 'mandate' | 'passport' | 'spend_policy' | 'risk' | 'intent' | 'provider';
export type Severity = 'block' | 'escalate' | 'info';

export interface Finding {
  layer: Layer;
  code: string;
  severity: Severity;
  message: string;
}

export interface CheckInput {
  agentId: string;
  mandate: Mandate;
  merchantId: string;
  merchantName: string;
  payeeEmail: string | null;
  category: string;
  amountMinor: number;
  currency: string;
  now: Date;
}

/** Deterministic spend-policy checks. Pure function of (policy, mandate, ledger state). */
export function spendPolicyChecks(policy: SpendPolicy, ledger: SpendLedger, i: CheckInput): Finding[] {
  const f: Finding[] = [];
  const fmt = (minor: number) => formatMoney({ amount_minor: minor, currency: i.currency });
  const add = (severity: Severity, code: string, message: string, layer: Layer = 'spend_policy') =>
    f.push({ layer, code, severity, message });

  if (!policy.allowed_currencies.includes(i.currency)) {
    add('block', 'CURRENCY_NOT_ALLOWED', `Currency ${i.currency} not allowed by spend policy`);
  }
  if (i.currency !== i.mandate.currency) {
    add('block', 'CURRENCY_MISMATCH', `Mandate is in ${i.mandate.currency}, payment in ${i.currency}`, 'mandate');
  }
  if (policy.blocked_categories.includes(i.category)) {
    add('block', 'CATEGORY_BLOCKED', `Category '${i.category}' is never payable by agents`);
  }
  if (!i.mandate.allowed_categories.includes(i.category)) {
    add(
      'block',
      'CATEGORY_OUTSIDE_MANDATE',
      `Task allows [${i.mandate.allowed_categories.join(', ')}], not '${i.category}'`,
      'mandate'
    );
  }
  if (i.mandate.allowed_merchants?.length) {
    const ok = i.mandate.allowed_merchants.some((m) => normalizeMerchantId(m) === i.merchantId);
    if (!ok) add('block', 'MERCHANT_OUTSIDE_MANDATE', `Merchant '${i.merchantId}' not in mandate allowlist`, 'mandate');
  }

  // Limits — only comparable when currency matches mandate/policy
  const perTxPolicy = limitFor(policy, i.agentId, 'per_tx', i.currency);
  const perTx = Math.min(
    perTxPolicy ? parseMajor(perTxPolicy, i.currency) : Number.MAX_SAFE_INTEGER,
    i.mandate.max_per_tx_minor ?? Number.MAX_SAFE_INTEGER
  );
  if (i.amountMinor > perTx) add('block', 'PER_TX_LIMIT', `${fmt(i.amountMinor)} exceeds per-transaction limit ${fmt(perTx)}`);

  const dailyStr = limitFor(policy, i.agentId, 'daily', i.currency);
  if (dailyStr) {
    const daily = parseMajor(dailyStr, i.currency);
    const since = new Date(i.now.getTime() - 24 * 3600_000).toISOString();
    const spent = ledger.sumForAgent(i.agentId, i.currency, since);
    if (spent + i.amountMinor > daily) {
      add('block', 'DAILY_LIMIT', `Rolling 24h spend would be ${fmt(spent + i.amountMinor)} > ${fmt(daily)}`);
    }
  }

  const mandateSpent = ledger.sumForMandate(i.mandate.mandate_id);
  if (mandateSpent + i.amountMinor > i.mandate.max_total_minor) {
    add(
      'block',
      'MANDATE_BUDGET',
      `Task budget ${fmt(i.mandate.max_total_minor)} exceeded (already committed ${fmt(mandateSpent)})`,
      'mandate'
    );
  }

  const threshold = approvalThreshold(policy, i);
  if (i.amountMinor > threshold) {
    add('escalate', 'OVER_APPROVAL_THRESHOLD', `${fmt(i.amountMinor)} is above the auto-approve limit ${fmt(threshold)}`);
  }
  return f;
}

export function approvalThreshold(policy: SpendPolicy, i: CheckInput): number {
  const p = limitFor(policy, i.agentId, 'approval_over', i.currency);
  return Math.min(
    p ? parseMajor(p, i.currency) : Number.MAX_SAFE_INTEGER,
    i.mandate.approval_over_minor ?? Number.MAX_SAFE_INTEGER
  );
}

/** Behavioural risk checks over the ledger. */
export function riskChecks(policy: SpendPolicy, ledger: SpendLedger, i: CheckInput): Finding[] {
  const f: Finding[] = [];
  const add = (severity: Severity, code: string, message: string) => f.push({ layer: 'risk', code, severity, message });
  const fmt = (minor: number) => formatMoney({ amount_minor: minor, currency: i.currency });
  const skeleton = merchantSkeleton(i.merchantId);

  // Directory: declared category / payee must match the registry entry.
  const dir = lookupDirectory(policy.merchants, i.merchantId)?.entry;
  if (dir) {
    if (dir.category !== i.category) {
      add('block', 'CATEGORY_MISDECLARED', `Agent declared '${i.category}' but '${i.merchantId}' is registered as '${dir.category}'`);
    }
    if (dir.payee_email && i.payeeEmail && dir.payee_email.toLowerCase() !== i.payeeEmail) {
      add('block', 'PAYEE_CHANGED', `Payee '${i.payeeEmail}' is not the registered account for '${i.merchantId}'`);
    }
    if (policy.blocked_categories.includes(dir.category)) {
      add('block', 'CATEGORY_BLOCKED', `'${i.merchantId}' is registered as blocked category '${dir.category}'`);
    }
  }

  // Velocity — counts attempts (including blocked ones): a looping agent trips it fast.
  const vSince = new Date(i.now.getTime() - policy.velocity.window_minutes * 60_000).toISOString();
  const attempts = ledger.countAttempts(i.agentId, vSince);
  if (attempts >= policy.velocity.max_tx) {
    add('block', 'VELOCITY', `${attempts} payment attempts in ${policy.velocity.window_minutes} min (max ${policy.velocity.max_tx})`);
  }

  // Look-alike merchants: renders like a trusted merchant, isn't one.
  if (hasMixedScripts(i.merchantName) || hasMixedScripts(i.merchantId)) {
    add('block', 'MIXED_SCRIPT_MERCHANT', `Merchant name mixes Latin with Cyrillic/Greek characters`);
  }
  const trusted = [
    ...ledger.knownMerchants(i.agentId).map((m) => m.merchant_id),
    ...(i.mandate.allowed_merchants ?? []),
  ];
  const twin = trusted.find((t) => isLookalike(i.merchantId, t));
  if (twin) add('block', 'LOOKALIKE_MERCHANT', `'${i.merchantId}' imitates trusted merchant '${twin}'`);

  // New merchant (a directory entry does not make a merchant "known" for this agent's task)
  const known = trusted.some((t) => normalizeMerchantId(t) === i.merchantId);
  if (!known && !twin) {
    if (policy.new_merchant === 'deny') add('block', 'NEW_MERCHANT', `First payment to '${i.merchantId}'`);
    if (policy.new_merchant === 'approval') add('escalate', 'NEW_MERCHANT', `First payment to '${i.merchantId}'`);
  }

  // Payee: the account that actually receives the money. The agent must never be the
  // one deciding it. Registered payee > previously-paid payee > human decision.
  const payees = ledger.knownPayees(i.agentId, i.merchantId);
  if (payees.length > 0 && !payees.includes(i.payeeEmail)) {
    add('block', 'PAYEE_CHANGED', `Payee for '${i.merchantId}' differs from every previous payment (${i.payeeEmail ?? 'default'})`);
  } else if (i.payeeEmail && payees.length === 0 && !(dir?.payee_email && dir.payee_email.toLowerCase() === i.payeeEmail)) {
    add('escalate', 'UNVERIFIED_PAYEE', `Agent-supplied payee '${i.payeeEmail}' is not registered for '${i.merchantId}'`);
  }

  // Duplicate: same merchant + same amount inside the window, different idempotency key — a looping agent.
  const dSince = new Date(i.now.getTime() - policy.split_detection.window_minutes * 60_000).toISOString();
  if (ledger.countSameAmount(i.agentId, skeleton, i.amountMinor, i.currency, dSince) > 0) {
    add('escalate', 'POSSIBLE_DUPLICATE', `Same amount to '${i.merchantId}' already committed in the last ${policy.split_detection.window_minutes} min`);
  }

  // Split purchase: several payments each under the auto-approve threshold, together above it.
  const threshold = approvalThreshold(policy, i);
  if (i.amountMinor <= threshold) {
    const sSince = new Date(i.now.getTime() - policy.split_detection.window_minutes * 60_000).toISOString();
    const prior = ledger.sumToMerchant(i.agentId, skeleton, i.currency, sSince);
    if (prior.count > 0 && prior.total + i.amountMinor > threshold) {
      add(
        'escalate',
        'SPLIT_PURCHASE',
        `${prior.count + 1} payments to '${i.merchantId}' in ${policy.split_detection.window_minutes} min total ${fmt(prior.total + i.amountMinor)} > ${fmt(threshold)}`
      );
    }
  }

  // Amount anomaly vs this agent's history in the category.
  const hist = ledger.capturedAmounts(i.agentId, i.category, i.currency);
  if (hist.length >= policy.anomaly.min_history) {
    const sorted = [...hist].sort((a, b) => a - b);
    const median = sorted[Math.floor(sorted.length / 2)];
    if (i.amountMinor > median * policy.anomaly.multiple_of_median) {
      add('escalate', 'AMOUNT_ANOMALY', `${fmt(i.amountMinor)} is >${policy.anomaly.multiple_of_median}× this agent's median ${fmt(median)} for '${i.category}'`);
    }
  }
  return f;
}
