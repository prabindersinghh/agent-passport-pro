import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';
import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import { canonicalJson } from '@agent-passport/core';
import { assertCurrency, parseMajor } from './money.js';

/**
 * A Mandate is the human's authority for ONE task, issued before the agent starts.
 * It is the only thing that can grant spending power, and it is signed — the agent
 * carries it but cannot widen it. Everything an injected prompt might ask for
 * ("also buy a gift card", "raise the limit") is outside the signed envelope.
 */
export const MandateSchema = z
  .object({
    v: z.literal(1),
    mandate_id: z.string().min(1),
    agent_id: z.string().min(1),
    task: z.string().min(1).max(2000),
    issued_by: z.string().min(1),
    issued_at: z.string(),
    expires_at: z.string(),
    currency: z.string().length(3),
    max_total_minor: z.number().int().positive(),
    max_per_tx_minor: z.number().int().positive().optional(),
    allowed_categories: z.array(z.string().min(1)).min(1),
    allowed_merchants: z.array(z.string().min(1)).optional(),
    approval_over_minor: z.number().int().nonnegative().optional(),
  })
  .strict();

export type Mandate = z.infer<typeof MandateSchema>;

export class MandateError extends Error {
  constructor(
    message: string,
    readonly code: 'MALFORMED' | 'BAD_SIGNATURE' | 'EXPIRED' | 'NOT_YET_VALID' | 'WRONG_AGENT' | 'REVOKED'
  ) {
    super(message);
    this.name = 'MandateError';
  }
}

function b64url(buf: Buffer | string): string {
  return Buffer.from(buf).toString('base64url');
}

/** Mandate signing key lives outside the project tree, like the approver token. */
export function mandateKeyPath(): string {
  const home = process.env.AGENT_PASSPORT_HOME ?? join(homedir(), '.agent-passport');
  return join(home, 'mandate.key');
}

export function loadOrCreateMandateKey(): Buffer {
  const env = process.env.AGENT_PASSPORT_MANDATE_KEY;
  if (env && env.length >= 32) return Buffer.from(env, 'utf8');
  const path = mandateKeyPath();
  if (existsSync(path)) return Buffer.from(readFileSync(path, 'utf8').trim(), 'hex');
  const key = randomBytes(32);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, key.toString('hex') + '\n', { mode: 0o600 });
  try {
    chmodSync(path, 0o600);
  } catch {
    /* non-POSIX */
  }
  return key;
}

export interface IssueMandateInput {
  agentId: string;
  task: string;
  issuedBy: string;
  currency: string;
  maxTotal: string;
  maxPerTx?: string;
  approvalOver?: string;
  allowedCategories: string[];
  allowedMerchants?: string[];
  ttlMinutes?: number;
  now?: Date;
}

export function buildMandate(input: IssueMandateInput): Mandate {
  const currency = assertCurrency(input.currency);
  const now = input.now ?? new Date();
  const ttl = input.ttlMinutes ?? 60;
  return MandateSchema.parse({
    v: 1,
    mandate_id: `mdt_${uuidv4()}`,
    agent_id: input.agentId,
    task: input.task,
    issued_by: input.issuedBy,
    issued_at: now.toISOString(),
    expires_at: new Date(now.getTime() + ttl * 60_000).toISOString(),
    currency,
    max_total_minor: parseMajor(input.maxTotal, currency),
    max_per_tx_minor: input.maxPerTx ? parseMajor(input.maxPerTx, currency) : undefined,
    approval_over_minor: input.approvalOver ? parseMajor(input.approvalOver, currency) : undefined,
    allowed_categories: input.allowedCategories,
    allowed_merchants: input.allowedMerchants,
  });
}

export function signMandate(mandate: Mandate, key: Buffer): string {
  const payload = b64url(canonicalJson(MandateSchema.parse(mandate)));
  const sig = b64url(createHmac('sha256', key).update(payload).digest());
  return `apm1.${payload}.${sig}`;
}

export function verifyMandate(
  token: unknown,
  key: Buffer,
  opts: { agentId: string; now?: Date; isRevoked?: (id: string) => boolean }
): Mandate {
  if (typeof token !== 'string') throw new MandateError('Mandate token missing', 'MALFORMED');
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== 'apm1') {
    throw new MandateError('Mandate token malformed', 'MALFORMED');
  }
  const [, payload, sig] = parts;
  const expected = createHmac('sha256', key).update(payload).digest();
  let presented: Buffer;
  try {
    presented = Buffer.from(sig, 'base64url');
  } catch {
    throw new MandateError('Mandate signature malformed', 'MALFORMED');
  }
  if (presented.length !== expected.length || !timingSafeEqual(presented, expected)) {
    throw new MandateError('Mandate signature invalid — token was altered or forged', 'BAD_SIGNATURE');
  }
  let mandate: Mandate;
  try {
    mandate = MandateSchema.parse(JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')));
  } catch {
    throw new MandateError('Mandate payload malformed', 'MALFORMED');
  }
  const now = opts.now ?? new Date();
  if (new Date(mandate.expires_at) <= now) throw new MandateError('Mandate expired', 'EXPIRED');
  if (new Date(mandate.issued_at).getTime() > now.getTime() + 60_000) {
    throw new MandateError('Mandate issued in the future', 'NOT_YET_VALID');
  }
  if (mandate.agent_id !== opts.agentId) {
    throw new MandateError(
      `Mandate belongs to '${mandate.agent_id}', presented by '${opts.agentId}'`,
      'WRONG_AGENT'
    );
  }
  if (opts.isRevoked?.(mandate.mandate_id)) throw new MandateError('Mandate revoked', 'REVOKED');
  return mandate;
}
