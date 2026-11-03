import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import yaml from 'js-yaml';
import { z } from 'zod';

/**
 * Organization/project spend policy: limits that apply to every mandate.
 * A mandate can be narrower than this policy, never wider.
 * File: .agent/spend-policy.yaml
 */
const AmountMap = z.record(z.string().regex(/^[A-Z]{3}$/), z.string());

const AgentLimitsSchema = z
  .object({
    per_tx: AmountMap.optional(),
    daily: AmountMap.optional(),
    approval_over: AmountMap.optional(),
  })
  .strict();

export const SpendPolicySchema = z
  .object({
    apiVersion: z.literal('agentpassport.dev/v1'),
    kind: z.literal('SpendPolicy'),
    metadata: z.object({ id: z.string(), version: z.union([z.string(), z.number()]).default('1') }),
    allowed_currencies: z.array(z.string().regex(/^[A-Z]{3}$/)).min(1),
    /** Categories no agent may ever pay for, whatever a mandate says. */
    blocked_categories: z.array(z.string()).default([]),
    defaults: AgentLimitsSchema.default({}),
    agents: z.record(AgentLimitsSchema).default({}),
    new_merchant: z.enum(['allow', 'approval', 'deny']).default('approval'),
    /**
     * Merchant directory: the source of truth for category and payee, so the agent's
     * self-declared category is checked rather than trusted. In production this is fed
     * from the provider's merchant category code (MCC) or an internal vendor registry.
     */
    merchants: z
      .record(z.object({ category: z.string(), payee_email: z.string().optional() }).strict())
      .default({}),
    velocity: z
      .object({ max_tx: z.number().int().positive(), window_minutes: z.number().positive() })
      .default({ max_tx: 5, window_minutes: 10 }),
    split_detection: z
      .object({ window_minutes: z.number().positive() })
      .default({ window_minutes: 60 }),
    anomaly: z
      .object({ multiple_of_median: z.number().positive(), min_history: z.number().int().positive() })
      .default({ multiple_of_median: 3, min_history: 3 }),
    /** Hold (authorization) lifetime while waiting for a human. Unanswered = voided. */
    approval_ttl_minutes: z.number().positive().default(15),
    provider_timeout_ms: z.number().int().positive().default(8000),
  })
  .strict();

export type SpendPolicy = z.infer<typeof SpendPolicySchema>;

export const DEFAULT_BLOCKED_CATEGORIES = [
  'gift_card',
  'crypto',
  'money_transfer',
  'gambling',
  'prepaid_card',
  'securities',
];

export function defaultSpendPolicy(id = 'default'): SpendPolicy {
  return SpendPolicySchema.parse({
    apiVersion: 'agentpassport.dev/v1',
    kind: 'SpendPolicy',
    metadata: { id },
    allowed_currencies: ['USD', 'INR', 'EUR', 'GBP'],
    blocked_categories: DEFAULT_BLOCKED_CATEGORIES,
    defaults: {
      per_tx: { USD: '500.00', INR: '40000.00', EUR: '500.00', GBP: '400.00' },
      daily: { USD: '1000.00', INR: '80000.00', EUR: '1000.00', GBP: '800.00' },
      approval_over: { USD: '100.00', INR: '8000.00', EUR: '100.00', GBP: '80.00' },
    },
  });
}

export function spendPolicyPath(cwd: string): string {
  return join(cwd, '.agent', 'spend-policy.yaml');
}

export function loadSpendPolicy(cwd: string): SpendPolicy {
  const path = spendPolicyPath(cwd);
  if (!existsSync(path)) return defaultSpendPolicy();
  return SpendPolicySchema.parse(yaml.load(readFileSync(path, 'utf8')));
}

export function limitFor(
  policy: SpendPolicy,
  agentId: string,
  key: 'per_tx' | 'daily' | 'approval_over',
  currency: string
): string | undefined {
  return policy.agents[agentId]?.[key]?.[currency] ?? policy.defaults[key]?.[currency];
}
