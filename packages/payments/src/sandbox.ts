import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import {
  saveYamlFile,
  ensureAgentStructure,
  discoveryToProjectConfig,
  discoverProject,
  createBaselineProjectPolicy,
  createPassportFromTemplate,
  SHELL_TEMPLATES,
  projectConfigPath,
  projectPolicyPath,
  agentPassportPath,
  type AgentPassport,
} from '@agent-passport/core';
import { SpendFirewall } from './firewall.js';
import { MockPayPalProvider } from './providers/mock-paypal.js';
import { buildMandate, signMandate, type IssueMandateInput } from './mandate.js';
import { defaultSpendPolicy, spendPolicyPath, type SpendPolicy } from './spend-policy.js';
import type { IntentVerifier } from './intent.js';
import type { Finding } from './checks.js';

export const SHOPPER_PASSPORT = (projectId: string): AgentPassport => ({
  apiVersion: 'agentpassport.dev/v1',
  kind: 'AgentPassport',
  metadata: { id: 'shopper', project: projectId },
  identity: { owner: 'demo', role: 'custom', name: 'Shopper', description: 'Buys things for a task, within a signed mandate' },
  capabilities: ['payment.authorize', 'payment.capture'],
  policyRef: '.agent/policy.yaml',
});

export interface Sandbox {
  cwd: string;
  firewall: SpendFirewall;
  provider: MockPayPalProvider;
  key: Buffer;
  approverToken: string;
  issue: (input: Omit<IssueMandateInput, 'issuedBy'> & { issuedBy?: string }) => string;
  close: () => void;
}

/**
 * Self-contained project for tests, the demo and the red-team harness:
 * a `shopper` agent allowed to request payments, a `researcher` with no payment
 * capability, project policy that denies payouts, a spend policy, a mock PayPal,
 * and isolated keys (never touches ~/.agent-passport).
 */
export function createSandbox(
  dir: string,
  opts: { policy?: SpendPolicy; intent?: IntentVerifier; now?: () => Date; ablate?: Finding['layer'][] } = {}
): Sandbox {
  mkdirSync(join(dir, 'src'), { recursive: true });
  process.env.AGENT_PASSPORT_HOME = join(dir, '.home');
  const approverToken = randomBytes(24).toString('hex');
  process.env.AGENT_PASSPORT_APPROVER_TOKEN = approverToken;

  ensureAgentStructure(dir);
  saveYamlFile(projectConfigPath(dir), discoveryToProjectConfig(discoverProject(dir)));
  const policy = createBaselineProjectPolicy('payments-sandbox');
  policy.metadata.activated = true;
  policy.rules.push(
    { id: 'project:allow-payments', effect: 'allow', action: 'payment.capture', resource: 'merchant:*', priority: 100, source: 'project' },
    { id: 'project:deny-payouts', effect: 'deny', action: 'payout.*', resource: '*', priority: 1000, source: 'project', reason: 'Agents never send payouts' }
  );
  saveYamlFile(projectPolicyPath(dir), policy);
  saveYamlFile(agentPassportPath('shopper', dir), SHOPPER_PASSPORT('payments-sandbox'));
  saveYamlFile(
    agentPassportPath('researcher', dir),
    createPassportFromTemplate(SHELL_TEMPLATES.researcher, { owner: 'demo', projectId: 'payments-sandbox' })
  );
  const spend = opts.policy ?? defaultSpendPolicy('sandbox');
  saveYamlFile(spendPolicyPath(dir), spend);

  const key = randomBytes(32);
  const provider = new MockPayPalProvider();
  const firewall = new SpendFirewall({ cwd: dir, provider, policy: spend, intent: opts.intent, mandateKey: key, now: opts.now, ablate: opts.ablate });
  return {
    cwd: dir,
    firewall,
    provider,
    key,
    approverToken,
    issue: (input) => signMandate(buildMandate({ issuedBy: 'owner@human', ...input }), key),
    close: () => firewall.close(),
  };
}
