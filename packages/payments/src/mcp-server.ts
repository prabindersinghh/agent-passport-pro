import { createInterface } from 'node:readline';
import { SpendFirewall } from './firewall.js';
import { MockPayPalProvider } from './providers/mock-paypal.js';
import { PayPalProvider } from './providers/paypal.js';
import type { PaymentProvider } from './providers/provider.js';
import { CompositeIntentVerifier, HeuristicIntentVerifier, LlmIntentVerifier, type IntentVerifier } from './intent.js';

/**
 * MCP server exposing the Spend Firewall to any MCP-capable agent (stdio, newline-delimited JSON-RPC).
 *
 * The agent gets ONE tool, `pay`. It never sees provider credentials, the mandate token,
 * or an approve tool. Identity and mandate are bound by whoever launches the process:
 *   AGENT_PASSPORT_CWD       project with .agent/ (passport, policy, spend-policy)
 *   AGENT_PASSPORT_AGENT     agent id this process speaks for
 *   AGENT_PASSPORT_MANDATE   signed mandate token for the current task
 */
interface Rpc {
  jsonrpc: '2.0';
  id?: string | number | null;
  method: string;
  params?: any;
}

const TOOLS = [
  {
    name: 'pay',
    description:
      'Request a payment for the current task. The payment is checked against the task mandate and spend policy, ' +
      'held with the provider, and either captured, held for human approval, or blocked. Returns the outcome and reasons.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['merchant_id', 'merchant_name', 'category', 'amount', 'currency'],
      properties: {
        merchant_id: { type: 'string', description: 'Merchant identifier, e.g. domain' },
        merchant_name: { type: 'string' },
        category: { type: 'string', description: 'e.g. travel.lodging, software.api' },
        payee_email: { type: 'string' },
        amount: { type: 'string', description: 'Decimal string in major units, e.g. "49.99"' },
        currency: { type: 'string', description: 'ISO 4217 code' },
        description: { type: 'string' },
        idempotency_key: { type: 'string', description: 'Reuse the same key when retrying the same purchase' },
      },
    },
  },
  {
    name: 'payment_status',
    description: 'Check the status of a payment you requested (e.g. whether a human approved it).',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['payment_id'],
      properties: { payment_id: { type: 'string' } },
    },
  },
];

export function createPayMcpHandler(fw: SpendFirewall, agentId: string, mandate: string) {
  return async (msg: Rpc): Promise<object | undefined> => {
    const reply = (result: unknown) => ({ jsonrpc: '2.0', id: msg.id ?? null, result });
    const error = (code: number, message: string) => ({ jsonrpc: '2.0', id: msg.id ?? null, error: { code, message } });
    switch (msg.method) {
      case 'initialize':
        return reply({
          protocolVersion: msg.params?.protocolVersion ?? '2025-06-18',
          capabilities: { tools: {} },
          serverInfo: { name: 'agent-passport-pay', version: '0.3.0' },
          instructions: 'Use `pay` for any purchase. Never ask the user for card or account details.',
        });
      case 'notifications/initialized':
        return undefined;
      case 'ping':
        return reply({});
      case 'tools/list':
        return reply({ tools: TOOLS });
      case 'tools/call': {
        const name = msg.params?.name;
        const a = msg.params?.arguments ?? {};
        if (name === 'pay') {
          const r = await fw.pay({
            agent_id: agentId,
            mandate,
            merchant: {
              id: a.merchant_id,
              name: a.merchant_name,
              category: a.category,
              ...(a.payee_email ? { email: a.payee_email } : {}),
            },
            amount: a.amount,
            currency: a.currency,
            description: a.description ?? '',
            ...(a.idempotency_key ? { idempotency_key: a.idempotency_key } : {}),
          });
          const text = JSON.stringify(
            { outcome: r.outcome, payment_id: r.payment_id, summary: r.summary, reasons: r.findings.filter((f) => f.severity !== 'info').map((f) => `${f.code}: ${f.message}`) },
            null,
            2
          );
          return reply({ content: [{ type: 'text', text }], isError: r.outcome === 'blocked' || r.outcome === 'failed' });
        }
        if (name === 'payment_status') {
          fw.sweepExpired();
          const row = fw.ledger.get(String(a.payment_id ?? ''));
          if (!row || row.agent_id !== agentId) return reply({ content: [{ type: 'text', text: 'Unknown payment' }], isError: true });
          return reply({ content: [{ type: 'text', text: JSON.stringify({ payment_id: row.id, status: row.status }) }] });
        }
        return error(-32602, `Unknown tool: ${name}`);
      }
      default:
        return msg.id === undefined ? undefined : error(-32601, `Method not found: ${msg.method}`);
    }
  };
}

export function providerFromEnv(): PaymentProvider {
  return PayPalProvider.fromEnv() ?? new MockPayPalProvider();
}

export function intentFromEnv(): IntentVerifier {
  const llm = LlmIntentVerifier.fromEnv();
  return llm ? new CompositeIntentVerifier([new HeuristicIntentVerifier(), llm]) : new HeuristicIntentVerifier();
}

export async function startPayMcpServer(): Promise<void> {
  const cwd = process.env.AGENT_PASSPORT_CWD ?? process.cwd();
  const agentId = process.env.AGENT_PASSPORT_AGENT;
  const mandate = process.env.AGENT_PASSPORT_MANDATE;
  if (!agentId || !mandate) {
    process.stderr.write('agent-passport-pay-mcp: AGENT_PASSPORT_AGENT and AGENT_PASSPORT_MANDATE are required\n');
    process.exit(2);
  }
  const fw = new SpendFirewall({ cwd, provider: providerFromEnv(), intent: intentFromEnv() });
  const handle = createPayMcpHandler(fw, agentId, mandate);
  const rl = createInterface({ input: process.stdin });
  rl.on('line', async (line) => {
    if (!line.trim()) return;
    let msg: Rpc;
    try {
      msg = JSON.parse(line);
    } catch {
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }) + '\n');
      return;
    }
    try {
      const out = await handle(msg);
      if (out) process.stdout.write(JSON.stringify(out) + '\n');
    } catch (e) {
      // Fail closed: an internal error is a failed payment, never a success.
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: msg.id ?? null, error: { code: -32603, message: 'Payment firewall error (no payment made)' } }) + '\n');
    }
  });
  rl.on('close', () => fw.close());
}
