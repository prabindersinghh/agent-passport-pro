import { describe, it, expect, afterAll } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createSandbox } from './sandbox.js';
import { createPayMcpHandler } from './mcp-server.js';

const sb = createSandbox(mkdtempSync(join(tmpdir(), 'ap-mcp-')));
const mandate = sb.issue({ agentId: 'shopper', task: 'Buy API credits', currency: 'USD', maxTotal: '50.00', allowedCategories: ['software.api'], allowedMerchants: ['api.example'] });
const handle = createPayMcpHandler(sb.firewall, 'shopper', mandate);
afterAll(() => sb.close());

describe('pay MCP server', () => {
  it('advertises pay + payment_status and no approval tool', async () => {
    const r: any = await handle({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
    const names = r.result.tools.map((t: any) => t.name);
    expect(names).toEqual(['pay', 'payment_status']);
    expect(names.some((n: string) => /approve|grant|reject/i.test(n))).toBe(false);
  });

  it('captures an in-mandate payment and blocks a gift card', async () => {
    const ok: any = await handle({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'pay', arguments: { merchant_id: 'api.example', merchant_name: 'API Co', category: 'software.api', amount: '20.00', currency: 'USD' } } });
    expect(JSON.parse(ok.result.content[0].text).outcome).toBe('captured');
    const bad: any = await handle({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'pay', arguments: { merchant_id: 'cards.example', merchant_name: 'Cards', category: 'gift_card', amount: '20.00', currency: 'USD' } } });
    expect(bad.result.isError).toBe(true);
    expect(JSON.parse(bad.result.content[0].text).outcome).toBe('blocked');
    expect(sb.provider.moved).toHaveLength(1);
  });

  it('ignores a mandate smuggled in tool arguments', async () => {
    const r: any = await handle({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'pay', arguments: { merchant_id: 'api.example', merchant_name: 'API Co', category: 'software.api', amount: '20.00', currency: 'USD', mandate: 'apm1.forged.sig', agent_id: 'admin' } } });
    // Extra args are dropped; identity + mandate come from process config
    const row = sb.firewall.ledger.get(JSON.parse(r.result.content[0].text).payment_id);
    expect(row?.agent_id).toBe('shopper');
    expect(row?.mandate_id).toMatch(/^mdt_/);
  });
});
