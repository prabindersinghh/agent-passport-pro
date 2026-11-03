import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdirSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import request from 'supertest';
import {
  saveYamlFile,
  ensureAgentStructure,
  discoveryToProjectConfig,
  createBaselineProjectPolicy,
  createPassportFromTemplate,
  SHELL_TEMPLATES,
  discoverProject,
  projectConfigPath,
  projectPolicyPath,
  agentPassportPath,
} from '@agent-passport/core';
import { createHttpServer } from './server.js';
import { z } from 'zod';

const TEST_DIR = join(tmpdir(), `agent-passport-http-test-${Date.now()}`);

const HttpPolicyDecisionSchema = z.object({
  decision: z.string(),
  effect: z.enum(['allow', 'deny', 'approval_required', 'approved', 'expired']),
  reason: z.string(),
  agent: z.string(),
  ruleIds: z.array(z.string()),
  policySource: z.string().optional(),
  approvalRequestId: z.string().optional(),
  trace_id: z.string(),
});

beforeAll(() => {
  mkdirSync(join(TEST_DIR, 'src'), { recursive: true });
  mkdirSync(join(TEST_DIR, 'tests'), { recursive: true });
  ensureAgentStructure(TEST_DIR);
  const discovery = discoverProject(TEST_DIR);
  saveYamlFile(projectConfigPath(TEST_DIR), discoveryToProjectConfig(discovery));
  const policy = createBaselineProjectPolicy('http-test-project');
  policy.metadata.activated = true;
  saveYamlFile(projectPolicyPath(TEST_DIR), policy);
  for (const role of ['researcher', 'coder', 'reviewer', 'deployer'] as const) {
    saveYamlFile(
      agentPassportPath(role, TEST_DIR),
      createPassportFromTemplate(SHELL_TEMPLATES[role], {
        owner: 'test',
        projectId: 'http-test-project',
      })
    );
  }
});

afterAll(() => {
  // SQLite may briefly hold the lock on Windows; best-effort cleanup
  try {
    if (existsSync(TEST_DIR)) rmSync(TEST_DIR, { recursive: true, force: true });
  } catch {
    /* ignore EBUSY */
  }
});

describe('@agent-passport/http', () => {
  it('POST /v1/authorize returns DENY for researcher filesystem.write', async () => {
    const { app, gateway } = createHttpServer({ cwd: TEST_DIR });
    try {
      const res = await request(app)
        .post('/v1/authorize')
        .send({
          agentId: 'researcher',
          action: 'filesystem.write',
          resource: './src/file.ts',
          traceId: 'trace-http-deny-1',
        })
        .expect(200);

      const body = HttpPolicyDecisionSchema.parse(res.body);
      expect(body.decision).toBe('DENY');
      expect(body.effect).toBe('deny');
      expect(body.agent).toBe('researcher');
      expect(body.trace_id).toBe('trace-http-deny-1');
    } finally {
      gateway.close();
    }
  });

  it('rejects invalid authorize body with fail-closed DENY schema', async () => {
    const { app, gateway } = createHttpServer({ cwd: TEST_DIR });
    try {
      const res = await request(app)
        .post('/v1/authorize')
        .send({ agentId: 'coder' })
        .expect(400);

      const body = HttpPolicyDecisionSchema.parse(res.body);
      expect(body.decision).toBe('DENY');
      expect(body.effect).toBe('deny');
      expect(body.ruleIds).toContain('fail-closed');
    } finally {
      gateway.close();
    }
  });

  it('GET /health returns ok', async () => {
    const { app, gateway } = createHttpServer({ cwd: TEST_DIR });
    try {
      const res = await request(app).get('/health').expect(200);
      expect(res.body).toEqual({ status: 'ok' });
    } finally {
      gateway.close();
    }
  });

  it('BYPASS-5: agent cannot grant approvals over HTTP without the approver credential', async () => {
    const { app, gateway } = createHttpServer({ cwd: TEST_DIR });
    const prev = process.env.AGENT_PASSPORT_APPROVER_TOKEN;
    process.env.AGENT_PASSPORT_APPROVER_TOKEN = 'test-approver-token-0123456789abcdef';
    try {
      const created = await request(app)
        .post('/v1/approvals')
        .send({ agentId: 'coder', shellId: 'coder', action: 'github.merge_pr', resource: 'repo/x/pr/9', parameters: { sha: 'abc' } })
        .expect(201);
      expect(created.body.params_hash).toMatch(/^[0-9a-f]{64}$/);
      const id = created.body.request_id;

      await request(app).post(`/v1/approvals/${id}/grant`).send({ decidedBy: 'human' }).expect(403);
      await request(app)
        .post(`/v1/approvals/${id}/grant`)
        .set('Authorization', 'Bearer wrong-token-wrong-token-wrong')
        .send({ decidedBy: 'human' })
        .expect(403);
      // Correct credential but approver claims to be the agent itself
      await request(app)
        .post(`/v1/approvals/${id}/grant`)
        .set('Authorization', 'Bearer test-approver-token-0123456789abcdef')
        .send({ decidedBy: 'coder' })
        .expect(403);
      const ok = await request(app)
        .post(`/v1/approvals/${id}/grant`)
        .set('Authorization', 'Bearer test-approver-token-0123456789abcdef')
        .send({ decidedBy: 'alice@human' })
        .expect(200);
      expect(ok.body.status).toBe('granted');
    } finally {
      if (prev === undefined) delete process.env.AGENT_PASSPORT_APPROVER_TOKEN;
      else process.env.AGENT_PASSPORT_APPROVER_TOKEN = prev;
      gateway.close();
    }
  });

  it('grant is disabled (403) when no approver credential is configured on the host', async () => {
    const { app, gateway } = createHttpServer({ cwd: TEST_DIR });
    const prevTok = process.env.AGENT_PASSPORT_APPROVER_TOKEN;
    const prevHome = process.env.AGENT_PASSPORT_HOME;
    delete process.env.AGENT_PASSPORT_APPROVER_TOKEN;
    process.env.AGENT_PASSPORT_HOME = join(TEST_DIR, 'no-such-home');
    try {
      await request(app)
        .post('/v1/approvals/whatever/grant')
        .set('Authorization', 'Bearer anything-anything-anything')
        .send({ decidedBy: 'human' })
        .expect(403);
    } finally {
      if (prevTok !== undefined) process.env.AGENT_PASSPORT_APPROVER_TOKEN = prevTok;
      if (prevHome === undefined) delete process.env.AGENT_PASSPORT_HOME;
      else process.env.AGENT_PASSPORT_HOME = prevHome;
      gateway.close();
    }
  });

  it('payments over HTTP: agent gets 202 + hold, cannot approve; approver with credential captures', async () => {
    const { createSandbox } = await import('@agent-passport/payments');
    const { mkdtempSync } = await import('node:fs');
    const sb = createSandbox(mkdtempSync(join(TEST_DIR, 'pay-')));
    const { app } = createHttpServer({ cwd: sb.cwd, gateway: sb.firewall.gateway, firewall: sb.firewall });
    try {
      const mandate = sb.issue({ agentId: 'shopper', task: 'hotel', currency: 'USD', maxTotal: '300.00', approvalOver: '100.00', allowedCategories: ['travel.lodging'], allowedMerchants: ['taj-goa.example'] });
      const res = await request(app)
        .post('/v1/payments')
        .send({ agent_id: 'shopper', mandate, merchant: { id: 'taj-goa.example', name: 'Taj Goa', category: 'travel.lodging' }, amount: '240.00', currency: 'USD', description: '2 nights' })
        .expect(202);
      expect(res.body.outcome).toBe('pending_approval');
      const id = res.body.payment_id;
      await request(app).post(`/v1/payments/${id}/approve`).send({ decidedBy: 'shopper' }).expect(403);
      await request(app).get('/v1/payments-pending').expect(403);
      const pend = await request(app).get('/v1/payments-pending').set('Authorization', `Bearer ${sb.approverToken}`).expect(200);
      expect(pend.body[0].payment_id).toBe(id);
      const ok = await request(app).post(`/v1/payments/${id}/approve`).set('Authorization', `Bearer ${sb.approverToken}`).send({ decidedBy: 'owner@human' }).expect(200);
      expect(ok.body.outcome).toBe('captured');
      expect(sb.provider.moved).toHaveLength(1);
      await request(app)
        .post('/v1/payments')
        .send({ agent_id: 'shopper', mandate, merchant: { id: 'cards.example', name: 'Cards', category: 'gift_card' }, amount: '20.00', currency: 'USD' })
        .expect(403);
    } finally {
      sb.close();
    }
  });
});
