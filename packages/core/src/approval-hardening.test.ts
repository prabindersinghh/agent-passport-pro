/**
 * v0.3 regression suite — each test is a bypass that WORKED against v0.2.0
 * (verified by probe on commit 640b4c5) and must stay closed.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdirSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  createGateway,
  saveYamlFile,
  ensureAgentStructure,
  discoveryToProjectConfig,
  createBaselineProjectPolicy,
  createPassportFromTemplate,
  SHELL_TEMPLATES,
  projectConfigPath,
  projectPolicyPath,
  agentPassportPath,
  discoverProject,
  actionBindingHash,
  canonicalJson,
  ApprovalError,
} from '../src/index.js';

const DIR = join(tmpdir(), `ap-hardening-${Date.now()}`);
const base = { agentId: 'coder', shellId: 'coder', action: 'github.merge_pr' };

beforeAll(() => {
  mkdirSync(join(DIR, 'src'), { recursive: true });
  ensureAgentStructure(DIR);
  saveYamlFile(projectConfigPath(DIR), discoveryToProjectConfig(discoverProject(DIR)));
  const p = createBaselineProjectPolicy('hardening');
  p.metadata.activated = true;
  saveYamlFile(projectPolicyPath(DIR), p);
  saveYamlFile(
    agentPassportPath('coder', DIR),
    createPassportFromTemplate(SHELL_TEMPLATES.coder, { owner: 't', projectId: 'hardening' })
  );
});
afterAll(() => {
  try {
    if (existsSync(DIR)) rmSync(DIR, { recursive: true, force: true });
  } catch {
    /* ignore */
  }
});

const ok = async () => ({ success: true, resultRef: 'ok' });

describe('BYPASS-1 argument swap after approval (bait-and-switch)', () => {
  it('approval for sha=SAFE does not authorize sha=MALICIOUS', async () => {
    const gw = createGateway({ cwd: DIR });
    const r1 = await gw.execute({ ...base, resource: 'repo/a/pr/1', parameters: { sha: 'SAFE' } }, ok);
    expect(r1.decision.effect).toBe('approval_required');
    gw.approvals.grant(r1.approvalRequestId!, 'alice@human');
    const swapped = await gw.execute(
      { ...base, resource: 'repo/a/pr/1', parameters: { sha: 'MALICIOUS' } },
      ok
    );
    expect(swapped.executed).toBe(false);
    expect(swapped.decision.effect).toBe('approval_required');
    const exact = await gw.execute({ ...base, resource: 'repo/a/pr/1', parameters: { sha: 'SAFE' } }, ok);
    expect(exact.executed).toBe(true);
    gw.close();
  });

  it('key order does not matter, values do', () => {
    expect(canonicalJson({ b: 1, a: { d: 2, c: 3 } })).toBe(canonicalJson({ a: { c: 3, d: 2 }, b: 1 }));
    expect(actionBindingHash('x', 'r', { amount: 100 })).not.toBe(actionBindingHash('x', 'r', { amount: 1000 }));
    expect(() => canonicalJson({ amount: NaN })).toThrow();
  });
});

describe('BYPASS-2 self-approval', () => {
  it('the requesting agent cannot grant its own request', async () => {
    const gw = createGateway({ cwd: DIR });
    const r = await gw.execute({ ...base, resource: 'repo/a/pr/2' }, ok);
    expect(() => gw.approvals.grant(r.approvalRequestId!, 'coder')).toThrow(ApprovalError);
    expect(() => gw.approvals.grant(r.approvalRequestId!, '  CODER ')).toThrow(ApprovalError);
    expect(gw.approvals.get(r.approvalRequestId!)!.status).toBe('pending');
    gw.close();
  });
});

describe('BYPASS-3 once-approval reused after failed execution', () => {
  it('executor runs at most once per once-approval, even if it fails', async () => {
    const gw = createGateway({ cwd: DIR });
    const r = await gw.execute({ ...base, resource: 'repo/a/pr/3' }, ok);
    gw.approvals.grant(r.approvalRequestId!, 'alice@human');
    let runs = 0;
    const failing = async () => {
      runs++;
      return { success: false, errorCode: 'TIMEOUT' };
    };
    for (let i = 0; i < 3; i++) await gw.execute({ ...base, resource: 'repo/a/pr/3' }, failing);
    expect(runs).toBe(1);
    gw.close();
  });

  it('concurrent duplicate executions: exactly one wins the claim', async () => {
    const gw = createGateway({ cwd: DIR });
    const r = await gw.execute({ ...base, resource: 'repo/a/pr/4' }, ok);
    gw.approvals.grant(r.approvalRequestId!, 'alice@human');
    let runs = 0;
    const slow = async () => {
      runs++;
      await new Promise((res) => setTimeout(res, 20));
      return { success: true };
    };
    const results = await Promise.all(
      Array.from({ length: 5 }, () => gw.execute({ ...base, resource: 'repo/a/pr/4' }, slow))
    );
    expect(runs).toBe(1);
    expect(results.filter((x) => x.executed)).toHaveLength(1);
    gw.close();
  });
});

describe('BYPASS-4 requester-chosen permanent wildcard scope', () => {
  it('wildcard, unbound approvals never satisfy a high-risk action', () => {
    const gw = createGateway({ cwd: DIR });
    const req = gw.approvals.createRequest({
      ...base,
      resource: '*',
      reason: 'please',
      scope: 'permanent',
    });
    const granted = gw.approvals.grant(req.request_id, 'alice@human');
    expect(granted!.granted_scope).toBe('once'); // approver default caps high-risk scope
    const d = gw.authorize({ ...base, resource: 'repo/anything/pr/999' });
    expect(d.effect).toBe('approval_required');
    gw.close();
  });
});

describe('Pending approvals expire', () => {
  it('a request nobody answered cannot be granted later', () => {
    const gw = createGateway({ cwd: DIR });
    const req = gw.approvals.createRequest({
      ...base,
      resource: 'repo/a/pr/5',
      reason: 'r',
      pendingTtlMs: -1,
    });
    expect(gw.approvals.grant(req.request_id, 'alice@human')).toBeUndefined();
    expect(gw.approvals.get(req.request_id)!.status).toBe('expired');
    gw.close();
  });
});

describe('Malformed arguments fail closed', () => {
  it('non-finite numbers in tool arguments are denied', () => {
    const gw = createGateway({ cwd: DIR });
    const d = gw.authorize({ ...base, action: 'tests.run', resource: '*', parameters: { n: Infinity } });
    expect(d.effect).toBe('deny');
    expect(d.ruleIds).toContain('security:malformed-arguments');
    gw.close();
  });
});
