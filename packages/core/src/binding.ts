import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';

/**
 * Canonical JSON: object keys sorted recursively, no whitespace.
 * Two semantically identical argument objects always produce the same string,
 * so an approval can be bound to *exactly* the arguments a human saw.
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortDeep(value === undefined ? null : value));
}

function sortDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortDeep);
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const v = (value as Record<string, unknown>)[key];
      if (v !== undefined) out[key] = sortDeep(v);
    }
    return out;
  }
  if (typeof value === 'number' && !Number.isFinite(value)) {
    // NaN / Infinity have no canonical JSON form — refuse rather than coerce to null.
    throw new Error('Non-finite number in bound parameters');
  }
  return value;
}

/**
 * Hash of (action, resource, parameters). An approval stores this hash and is
 * only valid for a request that produces the identical hash. Changing a single
 * argument after approval (amount, payee, commit SHA, target env) invalidates it.
 */
export function actionBindingHash(action: string, resource: string, parameters: unknown): string {
  return createHash('sha256')
    .update(canonicalJson({ action, resource, parameters: parameters ?? null }))
    .digest('hex');
}

export function constantTimeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

/**
 * The approver secret lives OUTSIDE the project tree so an agent with
 * filesystem.read on ./** can never read it. Resolution order:
 *   1. AGENT_PASSPORT_APPROVER_TOKEN env var
 *   2. $AGENT_PASSPORT_HOME/approver.token (default ~/.agent-passport)
 */
export function approverTokenPath(): string {
  const home = process.env.AGENT_PASSPORT_HOME ?? join(homedir(), '.agent-passport');
  return join(home, 'approver.token');
}

export function loadApproverToken(): string | undefined {
  const env = process.env.AGENT_PASSPORT_APPROVER_TOKEN;
  if (env && env.length >= 16) return env;
  const path = approverTokenPath();
  if (!existsSync(path)) return undefined;
  const token = readFileSync(path, 'utf8').trim();
  return token.length >= 16 ? token : undefined;
}

export function ensureApproverToken(): { token: string; path: string; created: boolean } {
  const existing = loadApproverToken();
  const path = approverTokenPath();
  if (existing) return { token: existing, path, created: false };
  const token = randomBytes(32).toString('hex');
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, token + '\n', { encoding: 'utf8', mode: 0o600 });
  try {
    chmodSync(path, 0o600);
  } catch {
    /* best effort on platforms without POSIX modes */
  }
  return { token, path, created: true };
}

export function verifyApproverToken(presented: string | undefined): boolean {
  const expected = loadApproverToken();
  if (!expected || !presented) return false; // fail closed when unconfigured
  return constantTimeEqual(presented, expected);
}
